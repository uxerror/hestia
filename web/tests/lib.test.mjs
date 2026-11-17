import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv, tick, FakeES } from './env.mjs';

test('validate: username and password rules', async () => {
  const env = setupEnv();
  const v = await env.import('lib/validate.js');
  assert.ok(v.validateUsername(''));
  assert.ok(v.validateUsername('A'));
  assert.ok(v.validateUsername('a b'));
  assert.ok(v.validateUsername('a'.repeat(33)));
  assert.equal(v.validateUsername('ad.min_1-x'), '');
  assert.ok(v.validatePassword('1234567'));
  assert.equal(v.validatePassword('12345678'), '');
  env.dispose();
});

test('api: relative URL, cookie credentials, JSON body, {error} message', async () => {
  const env = setupEnv({ 'POST /api/v1/auth/login': () => [401, { error: 'неверный логин или пароль' }] });
  const { api } = await env.import('lib/api.js');
  await assert.rejects(api.login('a', 'b'), (e) => e.status === 401 && e.message === 'неверный логин или пароль');
  const c = env.calls[0];
  assert.equal(c.init.credentials, 'same-origin');
  assert.deepEqual(c.body, { username: 'a', password: 'b' });
  env.dispose();
});

test('api: 401 triggers handler (except login), network error is readable, 204 ok', async () => {
  const env = setupEnv({
    'GET /api/v1/jobs': () => [401, { error: 'нужен вход' }],
    'POST /api/v1/auth/login': () => [401, { error: 'x' }],
    'POST /api/v1/auth/logout': () => [204],
  });
  const { api, onUnauthorized } = await env.import('lib/api.js');
  let hits = 0;
  onUnauthorized(() => hits++);
  await assert.rejects(api.jobs());
  assert.equal(hits, 1);
  await assert.rejects(api.login('a', 'b'));
  assert.equal(hits, 1);
  assert.equal(await api.logout(), null);
  globalThis.fetch = async () => { throw new TypeError('fail'); };
  await assert.rejects(api.jobs(), /Нет связи/);
  env.dispose();
});

test('router: hash parsing', async () => {
  const env = setupEnv();
  const { parseHash } = await env.import('lib/router.js');
  assert.equal(parseHash('').name, 'wizard');
  assert.equal(parseHash('#/jobs').name, 'jobs');
  assert.deepEqual(parseHash('#/jobs/j%201'), { name: 'job', id: 'j 1' });
  assert.equal(parseHash('#/wizard/next/proxmox').name, 'next');
  env.dispose();
});

test('jobs reducer: snapshot, step, log, status', async () => {
  const env = setupEnv();
  const { applyEvent } = await env.import('lib/jobs.js');
  let j = applyEvent(null, 'snapshot', { id: '1', status: 'running', steps: [{ idx: 0, title: 'a', status: 'running' }], log: [] });
  j = applyEvent(j, 'step', { idx: 0, status: 'done' });
  j = applyEvent(j, 'step', { idx: 1, title: 'b', status: 'running' });
  j = applyEvent(j, 'log', { level: 'info', line: 'hi' });
  j = applyEvent(j, 'status', { status: 'done' });
  assert.deepEqual(j.steps.map((s) => [s.title, s.status]), [['a', 'done'], ['b', 'running']]);
  assert.equal(j.log.length, 1);
  assert.equal(j.status, 'done');
  env.dispose();
});

test('sse: live updates, closes after final status', async () => {
  const env = setupEnv();
  const { subscribeJob } = await env.import('lib/sse.js');
  const seen = [];
  const close = subscribeJob('abc', { onUpdate: (j) => seen.push(structuredClone(j)) });
  const es = FakeES.all[0];
  assert.equal(es.url, '/api/v1/jobs/abc/events');
  es.emit('snapshot', { id: 'abc', status: 'running', steps: [], log: [] });
  es.emit('log', { level: 'info', line: 'x' });
  assert.equal(seen.at(-1).log.length, 1);
  assert.equal(es.closed, false);
  es.emit('status', { status: 'done' });
  assert.equal(es.closed, true);
  es.emit('log', { level: 'info', line: 'late' });
  assert.equal(seen.at(-1).status, 'done');
  assert.equal(seen.at(-1).log.length, 1);
  close();
  env.dispose();
});

test('session: boot routes to setup / login / app; 401 later returns to login', async () => {
  let authed = false, needs = true;
  const env = setupEnv({
    'GET /api/v1/auth/me': () => (authed ? [200, { user: { id: 1, username: 'root' } }] : [401, { error: 'нужен вход' }]),
    'GET /api/v1/setup': () => [200, { needs_admin: needs, mode: 'serve' }],
    'POST /api/v1/setup/admin': () => ((authed = true), [201, { user: { id: 1, username: 'root' } }]),
    'GET /api/v1/jobs': () => (authed ? [200, { jobs: [] }] : [401, { error: 'x' }]),
    'POST /api/v1/auth/logout': () => ((authed = false), [204]),
  });
  const s = await env.import('lib/session.svelte.js');
  const { api } = await env.import('lib/api.js');
  await s.boot();
  assert.equal(s.session.phase, 'setup');
  await s.setupAdmin('root', 'password1');
  assert.equal(s.session.phase, 'app');
  assert.equal(s.session.user.username, 'root');
  authed = false; needs = false;
  await assert.rejects(api.jobs());
  await tick(); await tick();
  assert.equal(s.session.phase, 'login');
  await s.boot();
  assert.equal(s.session.phase, 'login');
  env.dispose();
});
