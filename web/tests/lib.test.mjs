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

test('router: connect and targets routes', async () => {
  const env = setupEnv();
  const { parseHash } = await env.import('lib/router.js');
  assert.deepEqual(parseHash('#/wizard/proxmox'), { name: 'connect', kind: 'proxmox' });
  assert.deepEqual(parseHash('#/wizard/server'), { name: 'connect', kind: 'server' });
  assert.equal(parseHash('#/targets').name, 'targets');
  assert.equal(parseHash('#/wizard/next/proxmox').name, 'next');
  env.dispose();
});

test('connect form: validation', async () => {
  const env = setupEnv();
  const c = await env.import('lib/connect.js');
  const ok = { ...c.emptyForm(), host: '10.1.2.3', password: 'x' };
  assert.deepEqual(c.validateConnectForm(ok, 'proxmox'), {});
  assert.ok(c.validateConnectForm({ ...ok, host: '' }, 'server').host);
  assert.ok(c.validateConnectForm({ ...ok, host: 'a b' }, 'server').host);
  assert.deepEqual(c.validateConnectForm({ ...ok, host: '[fe80::1]' }, 'server'), {});
  assert.ok(c.validateConnectForm({ ...ok, port: '0' }, 'server').port);
  assert.ok(c.validateConnectForm({ ...ok, port: '70000' }, 'server').port);
  assert.ok(c.validateConnectForm({ ...ok, port: '2x' }, 'server').port);
  assert.deepEqual(c.validateConnectForm({ ...ok, port: '' }, 'server'), {});
  assert.ok(c.validateConnectForm({ ...ok, username: 'bob' }, 'proxmox').username);
  assert.deepEqual(c.validateConnectForm({ ...ok, username: 'bob' }, 'server'), {});
  assert.ok(c.validateConnectForm({ ...ok, username: 'a b' }, 'server').username);
  assert.ok(c.validateConnectForm({ ...ok, password: '' }, 'server').password);
  const key = { ...ok, auth: 'key', password: '' };
  assert.ok(c.validateConnectForm({ ...key, private_key: '' }, 'server').private_key);
  assert.ok(c.validateConnectForm({ ...key, private_key: 'hello' }, 'server').private_key);
  assert.deepEqual(c.validateConnectForm({ ...key, private_key: '-----BEGIN OPENSSH PRIVATE KEY-----\nx' }, 'server'), {});
  env.dispose();
});

test('connect form: request body', async () => {
  const env = setupEnv();
  const c = await env.import('lib/connect.js');
  const f = { ...c.emptyForm(), host: ' [::1] ', port: '', username: '', password: 'pw', private_key: 'ignored' };
  assert.deepEqual(c.buildProbeBody(f, 'server'), { kind: 'ssh', host: '::1', port: 22, username: 'root', auth: 'password', password: 'pw' });
  const k = { ...c.emptyForm(), host: 'h', port: '2222', auth: 'key', private_key: 'KEY', passphrase: 'pp', password: 'ignored' };
  assert.deepEqual(c.buildProbeBody(k, 'proxmox'), { kind: 'proxmox', host: 'h', port: 2222, username: 'root', auth: 'key', private_key: 'KEY', passphrase: 'pp' });
  env.dispose();
});

test('connect flow reducer: probe → review → job → done / failed / expired', async () => {
  const env = setupEnv();
  const { flowReducer, initialFlow } = await env.import('lib/connect.js');
  let s = flowReducer(initialFlow, { type: 'probing' });
  assert.equal(s.phase, 'probing');
  assert.equal(flowReducer(s, { type: 'probe_failed', error: 'нет доступа' }).error, 'нет доступа');
  assert.equal(flowReducer(s, { type: 'probe_failed', error: 'x' }).phase, 'form');

  const probe = { probe_id: 'p1', host_key_fp: 'SHA256:a' };
  s = flowReducer(s, { type: 'probed', probe });
  assert.equal(s.phase, 'review');
  assert.equal(s.probe, probe);

  s = flowReducer(s, { type: 'starting' });
  assert.equal(s.phase, 'starting');
  s = flowReducer(s, { type: 'started', job: { id: 'j1', status: 'queued' } });
  assert.equal(s.phase, 'running');
  s = flowReducer(s, { type: 'job', job: { id: 'j1', status: 'running', steps: [] } });
  assert.equal(s.phase, 'running');
  const done = flowReducer(s, { type: 'job', job: { id: 'j1', status: 'done' } });
  assert.equal(done.phase, 'done');

  const failed = flowReducer(s, { type: 'job', job: { id: 'j1', status: 'failed', error: 'откатано' } });
  assert.equal(failed.phase, 'failed');
  assert.equal(failed.error, 'откатано');
  const retry = flowReducer(failed, { type: 'retry' });
  assert.equal(retry.phase, 'review');
  assert.equal(retry.probe, probe);
  assert.equal(retry.job, null);

  // Expired session or changed fingerprints: probe again from scratch.
  const exp = flowReducer(flowReducer(s, { type: 'starting' }), { type: 'start_failed', status: 410, error: 'истекла' });
  assert.equal(exp.phase, 'form');
  assert.equal(exp.probe, null);
  assert.equal(exp.error, 'истекла');
  assert.equal(flowReducer(s, { type: 'start_failed', status: 409, error: 'x' }).phase, 'form');
  // Other errors keep the review.
  const keep = flowReducer(flowReducer(initialFlow, { type: 'probed', probe }), { type: 'start_failed', status: 500, error: 'сбой' });
  assert.equal(keep.phase, 'review');
  assert.equal(keep.probe, probe);
  assert.equal(flowReducer(initialFlow, { type: 'retry' }).phase, 'form');
  env.dispose();
});

test('connect: bytes and target summary formatting', async () => {
  const env = setupEnv();
  const c = await env.import('lib/connect.js');
  assert.equal(c.fmtBytes(0), '—');
  assert.equal(c.fmtBytes(512), '512 Б');
  assert.equal(c.fmtBytes(1536), '1,5 КБ');
  assert.equal(c.fmtBytes(8000000000), '7,5 ГБ');
  assert.equal(c.targetSummary({ kind: 'proxmox', cluster: 'lab', nodes: [{}, {}, {}] }), 'кластер «lab», узлов: 3');
  assert.equal(c.targetSummary({ kind: 'proxmox', cluster: '', nodes: [{}] }), 'узлов: 1');
  assert.equal(c.targetSummary({ kind: 'ssh', nodes: [] }), 'SSH-сервер');
  env.dispose();
});

test('api: target endpoints use the documented paths', async () => {
  const env = setupEnv({
    'GET /api/v1/identity': () => [200, { ssh_public_key: 'k', fingerprint: 'f' }],
    'POST /api/v1/targets/probe': () => [200, { probe_id: 'p' }],
    'POST /api/v1/targets': () => [202, { job: { id: 'j' } }],
    'GET /api/v1/targets': () => [200, { targets: [] }],
    'GET /api/v1/targets/7': () => [200, { target: { id: 7 } }],
    'DELETE /api/v1/targets/7?revert=true': () => [202, { job: { id: 'j2' } }],
    'DELETE /api/v1/targets/7?revert=false': () => [202, { job: { id: 'j3' } }],
  });
  const { api } = await env.import('lib/api.js');
  assert.equal((await api.identity()).fingerprint, 'f');
  await api.probeTarget({ kind: 'ssh' });
  assert.deepEqual(env.calls.at(-1).body, { kind: 'ssh' });
  await api.createTarget({ probe_id: 'p' });
  assert.deepEqual((await api.targets()).targets, []);
  assert.equal((await api.target(7)).target.id, 7);
  assert.equal((await api.deleteTarget(7, true)).job.id, 'j2');
  assert.equal((await api.deleteTarget(7, false)).job.id, 'j3');
  env.dispose();
});
