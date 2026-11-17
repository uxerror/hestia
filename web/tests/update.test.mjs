import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';

const NONCE = 'a'.repeat(64);

test('router: the update offer route keeps its query', async () => {
  const env = setupEnv();
  const { parseHash } = await env.import('lib/router.js');
  const h = `#/update/offer?from=${encodeURIComponent('http://127.0.0.1:4321')}&v=v0.2.0&n=${NONCE}`;
  assert.deepEqual(parseHash(h), { name: 'update-offer', hash: h });
  assert.equal(parseHash('#/jobs?x=1').name, 'jobs');
  assert.equal(parseHash('#/targets').name, 'targets');
  env.dispose();
});

test('parseOffer: only the loopback helper of this PC and a 32-byte nonce are accepted', async () => {
  const env = setupEnv();
  const { parseOffer } = await env.import('lib/update.js');
  const q = (o) => '#/update/offer?' + new URLSearchParams(o).toString();
  assert.deepEqual(parseOffer(q({ from: 'http://127.0.0.1:4321', v: 'v0.2.0', n: NONCE })), {
    kind: 'offer', version: 'v0.2.0', from: 'http://127.0.0.1:4321', nonce: NONCE,
  });
  for (const bad of [
    { from: 'http://evil.example:4321', v: 'v0.2.0', n: NONCE },
    { from: 'http://127.0.0.1:4321/x', v: 'v0.2.0', n: NONCE },
    { from: 'https://127.0.0.1:4321', v: 'v0.2.0', n: NONCE },
    { from: 'http://127.0.0.1', v: 'v0.2.0', n: NONCE },
    { from: 'http://127.0.0.1:4321', v: '', n: NONCE },
    { from: 'http://127.0.0.1:4321', v: 'v0.2.0', n: 'short' },
    { from: 'http://127.0.0.1:4321', v: 'v0.2.0' },
  ]) {
    assert.equal(parseOffer(q(bad)).kind, 'invalid', JSON.stringify(bad));
  }
  assert.deepEqual(parseOffer(q({ older: '1', v: 'v0.1.0' })), { kind: 'older', version: 'v0.1.0' });
  assert.equal(parseOffer(q({ older: '1' })).kind, 'invalid');
  assert.equal(parseOffer('').kind, 'invalid');
  env.dispose();
});

test('isDirty / whereText / badge / card state', async () => {
  const env = setupEnv();
  const m = await env.import('lib/update.js');
  assert.equal(m.isDirty('v0.1.0-5-gabc1234-dirty'), true);
  assert.equal(m.isDirty('v0.1.0'), false);
  assert.equal(m.isDirty(''), false);
  assert.match(m.whereText({ kind: 'lxc', vmid: 900, node: 'pve1', ip: '10.10.10.9' }), /контейнер 900 на узле pve1/);
  assert.match(m.whereText({ kind: 'ssh', host: 'nas', ip: '10.10.10.5' }), /сервер nas/);
  const st = (o) => ({ current: 'v0.1.0', location_ok: true, github: { configured: true, available: false, latest: 'v0.1.0' }, ...o });
  assert.equal(m.badgeText(st({ github: { configured: true, available: true, latest: 'v0.2.0' } })), 'Доступно обновление v0.2.0');
  assert.equal(m.badgeText(st({ location_ok: false, github: { available: true, latest: 'v0.2.0' } })), '');
  assert.equal(m.badgeText(null), '');
  assert.equal(m.cardState(null).kind, 'loading');
  assert.equal(m.cardState(st({ location_ok: false, reason: 'нет' })).kind, 'unavailable');
  assert.equal(m.cardState(st({ running_job: 'j1' })).kind, 'running');
  assert.equal(m.cardState(st({ github: { configured: false } })).kind, 'unconfigured');
  assert.equal(m.cardState(st({ github: { configured: true, available: true, latest: 'v0.2.0' } })).kind, 'available');
  assert.equal(m.cardState(st()).kind, 'current');
  env.dispose();
});

test('inRestart: only the last step, still running', async () => {
  const env = setupEnv();
  const { inRestart } = await env.import('lib/update.js');
  assert.equal(inRestart({ steps: [{ title: 'Перезапуск контроллера', status: 'running' }] }), true);
  assert.equal(inRestart({ steps: [{ title: 'Перезапуск контроллера', status: 'done' }] }), false);
  assert.equal(inRestart({ steps: [{ title: 'Загрузка', status: 'running' }] }), false);
  assert.equal(inRestart(null), false);
  env.dispose();
});

test('waitForVersion: retries while down or old, stops on the new version, times out at 90 s', async () => {
  const env = setupEnv();
  const { waitForVersion } = await env.import('lib/update.js');
  let t = 0;
  const clock = { now: () => t, sleep: async (ms) => { t += ms; } };
  const seq = [() => { throw new Error('down'); }, () => ({ status: 'ok', version: 'v0.1.0' }), () => ({ status: 'ok', version: 'v0.2.0' })];
  let i = 0;
  assert.equal(await waitForVersion(async () => seq[i++](), 'v0.2.0', clock), 'ok');
  assert.equal(i, 3);
  t = 0;
  let calls = 0;
  assert.equal(await waitForVersion(async () => { calls++; return { status: 'ok', version: 'v0.1.0' }; }, 'v0.2.0', clock), 'timeout');
  assert.ok(t >= 90000 && t <= 92000, 'waited ' + t);
  assert.ok(calls > 20);
  t = 0;
  assert.equal(await waitForVersion(async () => ({ status: 'moved', version: 'v0.2.0' }), 'v0.2.0', { ...clock, timeoutMs: 5000 }), 'timeout');
  env.dispose();
});

test('fetchPayload: meta and binary come from the helper; failures read well', async () => {
  const env = setupEnv();
  const { fetchPayload } = await env.import('lib/update.js');
  const urls = [];
  const fetchFn = async (u) => {
    urls.push(u);
    return u.endsWith('/meta')
      ? new Response(JSON.stringify({ version: 'v0.2.0', sha256: 'ab', size: 3, dirty: false }))
      : new Response(new Uint8Array([1, 2, 3]));
  };
  const r = await fetchPayload({ from: 'http://127.0.0.1:4321', nonce: NONCE }, fetchFn);
  assert.equal(r.meta.version, 'v0.2.0');
  assert.equal((await r.blob.arrayBuffer()).byteLength, 3);
  assert.deepEqual(urls, [`http://127.0.0.1:4321/payload/${NONCE}/meta`, `http://127.0.0.1:4321/payload/${NONCE}`]);
  await assert.rejects(fetchPayload({ from: 'x', nonce: 'y' }, async () => new Response('', { status: 404 })), /приложени/);
  await assert.rejects(fetchPayload({ from: 'x', nonce: 'y' }, async () => { throw new TypeError('net'); }), /приложени/);
  env.dispose();
});

test('uploadPayload: raw body with the version in the query, errors keep the server message', async () => {
  const env = setupEnv();
  const { uploadPayload } = await env.import('lib/update.js');
  const { ApiError } = await env.import('lib/api.js');
  let seen;
  const ok = async (u, init) => {
    seen = { u, init };
    return new Response(JSON.stringify({ upload_id: 'u1', version: 'v0.2.0', sha256: 'ab' }));
  };
  const blob = new Blob([new Uint8Array([1, 2])]);
  assert.equal((await uploadPayload('v0.2.0-1-gabc1234', blob, ok)).upload_id, 'u1');
  assert.equal(seen.u, '/api/v1/update/upload?version=v0.2.0-1-gabc1234');
  assert.equal(seen.init.method, 'POST');
  assert.equal(seen.init.credentials, 'same-origin');
  assert.equal(seen.init.headers['Content-Type'], 'application/octet-stream');
  assert.equal(seen.init.body, blob);
  const fail = async () => new Response(JSON.stringify({ error: 'файл больше 64 МБ' }), { status: 413 });
  await assert.rejects(uploadPayload('v1.0.0', blob, fail), (e) => e instanceof ApiError && e.status === 413 && e.message === 'файл больше 64 МБ');
  await assert.rejects(uploadPayload('v1.0.0', blob, async () => { throw new TypeError('x'); }), /Нет связи/);
  env.dispose();
});

test('api: update calls', async () => {
  const env = setupEnv({
    'GET /api/v1/update': () => [200, { current: 'v0.1.0' }],
    'POST /api/v1/update/check': () => [200, { configured: true }],
    'POST /api/v1/update': () => [202, { job: { id: 'j' } }],
  });
  const { api } = await env.import('lib/api.js');
  assert.equal((await api.update()).current, 'v0.1.0');
  await api.checkUpdate();
  await api.startUpdate({ source: 'github', version: 'v0.2.0' });
  assert.deepEqual(env.calls.at(-1).body, { source: 'github', version: 'v0.2.0' });
  env.dispose();
});
