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

// ---- inventory (stage 1e-1) ----

test('format: binary sizes, integer percents, uptime, age', async () => {
  const env = setupEnv();
  const f = await env.import('lib/format.js');
  assert.equal(f.fmtBytes(0), '0 Б');
  assert.equal(f.fmtBytes(512), '512 Б');
  assert.equal(f.fmtBytes(1024), '1 КиБ');
  assert.equal(f.fmtBytes(1536), '1,5 КиБ');
  assert.equal(f.fmtBytes(12 * 1024 ** 3), '12 ГиБ');
  assert.equal(f.fmtBytes(34359738368), '32 ГиБ');
  assert.equal(f.fmtBytes(4143677440), '3,9 ГиБ');
  assert.equal(f.fmtBytes(8237176848384), '7,5 ТиБ');
  assert.equal(f.fmtBytes(1024 ** 5 * 3), '3 ПиБ');
  assert.equal(f.fmtBytes(-1), '—');
  assert.equal(f.fmtBytes(undefined), '—');
  assert.equal(f.fmtBytes(NaN), '—');
  assert.equal(f.fmtPercent(0.426), '43%');
  assert.equal(f.fmtPercent(0), '0%');
  assert.equal(f.fmtPercent(1), '100%');
  assert.equal(f.fmtPercent(null), '—');
  assert.equal(f.pct(25, 100), 25);
  assert.equal(f.pct(1, 3), 33);
  assert.equal(f.pct(5, 0), null);
  assert.equal(f.pct(200, 100), 100);
  assert.equal(f.fmtUptime(3109409), '35 д 23 ч');
  assert.equal(f.fmtUptime(3700), '1 ч 1 мин');
  assert.equal(f.fmtUptime(150), '2 мин');
  assert.equal(f.fmtUptime(40), '40 с');
  assert.equal(f.fmtUptime(0), '—');
  assert.equal(f.fmtAge(20), '20 с назад');
  assert.equal(f.fmtAge(150), '2 мин назад');
  assert.equal(f.fmtAge(7300), '2 ч назад');
  assert.equal(f.fmtAge(null), 'не собиралось');
  assert.equal(f.ageSince('2026-01-01T00:00:00Z', Date.parse('2026-01-01T00:00:20Z')), 20);
  assert.equal(f.ageSince(null), null);
  assert.equal(f.fmtLoad(0.47), '0,47');
  env.dispose();
});

const G = (vmid, name, o = {}) => ({ vmid, name, type: 'qemu', node: 'pve', status: 'running', template: false, tags: [], ips: [], cpu_usage: 0, mem_used: 0, disk_used: 0, disk_total: 0, ...o });
const GUESTS = [
  G(100, 'gitea', { tags: ['git'], ips: ['10.10.10.20'], cpu_usage: 0.3, mem_used: 500 }),
  G(101, 'fluxer', { node: 'pve2', status: 'stopped' }),
  G(110, 'netronome', { type: 'lxc', node: 'pve2', tags: ['monitoring', 'network'], ips: ['10.10.10.118', 'fd00::1'], cpu_usage: 0.01, mem_used: 90 }),
  G(109, 'iris', { ips: ['10.10.10.9'], cpu_usage: 0.9, mem_used: 900, disk_used: 10, disk_total: 100 }),
  G(135, 'template', { node: 'pve2', status: 'stopped', template: true }),
];

test('inventory: filter by node, type, status and search', async () => {
  const env = setupEnv();
  const inv = await env.import('lib/inventory.js');
  const ids = (f) => inv.filterGuests(GUESTS, { ...inv.emptyFilter(), ...f }).map((g) => g.vmid);
  assert.deepEqual(ids({}), [100, 101, 110, 109, 135]);
  assert.deepEqual(ids({ node: 'pve2' }), [101, 110, 135]);
  assert.deepEqual(ids({ type: 'lxc' }), [110]);
  assert.deepEqual(ids({ status: 'stopped' }), [101, 135]);
  assert.deepEqual(ids({ node: 'pve2', status: 'stopped', type: 'qemu' }), [101, 135]);
  assert.deepEqual(ids({ query: 'GITEA' }), [100]); // case-insensitive name
  assert.deepEqual(ids({ query: '10.10.10.118' }), [110]); // IP
  assert.deepEqual(ids({ query: '109' }), [109]); // VMID
  assert.deepEqual(ids({ query: 'monitor' }), [110]); // tag
  assert.deepEqual(ids({ query: '  ' }), [100, 101, 110, 109, 135]);
  assert.deepEqual(ids({ query: 'nothing' }), []);
  env.dispose();
});

test('inventory: sorting by columns, direction and stability', async () => {
  const env = setupEnv();
  const inv = await env.import('lib/inventory.js');
  const by = (key, dir) => inv.sortGuests(GUESTS, key, dir).map((g) => g.vmid);
  assert.deepEqual(by('vmid', 'asc'), [100, 101, 109, 110, 135]);
  assert.deepEqual(by('vmid', 'desc'), [135, 110, 109, 101, 100]);
  assert.deepEqual(by('name', 'asc'), [101, 100, 109, 110, 135]); // fluxer gitea iris netronome template
  assert.deepEqual(by('cpu', 'desc'), [109, 100, 110, 101, 135]);
  assert.deepEqual(by('mem', 'desc'), [109, 100, 110, 101, 135]);
  // IPs compare numerically: 10.10.10.9 < 10.10.10.20 < 10.10.10.118; no IP goes last.
  assert.deepEqual(by('ip', 'asc'), [109, 100, 110, 101, 135]);
  assert.deepEqual(by('type', 'asc'), [110, 100, 101, 109, 135]); // lxc before qemu, ties by vmid
  assert.deepEqual(by('template', 'desc')[0], 135);
  assert.deepEqual(by('nonsense', 'asc'), by('vmid', 'asc'));
  assert.equal(GUESTS[0].vmid, 100); // input is not mutated
  assert.deepEqual(inv.nextSort({ key: 'vmid', dir: 'asc' }, 'vmid'), { key: 'vmid', dir: 'desc' });
  assert.deepEqual(inv.nextSort({ key: 'vmid', dir: 'desc' }, 'name'), { key: 'name', dir: 'asc' });
  env.dispose();
});

test('inventory: counts, status labels, entry reducer', async () => {
  const env = setupEnv();
  const inv = await env.import('lib/inventory.js');
  assert.deepEqual(inv.guestCounts(GUESTS), { running: 3, total: 4 }); // template not counted
  assert.deepEqual(inv.guestCounts(GUESTS, 'pve2'), { running: 1, total: 2 });
  assert.deepEqual(inv.guestCounts(undefined), { running: 0, total: 0 });
  assert.equal(inv.statusInfo('running').label, 'запущен');
  assert.equal(inv.statusInfo('weird').label, 'weird');
  assert.equal(inv.guestIPs(GUESTS[2]), '10.10.10.118, fd00::1');
  assert.equal(inv.guestIPs(GUESTS[1]), '');
  let list = [];
  list = inv.applyEntry(list, { target_id: 1, collecting: true });
  list = inv.applyEntry(list, { target_id: 2 });
  const before = list;
  list = inv.applyEntry(list, { target_id: 1, collecting: false, snapshot: { kind: 'ssh' } });
  assert.equal(list.length, 2);
  assert.equal(list[0].snapshot.kind, 'ssh');
  assert.equal(before[0].collecting, true); // immutable
  assert.equal(inv.entryOf(list, 2).target_id, 2);
  assert.equal(inv.entryOf(list, 3), null);
  assert.equal(inv.roleBanner({ needs_guest_agent_audit: true }), true);
  assert.equal(inv.roleBanner({}), false);
  assert.equal(inv.roleBanner(null), false);
  env.dispose();
});

test('api: inventory calls and role fix need an explicit confirm', async () => {
  const env = setupEnv({
    'GET /api/v1/inventory': () => [200, { inventory: [] }],
    'GET /api/v1/inventory/3': () => [200, { target_id: 3 }],
    'POST /api/v1/inventory/3/refresh': () => [202, { job: { id: 'j' } }],
    'GET /api/v1/inventory/3/role-fix': () => [200, { needed: true, missing: ['VM.GuestAgent.Audit'], command: 'pveum …' }],
    'POST /api/v1/inventory/3/role-fix': () => [202, { job: { id: 'k' } }],
  });
  const { api } = await env.import('lib/api.js');
  assert.deepEqual(await api.inventory(), { inventory: [] });
  assert.equal((await api.inventoryOf(3)).target_id, 3);
  assert.equal((await api.refreshInventory(3)).job.id, 'j');
  assert.equal((await api.rolePlan(3)).needed, true);
  assert.equal((await api.fixRole(3)).job.id, 'k');
  const fix = env.calls.find((c) => c.key === 'POST /api/v1/inventory/3/role-fix');
  assert.deepEqual(fix.body, { confirm: true });
  env.dispose();
});

test('sse: inventory events reach the callback, close stops them', async () => {
  const env = setupEnv();
  const { subscribeInventory } = await env.import('lib/sse.js');
  const seen = [];
  let opened = 0;
  const close = subscribeInventory({ onEntry: (e) => seen.push(e), onOpen: () => opened++ });
  const es = FakeES.all[0];
  assert.equal(es.url, '/api/v1/inventory/events');
  es.emit('snapshot', { target_id: 1, collecting: true });
  es.onopen();
  assert.deepEqual(seen, [{ target_id: 1, collecting: true }]);
  assert.equal(opened, 1);
  es.l.snapshot[0]({ data: 'not json' }); // ignored
  assert.equal(seen.length, 1);
  close();
  assert.equal(es.closed, true);
  es.emit('snapshot', { target_id: 2 });
  assert.equal(seen.length, 1);
  env.dispose();
});

test('live inventory: loads, follows events, keeps the fresher entry after reconnect', async () => {
  const env = setupEnv({
    'GET /api/v1/inventory': () => [200, { inventory: [{ target_id: 1, collected_at: '2026-01-01T00:00:10Z', snapshot: { kind: 'ssh' } }] }],
  });
  const { createLive } = await env.import('lib/live.svelte.js');
  const live = createLive();
  const stop = live.start();
  await tick();
  assert.equal(live.loaded, true);
  assert.equal(live.entries.length, 1);
  const es = FakeES.all[0];
  es.emit('snapshot', { target_id: 1, collected_at: '2026-01-01T00:00:20Z', snapshot: { kind: 'proxmox' } });
  es.emit('snapshot', { target_id: 2, collecting: true });
  assert.equal(live.entries.length, 2);
  assert.equal(live.entries[0].snapshot.kind, 'proxmox');
  live.markCollecting(1);
  assert.equal(live.entries[0].collecting, true);
  stop();
  assert.equal(es.closed, true);
  env.dispose();
});

test('router: guests routes', async () => {
  const env = setupEnv();
  const { parseHash } = await env.import('lib/router.js');
  assert.deepEqual(parseHash('#/targets/7'), { name: 'guests', id: 7, node: '' });
  assert.deepEqual(parseHash('#/targets/7/pve%202'), { name: 'guests', id: 7, node: 'pve 2' });
  assert.equal(parseHash('#/targets/abc').name, 'targets');
  assert.equal(parseHash('#/targets/0').name, 'targets');
  env.dispose();
});

test('router: install and handoff routes', async () => {
  const env = setupEnv();
  const { parseHash } = await env.import('lib/router.js');
  assert.deepEqual(parseHash('#/install'), { name: 'install' });
  assert.deepEqual(parseHash('#/handoff/abc-DEF_123'), { name: 'handoff', token: 'abc-DEF_123' });
  assert.deepEqual(parseHash('#/handoff'), { name: 'handoff', token: '' });
  env.dispose();
});

test('selfinstall: default target is the first Proxmox', async () => {
  const env = setupEnv();
  const m = await env.import('lib/selfinstall.js');
  assert.equal(m.defaultTargetId([{ id: 1, kind: 'ssh' }, { id: 2, kind: 'proxmox' }, { id: 3, kind: 'proxmox' }]), 2);
  assert.equal(m.defaultTargetId([{ id: 5, kind: 'ssh' }]), 5);
  assert.equal(m.defaultTargetId([]), 0);
  env.dispose();
});

test('selfinstall: probe request carries only the edited fields, typed', async () => {
  const env = setupEnv();
  const m = await env.import('lib/selfinstall.js');
  assert.deepEqual(m.buildProbeRequest(4, {}), { target_id: 4 });
  assert.deepEqual(
    m.buildProbeRequest(4, { node: 'pve2', vmid: '903', cores: '2', memory_mb: ' 1024 ', disk_gb: '8', ip: '192.168.1.20/24', gateway: '192.168.1.1', hostname: '  ', bridge: 'vmbr1', port: 'x' }),
    { target_id: 4, node: 'pve2', bridge: 'vmbr1', gateway: '192.168.1.1', vmid: 903, cores: 2, memory_mb: 1024, disk_gb: 8, ip: '192.168.1.20/24' },
  );
  assert.deepEqual(m.buildProbeRequest(4, { ip: 'dhcp', port: '8080' }), { target_id: 4, port: 8080, ip: 'dhcp' });
  env.dispose();
});

const sampleProbe = {
  probe_id: 'p1', kind: 'lxc', warnings: [], plan: [{ id: 'template', title: 'Шаблон', detail: '' }],
  params: { node: 'pve1', vmid: 900, hostname: 'hestia', storage: 'local-lvm', template_storage: 'local', bridge: 'vmbr0', ip: 'dhcp', cores: 1, memory_mb: 512, swap_mb: 512, disk_gb: 4, template: 'debian-13-standard_13.6-1_amd64.tar.zst', template_present: true },
  choices: { nodes: ['pve1', 'pve2'], storages: [{ name: 'local-lvm' }], template_storages: ['local'], bridges: ['vmbr0'] },
};

test('selfinstall flow: probe → review → start → running → done with the result', async () => {
  const env = setupEnv();
  const { installReducer: r, initialInstall: init, fieldValue, hasStaticIP, summarize, resultSummary, handoffHref } = await env.import('lib/selfinstall.js');
  let s = r(init, { type: 'probing' });
  assert.equal(s.phase, 'probing');
  s = r(s, { type: 'probed', probe: sampleProbe });
  assert.equal(s.phase, 'review');
  assert.equal(fieldValue(s.probe, s.dirty, 'vmid'), 900);
  assert.equal(hasStaticIP(s.probe, s.dirty), false);
  const sum = Object.fromEntries(summarize(sampleProbe));
  assert.equal(sum['Узел'], 'pve1');
  assert.equal(sum['VMID'], '900');
  assert.equal(sum['Адрес'], 'DHCP');
  assert.match(sum['Шаблон'], /уже скачан/);
  assert.match(sum['Ресурсы'], /1 vCPU, 512 МБ RAM, 512 МБ swap, диск 4 ГБ \(local-lvm\)/);
  s = r(s, { type: 'starting' });
  s = r(s, { type: 'started', job: { id: 'j1', status: 'queued', steps: [] } });
  assert.equal(s.phase, 'running');
  s = r(s, { type: 'job', job: { id: 'j1', status: 'running', steps: [] } });
  assert.equal(s.phase, 'running');
  const result = { url: 'http://198.51.100.7', handoff_url: 'http://198.51.100.7/#/handoff/tok', ip: '198.51.100.7', mac: 'BC:24:11:BC:4C:F6', vmid: 900, node: 'pve1', hint: 'Закрепите адрес' };
  s = r(s, { type: 'job', job: { id: 'j1', status: 'done', steps: [], result } });
  assert.equal(s.phase, 'done');
  assert.equal(s.result.mac, 'BC:24:11:BC:4C:F6');
  assert.equal(handoffHref(s.result), 'http://198.51.100.7/#/handoff/tok');
  const rows = Object.fromEntries(resultSummary(s.result));
  assert.equal(rows['Адрес Hestia'], 'http://198.51.100.7');
  assert.equal(rows['MAC'], 'BC:24:11:BC:4C:F6');
  assert.equal(rows['Контейнер'], '900 на узле pve1');
  assert.ok(!JSON.stringify(rows).includes('tok'), 'the token is not displayed');
  assert.equal(handoffHref(null), '');
  env.dispose();
});

test('selfinstall flow: failures, expiry and the "Подробнее" fields', async () => {
  const env = setupEnv();
  const { installReducer: r, initialInstall: init, fieldValue, hasStaticIP } = await env.import('lib/selfinstall.js');
  // first probe fails → back to the picker with the message
  let s = r(r(init, { type: 'probing' }), { type: 'probe_failed', error: 'порт занят' });
  assert.equal(s.phase, 'pick');
  assert.equal(s.error, 'порт занят');
  // editing + re-check keeps the form
  s = r(r(init, { type: 'probing' }), { type: 'probed', probe: sampleProbe });
  s = r(s, { type: 'toggle_details' });
  assert.equal(s.details, true);
  s = r(s, { type: 'edit_field', field: 'ip', value: '192.168.1.20/24' });
  s = r(s, { type: 'edit_field', field: 'storage', value: 'local-lvm' });
  s = r(s, { type: 'edit_field', field: 'vmid', value: '903' });
  assert.equal(hasStaticIP(s.probe, s.dirty), true);
  assert.equal(fieldValue(s.probe, s.dirty, 'vmid'), '903');
  s = r(s, { type: 'reprobing' });
  assert.equal(s.phase, 'probing');
  assert.ok(s.probe && s.dirty.vmid === '903', 'a re-check keeps the form');
  s = r(s, { type: 'probe_failed', error: 'VMID 903 уже занят' });
  assert.equal(s.phase, 'review');
  assert.equal(s.error, 'VMID 903 уже занят');
  assert.equal(s.dirty.ip, '192.168.1.20/24');
  // changing the node forgets what depends on it
  s = r(s, { type: 'edit_field', field: 'node', value: 'pve2' });
  assert.equal(s.dirty.storage, undefined);
  assert.equal(s.dirty.vmid, '903');
  // start errors: 410 → picker, others keep the review
  let t = r(r(s, { type: 'starting' }), { type: 'start_failed', status: 410, error: 'проверка истекла' });
  assert.equal(t.phase, 'pick');
  assert.equal(t.probe, null);
  t = r(r(s, { type: 'starting' }), { type: 'start_failed', status: 409, error: 'установка уже идёт' });
  assert.equal(t.phase, 'review');
  assert.equal(t.error, 'установка уже идёт');
  // a failed (rolled back) job can be retried with the same check
  t = r(r(s, { type: 'started', job: { id: 'j' } }), { type: 'job', job: { id: 'j', status: 'failed', error: 'откат выполнен' } });
  assert.equal(t.phase, 'failed');
  assert.equal(t.error, 'откат выполнен');
  assert.equal(r(t, { type: 'retry' }).phase, 'review');
  assert.equal(r(t, { type: 'back' }).phase, 'pick');
  env.dispose();
});

test('selfinstall: moved screen state', async () => {
  const env = setupEnv();
  const { movedView } = await env.import('lib/selfinstall.js');
  assert.equal(movedView(null).state, 'checking');
  assert.equal(movedView({ reachable: true }).state, 'ok');
  assert.equal(movedView({ reachable: false }).state, 'down');
  env.dispose();
});

test('api: selfinstall endpoints and the transfer-mode 503', async () => {
  let transfers = 0;
  const env = setupEnv({
    'GET /api/v1/selfinstall': () => [200, { state: 'local', transferring: false }],
    'POST /api/v1/selfinstall/probe': () => [200, sampleProbe],
    'POST /api/v1/selfinstall': () => [202, { job: { id: 'j1' } }],
    'POST /api/v1/auth/handoff': (b) => (b.token === 'good' ? [204] : [401, { error: 'ссылка для входа недействительна или устарела' }]),
    'POST /api/v1/targets/probe': () => [503, { error: 'идёт перенос Hestia на сервер' }],
    'POST /api/v1/jobs/demo': () => [503, { error: 'Hestia работает на http://x' }],
  });
  const { api, onTransfer, isTransferError } = await env.import('lib/api.js');
  onTransfer(() => transfers++);
  assert.equal((await api.selfinstall()).state, 'local');
  await api.probeInstall({ target_id: 1 });
  await api.startInstall('p1');
  assert.deepEqual(env.calls.map((c) => c.key), ['GET /api/v1/selfinstall', 'POST /api/v1/selfinstall/probe', 'POST /api/v1/selfinstall']);
  assert.deepEqual(env.calls[2].body, { probe_id: 'p1' });
  assert.equal(await api.handoff('good'), null);
  await assert.rejects(api.handoff('bad'), (e) => e.status === 401);
  await assert.rejects(api.probeTarget({}), (e) => e.status === 503);
  assert.equal(transfers, 1);
  await assert.rejects(api.demoJob());
  assert.equal(transfers, 1, 'another 503 is not a transfer');
  assert.equal(isTransferError(503, 'идёт перенос Hestia на сервер'), true);
  assert.equal(isTransferError(500, 'идёт перенос'), false);
  env.dispose();
});

test('jobs reducer: the final status event carries the result', async () => {
  const env = setupEnv();
  const { applyEvent } = await env.import('lib/jobs.js');
  let j = applyEvent(null, 'snapshot', { id: 'a', status: 'running', steps: [], log: [] });
  j = applyEvent(j, 'status', { status: 'done', error: '', finished_at: 'x', result: { url: 'http://h', handoff_url: 'http://h/#/handoff/t' } });
  assert.equal(j.status, 'done');
  assert.equal(j.result.url, 'http://h');
  j = applyEvent(j, 'snapshot', { id: 'a', status: 'done', steps: [], log: [], result: { url: 'http://h' } });
  assert.equal(j.result.url, 'http://h');
  env.dispose();
});

test('session: a moved controller shows the redirect screen, handoff signs in once', async () => {
  let moved = true, authed = false;
  const env = setupEnv({
    'GET /api/v1/health': () => (moved ? [200, { status: 'moved', remote: 'http://198.51.100.7', instance_id: 'i1' }] : [200, { status: 'ok', transferring: false }]),
    'GET /api/v1/auth/me': () => (authed ? [200, { user: { id: 1, username: 'admin' } }] : [401, { error: 'нужен вход' }]),
    'GET /api/v1/setup': () => [200, { needs_admin: false, mode: 'serve' }],
    'POST /api/v1/auth/handoff': (b) => (b.token === 'tok' ? ((authed = true), [204]) : [401, { error: 'устарела' }]),
  });
  const s = await env.import('lib/session.svelte.js');
  await s.boot();
  assert.equal(s.session.phase, 'moved');
  assert.equal(s.session.remote.url, 'http://198.51.100.7');
  assert.ok(!env.calls.some((c) => c.key === 'GET /api/v1/auth/me'), 'a moved controller does not ask for the session');

  moved = false;
  assert.equal(await s.handoffLogin('wrong'), false);
  assert.equal(s.session.phase, 'login');
  assert.equal(await s.handoffLogin('tok'), true);
  assert.equal(s.session.phase, 'app');
  assert.equal(s.session.user.username, 'admin');
  env.dispose();
});

test('transfer watch: banner stays until the server says the transfer is over', async () => {
  const env = setupEnv();
  const { createTransferWatch } = await env.import('lib/transfer.js');
  const answers = [{ transferring: true }, new Error('down'), { transferring: true }, { transferring: false }];
  const seen = [];
  const timers = [];
  const w = createTransferWatch(
    async () => {
      const a = answers.shift();
      if (a instanceof Error) throw a;
      return a;
    },
    (on) => seen.push(on),
    { setTimer: (fn) => (timers.push(fn), timers.length), clearTimer: () => {} },
  );
  w.start();
  assert.deepEqual(seen, [true]);
  assert.equal(w.active, true);
  w.start(); // a second start does not add a second timer
  assert.equal(timers.length, 1);
  for (let i = 0; i < 4; i++) {
    const fn = timers.shift();
    if (!fn) break;
    await fn();
  }
  assert.equal(seen.at(-1), false);
  assert.equal(w.active, false);
  assert.ok(seen.slice(0, -1).every((v) => v === true), 'no flicker while the server is unreachable');
  assert.equal(timers.length, 0, 'the poll stops after the transfer');
  env.dispose();
});
