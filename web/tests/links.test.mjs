import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv, tick } from './env.mjs';
import { sampleGraph } from './fixtures.mjs';

const from = (instance, port, dir) => ({ instance, port, dir });

test('compat: handle ids', async () => {
  const env = setupEnv();
  const c = await env.import('lib/compat.js');
  assert.deepEqual(c.parseHandle('i:1', 'p:web'), { kind: 'provides', instance: 1, port: 'web' });
  assert.deepEqual(c.parseHandle('i:2', 'r:target'), { kind: 'requires', instance: 2, port: 'target' });
  assert.deepEqual(c.parseHandle('h:10.10.10.33', 'out:1:web'), { kind: 'provides', instance: 1, port: 'web' });
  assert.deepEqual(c.parseHandle('h:10.10.10.34', 'dev'), { kind: 'device', ip: '10.10.10.34' });
  assert.equal(c.parseHandle('i:1', 'dev'), null);
  assert.equal(c.parseHandle('i:1', 'x:web'), null);
  assert.equal(c.parseHandle('i:x', 'p:web'), null);
  assert.deepEqual(c.dragOrigin('i:2', 'r:target'), from(2, 'target', 'requires'));
  assert.equal(c.dragOrigin('h:1.2.3.4', 'dev'), null);
  env.dispose();
});

test('compat: dragging a provides port — requires ports of the same type and client hosts', async () => {
  const env = setupEnv();
  const c = await env.import('lib/compat.js');
  const g = sampleGraph();
  const k = c.compatibility(g, from(1, 'web', 'provides'));
  assert.equal(k.type, 'http.service');
  // Probe 1 is already linked to this very port, Probe 2 is free
  assert.deepEqual(k.ports[c.portKey('requires', 2, 'target')], { ok: false, reason: 'уже связаны' });
  assert.deepEqual(k.ports[c.portKey('requires', 3, 'target')], { ok: true, reason: '' });
  // hello's web is `client`: hosts with a target reference are offered; the router (no ref) is not
  assert.equal(k.hosts['10.10.10.33'].ok, true);
  assert.equal(k.hosts['10.10.10.1'], undefined);
  // already linked to that device → not offered again
  assert.deepEqual(k.hosts['10.10.10.34'], { ok: false, reason: 'уже связаны' });
  // marks
  assert.equal(c.handleMark(k, 'provides', 1, 'web'), 'source');
  assert.equal(c.handleMark(k, 'requires', 3, 'target'), 'ok');
  assert.equal(c.handleMark(k, 'requires', 2, 'target'), 'blocked');
  // a consumer that takes one provider and has another one is busy
  const g2 = sampleGraph();
  g2.instances.push({ id: 9, plugin_id: 'p', plugin_name: 'P', name: 'Other', status: 'ok', provides: [{ name: 'web', type: 'http.service', multi: true, linked: 1, linkable: true }], requires: [], containers: [] });
  g2.instances[2].requires[0].linked = 1;
  assert.deepEqual(c.compatibility(g2, from(1, 'web', 'provides')).ports[c.portKey('requires', 3, 'target')], { ok: false, reason: 'порт уже занят' });
  assert.equal(c.handleMark(k, 'provides', 1, 'other'), 'dim');
  assert.equal(c.hostMark(k, '10.10.10.33'), 'ok');
  assert.equal(c.hostMark(k, '10.10.10.34'), 'blocked');
  assert.equal(c.hostMark(k, '10.10.10.1'), 'dim');
  assert.equal(c.handleMark(null, 'provides', 1, 'web'), '');
  env.dispose();
});

test('compat: types must match; unlinkable plugins and busy own ports block', async () => {
  const env = setupEnv();
  const c = await env.import('lib/compat.js');
  const g = sampleGraph();
  g.instances[2].requires[0].type = 'smb.share';
  let k = c.compatibility(g, from(1, 'web', 'provides'));
  assert.equal(k.ports[c.portKey('requires', 3, 'target')], undefined, 'another type is not even listed');
  g.instances[2].requires[0].type = 'http.service';
  g.instances[2].requires[0].linkable = false;
  k = c.compatibility(g, from(1, 'web', 'provides'));
  assert.deepEqual(k.ports[c.portKey('requires', 3, 'target')], { ok: false, reason: 'плагин не подключён' });
  g.instances[2].requires[0].linkable = true;
  // a provides port with multi:false that has its link is busy as a whole
  g.instances[0].provides[0].multi = false;
  k = c.compatibility(g, from(1, 'web', 'provides'));
  assert.deepEqual(k.ports[c.portKey('requires', 3, 'target')], { ok: false, reason: 'этот порт уже занят' });
  assert.deepEqual(k.hosts['10.10.10.33'], { ok: false, reason: 'этот порт уже занят' });
  // a port without `client` offers no hosts
  g.instances[0].provides[0].client = false;
  assert.deepEqual(c.compatibility(g, from(1, 'web', 'provides')).hosts, {});
  // an unknown port: nothing
  assert.deepEqual(c.compatibility(g, from(1, 'nope', 'provides')).ports, {});
  env.dispose();
});

test('compat: dragging a requires port — provides ports of the same type', async () => {
  const env = setupEnv();
  const c = await env.import('lib/compat.js');
  const g = sampleGraph();
  const k = c.compatibility(g, from(3, 'target', 'requires'));
  assert.deepEqual(k.ports[c.portKey('provides', 1, 'web')], { ok: true, reason: '' });
  assert.deepEqual(k.hosts, {}, 'a requires port never links to a device');
  // linked pair is "уже связаны"
  const k2 = c.compatibility(g, from(2, 'target', 'requires'));
  assert.equal(k2.ports[c.portKey('provides', 1, 'web')].ok, false);
  assert.equal(c.handleMark(k, 'provides', 1, 'web'), 'ok');
  assert.equal(c.handleMark(k, 'requires', 3, 'target'), 'source');
  env.dispose();
});

test('compat: the server candidates refine the graph answer', async () => {
  const env = setupEnv();
  const c = await env.import('lib/compat.js');
  const g = sampleGraph();
  const k = c.compatibility(g, from(1, 'web', 'provides'));
  const merged = c.mergeCandidates(
    k,
    {
      ports: [{ instance: 3, port: 'target', available: false, reason: 'плагин не подключён' }],
      // only one device is a candidate, and it is unavailable
      devices: [{ device: 'lxc:1:pve1:902', available: false, reason: 'нет root' }],
    },
    g,
  );
  assert.deepEqual(merged.ports[c.portKey('requires', 3, 'target')], { ok: false, reason: 'плагин не подключён' });
  assert.deepEqual(merged.hosts, { '10.10.10.34': { ok: false, reason: 'нет root' } });
  assert.equal(c.mergeCandidates(k, null, g), k);
  // for a requires port the devices are untouched
  const kr = c.compatibility(g, from(3, 'target', 'requires'));
  assert.deepEqual(c.mergeCandidates(kr, { ports: [], devices: [] }, g).hosts, {});
  env.dispose();
});

test('compat: a connection resolves to a link and is checked against the drag', async () => {
  const env = setupEnv();
  const c = await env.import('lib/compat.js');
  const g = sampleGraph();
  const k = c.compatibility(g, from(1, 'web', 'provides'));
  const svc = c.resolveConnection(g, { source: 'i:1', sourceHandle: 'p:web', target: 'i:3', targetHandle: 'r:target' });
  assert.deepEqual(svc, { kind: 'service', provider: { instance: 1, port: 'web' }, consumer: { instance: 3, port: 'target' } });
  assert.equal(c.connectionAllowed(k, svc), true);
  // from the port exported to the border of the host: the same provider
  const out = c.resolveConnection(g, { source: 'h:10.10.10.33', sourceHandle: 'out:1:web', target: 'i:3', targetHandle: 'r:target' });
  assert.deepEqual(out, svc);
  // a busy consumer is refused
  const busy = c.resolveConnection(g, { source: 'i:1', sourceHandle: 'p:web', target: 'i:2', targetHandle: 'r:target' });
  assert.equal(c.connectionAllowed(k, busy), false);
  // a device: the host with a reference
  const dev = c.resolveConnection(g, { source: 'i:1', sourceHandle: 'p:web', target: 'h:10.10.10.33', targetHandle: 'dev' });
  assert.deepEqual(dev, { kind: 'device', provider: { instance: 1, port: 'web' }, device: { ref: 'lxc:1:pve1:901', ip: '10.10.10.33' } });
  assert.equal(c.connectionAllowed(k, dev), true);
  assert.equal(c.connectionAllowed(k, c.resolveConnection(g, { source: 'i:1', sourceHandle: 'p:web', target: 'h:10.10.10.34', targetHandle: 'dev' })), false);
  // the router has no reference: not a device
  assert.equal(c.resolveConnection(g, { source: 'i:1', sourceHandle: 'p:web', target: 'h:10.10.10.1', targetHandle: 'dev' }), null);
  // a connection of another origin than the drag is refused
  assert.equal(c.connectionAllowed(c.compatibility(g, from(3, 'target', 'requires')), svc), true);
  assert.equal(c.connectionAllowed(c.compatibility(g, from(2, 'target', 'requires')), svc), false);
  // consumer → consumer, nonsense and nulls
  assert.equal(c.resolveConnection(g, { source: 'i:2', sourceHandle: 'r:target', target: 'i:3', targetHandle: 'r:target' }), null);
  assert.equal(c.resolveConnection(g, null), null);
  assert.equal(c.connectionAllowed(null, svc), false);
  env.dispose();
});

test('positions: saved ones win, the rest stay automatic, instances never move', async () => {
  const env = setupEnv();
  const p = await env.import('lib/positions.js');
  const nodes = [
    { id: 'h:1', type: 'host', position: { x: 1, y: 1 } },
    { id: 'g:a', type: 'group', position: { x: 2, y: 2 } },
    { id: 'i:5', type: 'inst', position: { x: 3, y: 3 } },
    { id: 'h:2', type: 'chost', position: { x: 4, y: 4 } },
  ];
  const saved = { 'h:1': { x: 100, y: 200 }, 'i:5': { x: 9, y: 9 }, 'g:gone': { x: 5, y: 5 }, 'h:2': { x: 'a', y: 1 } };
  const m = p.mergePositions(nodes, saved);
  assert.deepEqual(m[0].position, { x: 100, y: 200 });
  assert.deepEqual(m[1].position, { x: 2, y: 2 });
  assert.deepEqual(m[2].position, { x: 3, y: 3 }, 'a sub-node is always automatic');
  assert.deepEqual(m[3].position, { x: 4, y: 4 }, 'a broken saved position is ignored');
  assert.equal(nodes[0].position.x, 1, 'the input is not changed');
  assert.equal(p.mergePositions(nodes, null), nodes);
  assert.equal(p.savedCount(nodes, saved), 1);
  assert.deepEqual(p.dragged([{ id: 'h:1', type: 'host', position: { x: 10.4, y: 20.6 } }, { id: 'i:1', type: 'inst', position: { x: 1, y: 1 } }]), { 'h:1': { x: 10, y: 21 } });
  env.dispose();
});

test('positions: PositionSaver sends one request a second after the last move; cancel forgets', async () => {
  const env = setupEnv();
  const p = await env.import('lib/positions.js');
  const timers = [];
  const sent = [];
  const saver = new p.PositionSaver(async (b) => sent.push(b), {
    setTimer: (fn, ms) => (timers.push({ fn, ms, live: true }), timers.length - 1),
    clearTimer: (id) => (timers[id].live = false),
  });
  saver.move({ 'h:1': { x: 1, y: 1 } });
  saver.move({ 'h:2': { x: 2, y: 2 } });
  saver.move({ 'h:1': { x: 5, y: 5 } });
  assert.equal(timers.filter((t) => t.live).length, 1, 'only the last timer lives (debounce)');
  assert.equal(timers[0].ms, 1000);
  assert.equal(sent.length, 0);
  timers.find((t) => t.live).fn();
  await tick();
  assert.deepEqual(sent, [{ 'h:1': { x: 5, y: 5 }, 'h:2': { x: 2, y: 2 } }]);
  saver.flush();
  await tick();
  assert.equal(sent.length, 1, 'nothing pending: no request');
  saver.move({ 'h:3': { x: 3, y: 3 } });
  saver.cancel();
  await saver.flush();
  assert.equal(sent.length, 1, 'cancelled moves are never sent');
  saver.move({});
  assert.equal(timers.filter((t) => t.live).length, 0);
  env.dispose();
});

test('positions: a failed save is reported, the saver keeps working', async () => {
  const env = setupEnv();
  const p = await env.import('lib/positions.js');
  const errors = [];
  let fail = true;
  const sent = [];
  const saver = new p.PositionSaver(
    async (b) => {
      if (fail) throw new Error('нет связи');
      sent.push(b);
    },
    { setTimer: () => 1, clearTimer: () => {}, onError: (e) => errors.push(e.message) },
  );
  saver.move({ 'h:1': { x: 1, y: 1 } });
  await saver.flush();
  assert.deepEqual(errors, ['нет связи']);
  fail = false;
  saver.move({ 'h:1': { x: 2, y: 2 } });
  await saver.flush();
  assert.deepEqual(sent, [{ 'h:1': { x: 2, y: 2 } }]);
  env.dispose();
});

test('api: graph, positions, links and compose calls', async () => {
  const calls = [];
  const env = setupEnv({
    'GET /api/v1/graph': () => [200, { hosts: [] }],
    'PUT /api/v1/graph/positions': (b) => (calls.push(b), [204, null]),
    'DELETE /api/v1/graph/positions': () => [204, null],
    'GET /api/v1/plugins/links/candidates?instance=1&port=web&dir=provides': () => [200, { ports: [], devices: [] }],
    'POST /api/v1/plugins/links/plan': (b) => (calls.push(b), [200, { plan_id: 'p' }]),
    'POST /api/v1/plugins/links/4/plan': (b) => (calls.push(b), [200, { plan_id: 'q' }]),
    'GET /api/v1/plugins/links/4?status=refresh': () => [200, { id: 4, status: 'ok' }],
    'POST /api/v1/plugins/compose/plan': (b) => (calls.push(b), [200, { plan_id: 'c' }]),
  });
  const { api } = await env.import('lib/api.js');
  await api.graph();
  await api.saveGraphPositions({ 'h:1': { x: 1, y: 2 } });
  await api.resetGraphPositions();
  await api.linkCandidates(1, 'web', 'provides');
  await api.planLink({ kind: 'device' });
  await api.planRemoveLink(4);
  assert.equal((await api.link(4, true)).status, 'ok');
  await api.planCompose({ root: {} });
  assert.deepEqual(calls, [{ positions: { 'h:1': { x: 1, y: 2 } } }, { kind: 'device' }, { action: 'remove' }, { root: {} }]);
  env.dispose();
});

test('linkpanel: statuses, sides, remove action', async () => {
  const env = setupEnv();
  const l = await env.import('lib/linkpanel.js');
  const g = sampleGraph();
  assert.equal(l.linkStatusInfo('ok').label, 'Работает');
  assert.equal(l.linkStatusInfo('orphaned').cls, 'badge-error');
  assert.equal(l.linkStatusInfo('weird').label, 'weird');
  assert.deepEqual(l.linkSides(g.links[0]), { provider: 'Hello 1 · web', consumer: 'Probe 1 · target', consumerLabel: 'Потребитель' });
  assert.deepEqual(l.linkSides(g.links[1]), { provider: 'Hello 1 · web', consumer: 'device-ct (10.10.10.34)', consumerLabel: 'Устройство' });
  assert.equal(l.removeAction({ status: 'ok' }).label, 'Удалить');
  assert.equal(l.removeAction({ status: 'orphaned' }).label, 'Удалить запись');
  env.dispose();
});

test('linkpanel: request of a new link from either side', async () => {
  const env = setupEnv();
  const l = await env.import('lib/linkpanel.js');
  const own = { instance: 1, port: 'web', dir: 'provides' };
  assert.deepEqual(l.newLinkRequest(own, { kind: 'port', instance: 3, port: 'target' }, { a: 1 }), {
    kind: 'service', provider: { instance: 1, port: 'web' }, consumer: { instance: 3, port: 'target' }, config: { a: 1 },
  });
  // from the consumer's page: the chosen peer is the provider
  assert.deepEqual(l.newLinkRequest({ instance: 3, port: 'target', dir: 'requires' }, { kind: 'port', instance: 1, port: 'web' }), {
    kind: 'service', provider: { instance: 1, port: 'web' }, consumer: { instance: 3, port: 'target' }, config: {},
  });
  assert.deepEqual(l.newLinkRequest(own, { kind: 'device', ref: 'ssh:3' }), { kind: 'device', provider: { instance: 1, port: 'web' }, device: { ref: 'ssh:3' }, config: {} });
  assert.equal(l.newLinkRequest({ instance: 3, port: 'target', dir: 'requires' }, { kind: 'device', ref: 'ssh:3' }), null, 'a requires port cannot go to a device');
  assert.equal(l.newLinkRequest(own, null), null);
  assert.equal(l.newLinkRequest(own, { kind: 'port', instance: 0, port: '' }), null);
  assert.deepEqual(l.providerSide({ instance: 3, port: 'target', dir: 'requires' }, { kind: 'port', instance: 1, port: 'web' }), { instance: 1, port: 'web' });
  assert.deepEqual(l.providerSide(own, { kind: 'device', ref: 'x' }), { instance: 1, port: 'web' });
  env.dispose();
});

test('linkpanel: the list of the second side and its choice', async () => {
  const env = setupEnv();
  const l = await env.import('lib/linkpanel.js');
  const opts = l.candidateOptions({
    ports: [
      { instance: 3, port: 'target', name: 'Probe 2', label: 'Что проверять', plugin_name: 'Hestia Probe', available: true },
      { instance: 2, port: 'target', name: 'Probe 1', available: false, reason: 'порт уже занят' },
    ],
    devices: [{ device: 'ssh:7', name: 'nas', address: '10.10.10.50', available: true }, { device: 'ssh:8', name: 'x', address: 'x', available: false }],
  });
  assert.equal(opts.length, 4);
  assert.deepEqual(opts[0], { value: 'p|3|target', label: 'Probe 2 · Что проверять (Hestia Probe)', disabled: false, reason: '', group: 'Сервисы' });
  assert.equal(opts[1].disabled, true);
  assert.equal(opts[1].reason, 'порт уже занят');
  assert.equal(opts[2].label, 'nas (10.10.10.50)');
  assert.equal(opts[3].label, 'x');
  assert.deepEqual(l.parseChoice('p|3|target'), { kind: 'port', instance: 3, port: 'target' });
  assert.deepEqual(l.parseChoice('d|ssh:7'), { kind: 'device', ref: 'ssh:7' });
  assert.equal(l.parseChoice(''), null);
  assert.deepEqual(l.candidateOptions(null), []);
  env.dispose();
});

test('linkpanel: errors of a link plan — form fields vs. the sides', async () => {
  const env = setupEnv();
  const l = await env.import('lib/linkpanel.js');
  const { ApiError } = await env.import('lib/api.js');
  const e = new ApiError(422, 'Проверьте связь: hostname — Неверный формат', { fields: [{ field: 'hostname', msg: 'Неверный формат' }] });
  const r = l.linkPlanError(e);
  assert.equal(r.kind, 'fields');
  assert.deepEqual(r.fields, { hostname: 'Неверный формат' });
  assert.equal(r.side, false);
  const side = l.linkPlanError(new ApiError(422, 'Проверьте связь: порт уже занят', { fields: [{ field: 'consumer.port', msg: 'порт уже занят' }] }));
  assert.deepEqual(side.fields, {});
  assert.equal(side.side, true);
  assert.equal(l.linkPlanError(new ApiError(409, 'Состояние изменилось')).kind, 'stale');
  assert.equal(l.linkPlanError(new ApiError(410, 'x')).kind, 'expired');
  env.dispose();
});
