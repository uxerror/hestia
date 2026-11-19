import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';
import { sampleGraph } from './fixtures.mjs';

const helloSchema = { fields: [{ name: 'target', type: 'target', label: 'Сервер', required: true }, { name: 'port', type: 'int', label: 'Порт', default: 8080, min: 1, max: 65535 }] };
const hello = { id: 'hestia-hello', name: 'Hestia Hello', enabled: true, state: 'connected', multi_instance: true, instances: 1,
  provides: [{ name: 'web', type: 'http.service', label: 'Веб-страница' }], manifest: { schema: helloSchema, requires: [], provides: [{ name: 'web', type: 'http.service' }] } };
const probe = { id: 'hestia-probe', name: 'Hestia Probe', enabled: true, state: 'connected', multi_instance: true, instances: 2,
  provides: [], manifest: { schema: { fields: [{ name: 'interval_s', type: 'int', label: 'Интервал', default: 60, min: 30, max: 3600 }] },
    requires: [{ name: 'target', type: 'http.service', label: 'Что проверять' }, { name: 'extra', type: 'http.service', label: 'Ещё', optional: true }], provides: [] } };
// A plugin that needs an http.service and provides one (to build chains and cycles).
const relay = { id: 'relay', name: 'Relay', enabled: true, state: 'connected', multi_instance: true, instances: 0,
  provides: [{ name: 'web', type: 'http.service' }], manifest: { schema: { fields: [] }, requires: [{ name: 'up', type: 'http.service' }], provides: [{ name: 'web', type: 'http.service' }] } };
const plugins = { 'hestia-hello': hello, 'hestia-probe': probe, relay };
const fieldsBy = (id) => (plugins[id].manifest.schema.fields);

async function lib(env) {
  const d = await env.import('lib/deps.js');
  return d;
}

test('deps: a node gets a dependency slot per requires port', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const root = d.newNode(probe, { name: 'Probe 3' });
  assert.deepEqual(root.deps.map((x) => [x.port, x.optional, x.choice]), [['target', false, null], ['extra', true, null]]);
  assert.deepEqual(root.chain, ['hestia-probe']);
  assert.equal(root.values.interval_s, 60);
  assert.equal(d.newNode(hello, { name: 'h' }).deps.length, 0);
  env.dispose();
});

test('deps: providers — existing (busy greyed), new offers, nothing installed', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const g = sampleGraph();
  g.instances.push({ id: 4, plugin_id: 'hestia-hello', plugin_name: 'Hestia Hello', name: 'Hello 2', status: 'ok', host_ip: '10.10.10.34', controller: false,
    provides: [{ name: 'web', type: 'http.service', label: 'Веб-страница', multi: false, linked: 1, linkable: true }], requires: [], containers: [] });
  const ex = d.existingProviders(g, 'http.service');
  assert.deepEqual(ex.map((e) => [e.instance, e.disabled, e.reason]), [[1, false, ''], [4, true, 'порт уже занят']]);
  assert.equal(ex[0].hostIP, '10.10.10.33');
  // already taken in this tree: also busy (single-link port only)
  assert.equal(d.existingProviders(g, 'http.service', new Set(['4:web']))[1].disabled, true);
  assert.equal(d.existingProviders(g, 'smb.share').length, 0);

  const root = d.newNode(probe, { name: 'P' });
  const offers = d.newProviderOffers([hello, probe, { ...relay, enabled: false }, { ...hello, id: 'off', state: 'disabled' }], 'http.service', root);
  assert.deepEqual(offers.map((o) => [o.pluginId, o.port, o.reason]), [['hestia-hello', '', '']]);
  assert.deepEqual(d.newProviderOffers([probe], 'http.service', root), [], 'nobody provides it: the UI links to the catalog');
  // a single-instance plugin that already has an instance cannot be created again
  assert.match(d.newProviderOffers([{ ...hello, multi_instance: false, instances: 1 }], 'http.service', root)[0].reason, /один экземпляр/);
  env.dispose();
});

test('deps: compose request — existing and new providers, optional ones left out', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const root = d.newNode(probe, { name: 'Probe 3' });
  root.values.interval_s = 30;
  assert.equal(d.needsCompose(root), false);
  const sub = d.newNode(hello, { name: 'Hello 3', depth: 1, chain: root.chain, port: 'web' });
  sub.sameTarget = false;
  sub.values.target = 'lxc:1:pve1:901';
  sub.values.port = 8081;
  root.deps[0].choice = { kind: 'new', node: sub };
  assert.equal(d.needsCompose(root), true);
  const { body } = d.buildCompose(root, fieldsBy);
  assert.deepEqual(body, {
    root: { plugin_id: 'hestia-probe', name: 'Probe 3', config: { interval_s: 30 } },
    deps: [{ port: 'target', new: { plugin_id: 'hestia-hello', name: 'Hello 3', config: { target: 'lxc:1:pve1:901', port: 8081 }, port: 'web' } }],
  });
  // both slots: the optional one closed with an existing provider
  root.deps[1].choice = { kind: 'existing', instance: 1, port: 'web' };
  const b2 = d.buildCompose(root, fieldsBy).body;
  assert.deepEqual(b2.deps[1], { port: 'extra', existing: { instance: 1, port: 'web' } });
  env.dispose();
});

test('deps: nested provider inherits the target of the ancestor («тот же сервер»)', async () => {
  const env = setupEnv();
  const d = await lib(env);
  // hello (has a target) needs something? make a chain: relay(root) → hello(new): relay has no target;
  // use hello as the root of a custom tree instead: a root with a target and a nested one.
  const withTarget = { ...relay, manifest: { ...relay.manifest, schema: { fields: [{ name: 'target', type: 'target', label: 'Сервер', required: true }] } } };
  const pl = { ...plugins, relay: withTarget };
  const fb = (id) => pl[id].manifest.schema.fields;
  const root = d.newNode(withTarget, { name: 'R' });
  root.values.target = 'ssh:3';
  const sub = d.newNode(hello, { name: 'Hello 3', depth: 1, chain: root.chain });
  root.deps[0].choice = { kind: 'new', node: sub };
  assert.equal(d.inheritedTarget([root], fb), 'ssh:3');
  assert.equal(d.buildCompose(root, fb).body.deps[0].new.config.target, 'ssh:3');
  // «другой сервер»: its own
  sub.sameTarget = false;
  sub.values.target = 'ssh:9';
  assert.equal(d.buildCompose(root, fb).body.deps[0].new.config.target, 'ssh:9');
  // the root without a target: nothing is inherited, the nested form asks for its own
  assert.equal(d.inheritedTarget([d.newNode(probe, { name: 'P' })], fieldsBy), '');
  env.dispose();
});

test('deps: client validation of the tree — required provider, names, fields of nested nodes', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const root = d.newNode(probe, { name: 'Probe 3' });
  let v = d.validateTree(root, fieldsBy);
  assert.equal(v.ok, false);
  assert.deepEqual(v.deps, { [root.deps[0].key]: 'Выберите поставщика' }, 'the optional one is fine empty');
  assert.deepEqual(v.first, { key: root.key, step: 'deps' });
  const sub = d.newNode(hello, { name: 'Hello 3', depth: 1, chain: root.chain });
  sub.sameTarget = false; // no inherited target, and the field is empty
  root.deps[0].choice = { kind: 'new', node: sub };
  v = d.validateTree(root, fieldsBy);
  assert.equal(v.ok, false);
  assert.equal(v.fields[sub.key].target, 'Обязательное поле');
  assert.deepEqual(v.first, { key: sub.key, step: 'form' }, 'the error opens the nested step');
  sub.values.target = 'ssh:3';
  sub.name = ' ';
  assert.equal(d.validateTree(root, fieldsBy).fields[sub.key].__name, 'Введите имя');
  sub.name = 'Hello 3';
  assert.equal(d.validateTree(root, fieldsBy).ok, true);
  // an existing provider without an instance is an error
  root.deps[0].choice = { kind: 'existing', instance: 0, port: 'web' };
  assert.equal(d.validateTree(root, fieldsBy).ok, false);
  env.dispose();
});

test('deps: server errors go to their own nested nodes by path', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const root = d.newNode(relay, { name: 'R1' });
  const mid = d.newNode(relay, { name: 'R2', depth: 1, chain: ['x'] });
  const leaf = d.newNode(hello, { name: 'H', depth: 2, chain: ['x', 'y'] });
  mid.deps[0].choice = { kind: 'new', node: leaf };
  root.deps[0].choice = { kind: 'new', node: mid };
  const { route } = d.buildCompose(root, (id) => (plugins[id] || relay).manifest.schema.fields);
  const dist = d.distributeErrors(route, [
    { field: 'deps[0].new.deps[0].new.target', msg: 'Выберите сервер' },
    { field: 'deps[0].new.deps[0].new.port', msg: 'нет порта' },
    { field: 'deps[0].new.name', msg: 'имя занято' },
    { field: 'deps', msg: 'не выбран поставщик' },
    { field: 'deps[7].port', msg: 'нет такого' },
    { field: 'deps[0].new.plugin_id', msg: 'плагин не найден' },
  ]);
  assert.deepEqual(dist.fields[leaf.key], { target: 'Выберите сервер' });
  assert.deepEqual(dist.fields[mid.key], { __name: 'имя занято' });
  assert.equal(dist.deps[mid.deps[0].key], 'нет порта', 'new.port is a problem of the dependency itself');
  assert.equal(dist.nodeDeps[root.key], 'не выбран поставщик');
  assert.deepEqual(dist.general.sort(), ['нет такого', 'плагин не найден']);
  assert.deepEqual(d.firstErrorStep(root, dist), { key: root.key, step: 'deps' });
  assert.deepEqual(d.firstErrorStep(root, { fields: { [leaf.key]: { x: 'y' } }, deps: {}, nodeDeps: {} }), { key: leaf.key, step: 'form' });
  assert.equal(d.firstErrorStep(root, { fields: {}, deps: {}, nodeDeps: {} }), null);
  env.dispose();
});

test('deps: error indexes follow the request, not the slots (an empty optional slot is skipped)', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const root = d.newNode(probe, { name: 'P' });
  // slot 0 (required) is empty here and slot 1 (optional) is closed: it is deps[0] of the request
  const sub = d.newNode(hello, { name: 'H', depth: 1, chain: root.chain });
  root.deps[1].choice = { kind: 'new', node: sub };
  const { body, route } = d.buildCompose(root, fieldsBy);
  assert.equal(body.deps.length, 1);
  assert.equal(body.deps[0].port, 'extra');
  const dist = d.distributeErrors(route, [{ field: 'deps[0].new.target', msg: 'x' }, { field: 'root.interval_s', msg: 'мало' }]);
  assert.deepEqual(dist.fields[sub.key], { target: 'x' });
  assert.deepEqual(dist.fields[root.key], { interval_s: 'мало' });
  env.dispose();
});

test('deps: depth up to 3 and no cycles', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const r0 = d.newNode(relay, { name: 'r0' });
  assert.match(d.newBlockedReason(r0, relay), /цикл/, 'the same plugin along the chain');
  assert.equal(d.newBlockedReason(r0, hello), '');
  assert.equal(d.MAX_DEPTH, 3);
  const deep = d.newNode(relay, { name: 'deep', depth: 3, chain: ['a', 'b', 'c'] });
  assert.match(d.newBlockedReason(deep, hello), /вложенность больше 3/);
  const ok = d.newNode(relay, { name: 'ok', depth: 2, chain: ['a', 'b'] });
  assert.equal(d.newBlockedReason(ok, hello), '');
  // the offers carry the reason, so the UI disables them
  assert.match(d.newProviderOffers([relay], 'http.service', r0)[0].reason, /цикл/);
  env.dispose();
});

test('deps: tree helpers — paths, breadcrumbs, names, used providers', async () => {
  const env = setupEnv();
  const d = await lib(env);
  const root = d.newNode(probe, { name: 'Probe 3' });
  const sub = d.newNode(hello, { name: 'Hello 3', depth: 1, chain: root.chain });
  root.deps[0].choice = { kind: 'new', node: sub };
  root.deps[1].choice = { kind: 'existing', instance: 1, port: 'web' };
  assert.equal(d.findNode(root, sub.key), sub);
  assert.deepEqual(d.pathTo(root, sub.key).map((n) => n.name), ['Probe 3', 'Hello 3']);
  assert.equal(d.pathTo(root, 'nope'), null);
  assert.deepEqual(d.breadcrumb(root, sub.key), ['Probe 3', 'Hello 3']);
  assert.deepEqual([...d.usedProviders(root)], ['1:web']);
  const g = sampleGraph();
  // two names of this plugin are taken (an instance and the tree's node): the next number
  assert.equal(d.nodeName('Hestia Hello', 'hestia-hello', g, root), 'Hestia Hello 3');
  sub.name = 'Hestia Hello 3';
  assert.equal(d.nodeName('Hestia Hello', 'hestia-hello', g, root), 'Hestia Hello 4');
  const names = [];
  d.walk(root, (x) => names.push(x.name));
  assert.deepEqual(names, ['Probe 3', 'Hestia Hello 3']);
  env.dispose();
});
