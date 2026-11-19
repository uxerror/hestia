// State of the «Зависимости» step of the instance wizard. A tree: the root is the instance
// being created; each node has `deps` — one per requires port of its plugin — and each
// dependency is closed by an existing provider or by a new instance (a nested node, which
// has its own form and dependencies). The tree becomes the body of POST /plugins/compose/plan,
// and the server's errors (paths like `deps[0].new.target`) go back to the nodes.
import { fieldsOf, initialValues, toConfig, validate } from './schemaform.js';
import { suggestedInstanceName } from './plugins.js';

export const MAX_DEPTH = 3; // nesting of new providers (as on the server)

let seq = 0;
const nextKey = (p) => `${p}${++seq}`;

// A dependency slot for a requires port: choice is null | {kind: 'existing', instance, port}
// | {kind: 'new', node}.
export function newDep(port) {
  return {
    key: nextKey('d'),
    port: port.name,
    type: port.type,
    label: port.label || port.name,
    optional: !!port.optional,
    choice: null,
  };
}

export const requiresOf = (plugin) => plugin?.manifest?.requires || plugin?.requires || [];
export const providesOf = (plugin) => plugin?.manifest?.provides || plugin?.provides || [];
export const schemaOf = (plugin) => plugin?.manifest?.schema || null;

// A node of the tree: plugin = GET /plugins/{id}; chain = ids of the plugins from the root.
export function newNode(plugin, { name = '', depth = 0, chain = [], port = '' } = {}) {
  const fields = fieldsOf(schemaOf(plugin));
  return {
    key: nextKey('n'),
    pluginId: plugin.id,
    pluginName: plugin.name || plugin.id,
    name,
    port, // the provides port to link (a new provider; '' = the only one that fits)
    depth,
    chain: [...chain, plugin.id],
    values: initialValues(fields, null),
    sameTarget: true, // «тот же сервер»: the target of the nearest ancestor that has one
    deps: requiresOf(plugin).map(newDep),
    step: 'form', // form | deps
  };
}

export function walk(node, fn, parent = null) {
  fn(node, parent);
  for (const d of node.deps) if (d.choice?.kind === 'new') walk(d.choice.node, fn, node);
}

export function findNode(root, key) {
  let found = null;
  walk(root, (n) => {
    if (n.key === key) found = n;
  });
  return found;
}

// The nodes from the root down to the node with the key (null if absent).
export function pathTo(root, key) {
  if (root.key === key) return [root];
  for (const d of root.deps) {
    if (d.choice?.kind !== 'new') continue;
    const p = pathTo(d.choice.node, key);
    if (p) return [root, ...p];
  }
  return null;
}

const targetFieldsOf = (fields) => fields.filter((f) => f.type === 'target');

// The target value a nested node inherits: from the nearest ancestor that has one ('' if none).
export function inheritedTarget(ancestors, fieldsByPlugin) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const a = ancestors[i];
    for (const f of targetFieldsOf(fieldsByPlugin(a.pluginId))) {
      const v = effectiveValues(a, ancestors.slice(0, i), fieldsByPlugin)[f.name];
      if (v) return v;
    }
  }
  return '';
}

// Form values of a node: with «тот же сервер» the target fields take the inherited value.
export function effectiveValues(node, ancestors, fieldsByPlugin) {
  const values = { ...node.values };
  if (node.sameTarget && ancestors.length) {
    const inherited = inheritedTarget(ancestors, fieldsByPlugin);
    if (inherited) for (const f of targetFieldsOf(fieldsByPlugin(node.pluginId))) values[f.name] = inherited;
  }
  return values;
}

// Why a new instance of `plugin` cannot be created under `node` ('' if it can).
export function newBlockedReason(node, plugin) {
  if (node.chain.includes(plugin.id)) return 'цикл: этот плагин уже есть в цепочке зависимостей';
  if (node.depth >= MAX_DEPTH) return `вложенность больше ${MAX_DEPTH}`;
  if (plugin.multi_instance === false && (plugin.instances || 0) > 0) return 'плагин поддерживает один экземпляр, он уже есть';
  return '';
}

// Installed plugins that can provide the type as a new instance: [{pluginId, name, port, reason}].
export function newProviderOffers(plugins, type, node) {
  const out = [];
  for (const p of plugins || []) {
    if (!p.enabled || p.state !== 'connected') continue;
    const ports = (p.provides || []).filter((x) => x.type === type);
    if (!ports.length) continue;
    // Several ports of the type: the first is taken (the server asks for `port` otherwise).
    out.push({ pluginId: p.id, name: p.name || p.id, port: ports.length > 1 ? ports[0].name || '' : '', ports: ports.length, reason: newBlockedReason(node, p) });
  }
  return out;
}

// Existing providers of a type (instances of GET /graph): busy ports (one link, taken) are
// listed but disabled. used = Set of "<instance>:<port>" already chosen in this tree.
export function existingProviders(graph, type, used = new Set()) {
  const out = [];
  for (const inst of graph?.instances || []) {
    for (const p of inst.provides || []) {
      if (p.type !== type) continue;
      let reason = '';
      if (!p.multi && (p.linked > 0 || used.has(`${inst.id}:${p.name}`))) reason = 'порт уже занят';
      else if (!p.linkable) reason = 'плагин не подключён';
      out.push({
        instance: inst.id,
        port: p.name,
        name: inst.name,
        pluginName: inst.plugin_name || inst.plugin_id,
        label: p.label || p.name,
        status: inst.status,
        hostIP: inst.host_ip || '',
        controller: !!inst.controller,
        disabled: !!reason,
        reason,
      });
    }
  }
  return out;
}

// «instance:port» of the existing providers chosen in the tree (for busy marks).
export function usedProviders(root) {
  const used = new Set();
  walk(root, (n) => {
    for (const d of n.deps) if (d.choice?.kind === 'existing') used.add(`${d.choice.instance}:${d.choice.port}`);
  });
  return used;
}

// A default name for a new nested instance: «<plugin> N» not taken by an instance or by the tree.
export function nodeName(pluginName, pluginId, graph, root) {
  const taken = (graph?.instances || []).filter((i) => i.plugin_id === pluginId).map((i) => ({ name: i.name }));
  if (root) walk(root, (n) => n.pluginId === pluginId && n.name && taken.push({ name: n.name }));
  return suggestedInstanceName(pluginName, taken);
}

// The dependencies the user closed (an optional one left empty is not sent).
export const chosenDeps = (node) => node.deps.filter((d) => d.choice);

// The request of POST /plugins/compose/plan and the route of its dependency indexes:
// {body, route} where route = {key, deps: [{key: depKey, child: route|null}]} mirrors the
// `deps` arrays of the request (the server reports errors by index).
export function buildCompose(root, fieldsByPlugin) {
  const make = (node, ancestors, nested) => {
    const fields = fieldsByPlugin(node.pluginId);
    const config = toConfig(fields, effectiveValues(node, ancestors, fieldsByPlugin));
    const out = { plugin_id: node.pluginId, name: node.name.trim(), config };
    if (nested && node.port) out.port = node.port;
    const route = { key: node.key, deps: [] };
    const deps = [];
    for (const d of chosenDeps(node)) {
      if (d.choice.kind === 'existing') {
        deps.push({ port: d.port, existing: { instance: d.choice.instance, port: d.choice.port } });
        route.deps.push({ key: d.key, child: null });
      } else {
        const sub = make(d.choice.node, [...ancestors, node], true);
        deps.push({ port: d.port, new: sub.body });
        route.deps.push({ key: d.key, child: sub.route });
      }
    }
    if (nested) {
      if (deps.length) out.deps = deps;
      return { body: out, route };
    }
    return { body: { root: out, deps }, route };
  };
  return make(root, [], false);
}

// Whether the tree needs a composite plan (some dependency is closed).
export const needsCompose = (root) => chosenDeps(root).length > 0;

// Server errors → the nodes. Paths (relative to the request): «target» (root field),
// «deps[0].new.target» (field of a nested node), «deps[0].new.port» / «deps[0].port» /
// «deps[0].existing.port» (the dependency itself), «deps» (a required one is not closed).
// Returns {fields: {nodeKey: {field: msg}}, deps: {depKey: msg}, nodeDeps: {nodeKey: msg},
// general: [msg]}.
export function distributeErrors(route, serverFields) {
  const out = { fields: {}, deps: {}, nodeDeps: {}, general: [] };
  for (const f of serverFields || []) {
    if (!f?.field) continue;
    let r = route;
    let rest = f.field;
    rest = rest.replace(/^root\./, '');
    for (;;) {
      const m = /^deps\[(\d+)\]\.(.*)$/.exec(rest);
      if (!m) break;
      const dep = r.deps[Number(m[1])];
      if (!dep) {
        out.general.push(f.msg);
        r = null;
        break;
      }
      const tail = m[2];
      if (tail.startsWith('new.') && dep.child && tail !== 'new.port') {
        r = dep.child;
        rest = tail.slice(4);
        continue;
      }
      // port, existing.*, new.port: the dependency itself
      out.deps[dep.key] ||= f.msg;
      r = null;
      break;
    }
    if (!r) continue;
    if (rest === 'deps') out.nodeDeps[r.key] ||= f.msg;
    else if (rest === 'plugin_id' || rest === 'port') out.general.push(f.msg);
    else (out.fields[r.key] ||= {})[rest === 'name' ? '__name' : rest] ||= f.msg;
  }
  return out;
}

// The first node (depth-first) that has an error and the step that shows it.
export function firstErrorStep(root, dist) {
  let found = null;
  walk(root, (n) => {
    if (found) return;
    if (dist.fields[n.key] && Object.keys(dist.fields[n.key]).length) found = { key: n.key, step: 'form' };
    else if (dist.nodeDeps[n.key] || n.deps.some((d) => dist.deps[d.key])) found = { key: n.key, step: 'deps' };
  });
  return found;
}

// Client validation of the whole tree: {ok, fields: {nodeKey: {..}}, deps: {depKey: msg}, first}.
export function validateTree(root, fieldsByPlugin, { targets = null, secretsSet = [] } = {}) {
  const res = { ok: true, fields: {}, deps: {}, first: null };
  const visit = (node, ancestors) => {
    const fields = fieldsByPlugin(node.pluginId);
    const values = effectiveValues(node, ancestors, fieldsByPlugin);
    const inherited = node.sameTarget && ancestors.length ? inheritedTarget(ancestors, fieldsByPlugin) : '';
    const errs = validate(fields, values, { targets: inherited ? null : targets, secretsSet });
    if (!node.name.trim()) errs.__name = 'Введите имя';
    if (Object.keys(errs).length) res.fields[node.key] = errs;
    for (const d of node.deps) {
      if (!d.choice && !d.optional) res.deps[d.key] = 'Выберите поставщика';
      else if (d.choice?.kind === 'existing' && !d.choice.instance) res.deps[d.key] = 'Выберите поставщика';
    }
  };
  const rec = (node, ancestors) => {
    visit(node, ancestors);
    for (const d of node.deps) if (d.choice?.kind === 'new') rec(d.choice.node, [...ancestors, node]);
  };
  rec(root, []);
  res.ok = !Object.keys(res.fields).length && !Object.keys(res.deps).length;
  res.first = firstErrorStep(root, { fields: res.fields, deps: res.deps, nodeDeps: {} });
  return res;
}

// «Probe 1 › Hestia Hello 1» for the header of a nested step.
export function breadcrumb(root, key) {
  return (pathTo(root, key) || []).map((n) => n.name || n.pluginName);
}
