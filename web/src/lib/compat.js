// Compatibility of ports while a link is dragged on the map. Pure functions over the data
// of GET /graph (and, to refine it, GET /plugins/links/candidates).
//
// Handle ids: `p:<port>` (provides, right) and `r:<port>` (requires, left) on an instance
// node `i:<id>`; `out:<instance>:<port>` (provides exported to the border of a composite
// host); `dev` on a host node `h:<ip>` (the device side of a link «сервис → устройство»).

export const portKey = (dir, instance, port) => `${dir}:${instance}:${port}`;

const PORT = '[a-z][a-z0-9_]*';

// (node id, handle id) → what the handle is.
export function parseHandle(nodeId, handleId) {
  const n = /^i:(\d+)$/.exec(nodeId || '');
  const h = /^h:(.+)$/.exec(nodeId || '');
  let m;
  if (handleId === 'dev') return h ? { kind: 'device', ip: h[1] } : null;
  if (n && (m = new RegExp(`^p:(${PORT})$`).exec(handleId || ''))) return { kind: 'provides', instance: Number(n[1]), port: m[1] };
  if (n && (m = new RegExp(`^r:(${PORT})$`).exec(handleId || ''))) return { kind: 'requires', instance: Number(n[1]), port: m[1] };
  if ((m = new RegExp(`^out:(\\d+):(${PORT})$`).exec(handleId || ''))) return { kind: 'provides', instance: Number(m[1]), port: m[2] };
  return null;
}

const instOf = (graph, id) => (graph?.instances || []).find((i) => i.id === id) || null;
const portOf = (graph, id, dir, name) => (instOf(graph, id)?.[dir] || []).find((p) => p.name === name) || null;

// A port that takes one link only and has it.
export const portBusy = (p) => !!p && !p.multi && p.linked > 0;

const serviceLinked = (graph, provider, consumer) =>
  (graph?.links || []).some(
    (l) =>
      l.kind === 'service' &&
      l.provider.instance === provider.instance &&
      l.provider.port === provider.port &&
      l.consumer?.instance === consumer.instance &&
      l.consumer?.port === consumer.port,
  );

const deviceLinked = (graph, provider, ref) =>
  (graph?.links || []).some((l) => l.kind === 'device' && l.provider.instance === provider.instance && l.provider.port === provider.port && l.device?.ref === ref);

// What the port `from` ({instance, port, dir}) can be linked to, by the graph alone:
// {from, type, ports: {key: {ok, reason}}, hosts: {ip: {ok, reason}}}. Ports of the other
// side with the same type are listed (ok=false with the reason when they cannot be used);
// hosts only for a provides port with `client`.
export function compatibility(graph, from) {
  const empty = { from, type: '', ports: {}, hosts: {} };
  const own = portOf(graph, from?.instance, from?.dir, from?.port);
  if (!own) return empty;
  const out = { from, type: own.type, ports: {}, hosts: {} };
  const otherDir = from.dir === 'provides' ? 'requires' : 'provides';
  const ownReason = portBusy(own) ? 'этот порт уже занят' : !own.linkable ? 'плагин не подключён' : '';
  for (const inst of graph.instances || []) {
    if (inst.id === from.instance) continue;
    for (const p of inst[otherDir] || []) {
      if (p.type !== own.type) continue;
      const a = { instance: inst.id, port: p.name };
      const prov = from.dir === 'provides' ? from : a;
      const cons = from.dir === 'provides' ? a : from;
      let reason = '';
      if (serviceLinked(graph, prov, cons)) reason = 'уже связаны';
      else if (portBusy(p)) reason = 'порт уже занят';
      else if (ownReason) reason = ownReason;
      else if (!p.linkable) reason = 'плагин не подключён';
      out.ports[portKey(otherDir, inst.id, p.name)] = { ok: !reason, reason };
    }
  }
  if (from.dir === 'provides' && own.client) {
    for (const h of graph.hosts || []) {
      if (!h.ref) continue;
      const reason = ownReason || (deviceLinked(graph, from, h.ref) ? 'уже связаны' : '');
      out.hosts[h.ip] = { ok: !reason, reason };
    }
  }
  return out;
}

// Refines the compatibility with the server's answer (GET /plugins/links/candidates of the
// dragged port): the server knows about busy ports and which devices can be used.
export function mergeCandidates(compat, cands, graph) {
  if (!compat || !cands) return compat;
  const otherDir = compat.from.dir === 'provides' ? 'requires' : 'provides';
  const ports = { ...compat.ports };
  for (const c of cands.ports || []) {
    if (c.instance === undefined) continue;
    ports[portKey(otherDir, c.instance, c.port)] = { ok: !!c.available, reason: c.available ? '' : c.reason || 'недоступно' };
  }
  let hosts = compat.hosts;
  if (compat.from.dir === 'provides' && Array.isArray(cands.devices)) {
    const byRef = new Map(cands.devices.map((d) => [d.device, d]));
    hosts = {};
    for (const h of graph?.hosts || []) {
      const d = byRef.get(h.ref);
      if (d) hosts[h.ip] = { ok: !!d.available, reason: d.available ? '' : d.reason || 'недоступно' };
    }
  }
  return { ...compat, ports, hosts };
}

// A connection of xyflow ({source, target, sourceHandle, targetHandle}) → what it would link:
//   {kind: 'service', provider: {instance, port}, consumer: {instance, port}} |
//   {kind: 'device', provider: {instance, port}, device: {ref, ip}} | null.
export function resolveConnection(graph, conn) {
  const a = parseHandle(conn?.source, conn?.sourceHandle);
  const b = parseHandle(conn?.target, conn?.targetHandle);
  if (!a || !b || a.kind !== 'provides') return null;
  const provider = { instance: a.instance, port: a.port };
  if (b.kind === 'requires') return { kind: 'service', provider, consumer: { instance: b.instance, port: b.port } };
  if (b.kind === 'device') {
    const h = (graph?.hosts || []).find((x) => x.ip === b.ip);
    return h?.ref ? { kind: 'device', provider, device: { ref: h.ref, ip: h.ip } } : null;
  }
  return null;
}

// Whether the resolved connection is one the drag (compat of the origin port) allows.
export function connectionAllowed(compat, r) {
  if (!compat?.from || !r) return false;
  const f = compat.from;
  if (r.kind === 'service') {
    if (f.dir === 'provides') return r.provider.instance === f.instance && r.provider.port === f.port && !!compat.ports[portKey('requires', r.consumer.instance, r.consumer.port)]?.ok;
    return r.consumer.instance === f.instance && r.consumer.port === f.port && !!compat.ports[portKey('provides', r.provider.instance, r.provider.port)]?.ok;
  }
  return f.dir === 'provides' && r.provider.instance === f.instance && r.provider.port === f.port && !!compat.hosts[r.device.ip]?.ok;
}

// Look of a port handle while dragging: '' (no drag), 'source', 'ok', 'blocked' (right type but
// unusable — the reason is in compat), 'dim'.
export function handleMark(compat, dir, instance, port) {
  if (!compat?.from) return '';
  const f = compat.from;
  if (f.dir === dir && f.instance === instance && f.port === port) return 'source';
  const c = compat.ports[portKey(dir, instance, port)];
  if (!c) return 'dim';
  return c.ok ? 'ok' : 'blocked';
}

export function hostMark(compat, ip) {
  if (!compat?.from) return '';
  const c = compat.hosts[ip];
  if (!c) return 'dim';
  return c.ok ? 'ok' : 'blocked';
}

// The origin of a drag from xyflow's onconnectstart params ({nodeId, handleId}).
export function dragOrigin(nodeId, handleId) {
  const h = parseHandle(nodeId, handleId);
  if (!h || (h.kind !== 'provides' && h.kind !== 'requires')) return null;
  return { instance: h.instance, port: h.port, dir: h.kind };
}
