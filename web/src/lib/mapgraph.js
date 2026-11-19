// The map with plugin instances: the network graph of netmap.js plus composite hosts
// (a host with instances is a node with instance sub-nodes inside), the «Без хоста» box
// and the link edges. Input: GET /network (view) and GET /graph (graph). Pure, no DOM.
import { buildGraph, defaultFilters } from './netmap.js';

export const NOHOST_ID = 'g:nohost';
export const hostNodeId = (ip) => 'h:' + ip;
export const instNodeId = (id) => 'i:' + id;
export const linkEdgeId = (id) => 'l:' + id;

// Status of a link or instance → colour of its edge / frame (daisyUI CSS variables).
export const STATUS_COLOR = {
  ok: 'var(--color-success)',
  degraded: 'var(--color-warning)',
  down: 'var(--color-error)',
  failed: 'var(--color-error)',
  orphaned: 'var(--color-error)',
  unknown: 'var(--color-neutral)',
};

export function statusColor(status) {
  return STATUS_COLOR[status] || STATUS_COLOR.unknown;
}

// An unclosed required requires port is drawn red.
export const portOpen = (p) => !p.optional && !(p.linked > 0);

function instanceData(inst) {
  return {
    id: inst.id,
    label: inst.name,
    plugin: inst.plugin_name || inst.plugin_id,
    pluginId: inst.plugin_id,
    iconUrl: inst.icon_url || '',
    status: inst.status,
    detail: inst.detail || '',
    provides: inst.provides || [],
    requires: (inst.requires || []).map((p) => ({ ...p, open: portOpen(p) })),
    containers: inst.containers || [],
  };
}

function matchesInstance(inst, q) {
  if (!q) return true;
  return [inst.name, inst.plugin_name, inst.plugin_id].filter(Boolean).join('\n').toLowerCase().includes(q);
}

// The IP of the host an instance stands on ('' when it is not on the map): the host of its
// target, or the controller's host when it has no target.
export function instanceHostIP(graph, inst, knownIPs) {
  const ip = inst.host_ip || (inst.controller ? graph?.controller_ip || '' : '');
  return ip && knownIPs.has(ip) ? ip : '';
}

// Builds {nodes, edges, linkEdges, counts}: `edges` are the tree edges the layout needs,
// `linkEdges` are the links (edges between ports; they do not take part in the layout).
// graph may be null (no plugins): the result is the plain network map.
export function buildMapGraph(view, graph, filters = defaultFilters()) {
  const instances = graph?.instances || [];
  const q = (filters.query || '').trim().toLowerCase();
  const known = new Set((view?.hosts || []).map((h) => h.ip));
  const byHost = new Map(); // ip → instances
  const noHost = [];
  const extra = new Map();
  for (const inst of instances) {
    const ip = instanceHostIP(graph, inst, known);
    if (!ip) {
      // On a host that exists but whose address is not on the map: «Без хоста».
      if (matchesInstance(inst, q)) noHost.push(inst);
      continue;
    }
    byHost.set(ip, [...(byHost.get(ip) || []), inst]);
    extra.set(ip, (extra.get(ip) || '') + '\n' + [inst.name, inst.plugin_name].join(' '));
  }

  const base = buildGraph(view, filters, { keep: new Set(byHost.keys()), extra });
  const nodes = base.nodes;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const instNodes = [];
  const addInst = (inst, parentId) =>
    instNodes.push({ id: instNodeId(inst.id), type: 'inst', parentId, extent: 'parent', draggable: false, position: { x: 0, y: 0 }, data: instanceData(inst) });

  for (const n of nodes) if (n.type === 'host' && n.data.ip && n.data.ip === graph?.controller_ip) n.data = { ...n.data, controller: true };
  for (const [ip, list] of byHost) {
    const host = byId.get(hostNodeId(ip));
    if (!host) continue; // the host is filtered out (by the search): its instances too
    host.type = 'chost';
    host.data = { ...host.data, instances: list.length };
    for (const inst of list) addInst(inst, host.id);
  }
  if (noHost.length) {
    nodes.push({ id: NOHOST_ID, type: 'group', position: { x: 0, y: 0 }, data: { label: 'Без хоста', kind: 'nohost', count: noHost.length } });
    for (const inst of noHost) addInst(inst, NOHOST_ID);
  }
  // A parent must precede its children.
  nodes.push(...instNodes);
  const nodeOf = new Map(nodes.map((n) => [n.id, n]));

  // Link edges. A provider on another host leaves from the port exported to the border of
  // its composite host; inside a host the edge goes between the instance cards.
  const source = (instance, port, targetParent) => {
    const n = nodeOf.get(instNodeId(instance));
    if (!n) return null;
    if (nodeOf.get(n.parentId)?.type === 'chost' && n.parentId !== targetParent) return { source: n.parentId, sourceHandle: `out:${instance}:${port}` };
    return { source: n.id, sourceHandle: 'p:' + port };
  };
  const linkEdges = [];
  for (const l of graph?.links || []) {
    let to = null;
    if (l.kind === 'service' && l.consumer) {
      const c = nodeOf.get(instNodeId(l.consumer.instance));
      if (c) to = { target: c.id, targetHandle: 'r:' + l.consumer.port, parent: c.parentId };
    } else if (l.kind === 'device' && l.device) {
      const h = nodeOf.get(hostNodeId(l.device.host_ip));
      if (h) to = { target: h.id, targetHandle: 'dev', parent: h.id };
    }
    const from = to && source(l.provider.instance, l.provider.port, to.parent);
    if (!to || !from) continue;
    linkEdges.push({
      id: linkEdgeId(l.id),
      type: 'link',
      ...from,
      target: to.target,
      targetHandle: to.targetHandle,
      data: { link: l, label: l.type || '', detail: l.detail || '', status: l.status, color: statusColor(l.status), dashed: l.kind === 'device' },
    });
  }
  return { nodes, edges: base.edges, linkEdges, counts: { ...base.counts, instances: instances.length } };
}

// What a node id of the map stands for: {kind: 'host'|'instance'|'link', id}.
export function parseNodeId(id) {
  const s = String(id || '');
  if (s.startsWith('h:')) return { kind: 'host', id: s.slice(2) };
  if (s.startsWith('i:')) return { kind: 'instance', id: Number(s.slice(2)) };
  if (s.startsWith('l:')) return { kind: 'link', id: Number(s.slice(2)) };
  return null;
}

export const instanceById = (graph, id) => (graph?.instances || []).find((i) => i.id === id) || null;
export const linkById = (graph, id) => (graph?.links || []).find((l) => l.id === id) || null;
export const linksOfInstance = (graph, id) => (graph?.links || []).filter((l) => l.provider?.instance === id || l.consumer?.instance === id);
