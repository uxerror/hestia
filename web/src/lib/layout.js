// Layout of the network map. Positions of sub-nodes are never stored: they are
// computed again every time (the user's own positions of hosts and boxes are merged
// in by positions.js).
//
// Hosts live in group boxes (xyflow parent nodes): inside a box they stand in a
// grid of cards, the box size follows from the grid. A host with plugin instances is
// a composite node ('chost'): its card is the header, the instances (type 'inst', with
// their ports and container rows) stand below it; the `provides` ports of the instances
// are also exported to the border of the composite (data.exports). dagre only places the
// top levels — the router(s) and the boxes. When there are many boxes they are wrapped
// into several rows, so the map is close to the screen shape.
import { Graph, layout } from '@dagrejs/dagre';

export const CARD = { w: 180, h: 68 };
export const NODE_SIZE = {
  host: CARD,
  net: { w: 150, h: 44 },
};
export const GRID = { pad: 14, gap: 12, label: 34, headerGap: 20, minW: 220 };
// An instance card: head (name, status), one row per port pair, then container rows.
export const INST = { w: 232, head: 44, row: 22, cont: 20, pad: 8, maxCont: 5 };
export const HOST_BOX = { pad: 8, gap: 8 };

// Container rows shown in an instance card ("ещё N" takes the last one).
export function containerRows(containers) {
  const n = containers?.length || 0;
  return n > INST.maxCont ? INST.maxCont + 1 : n;
}

export function instanceSize(d) {
  const rows = Math.max(d?.provides?.length || 0, d?.requires?.length || 0);
  const nc = containerRows(d?.containers);
  return { w: INST.w, h: INST.head + rows * INST.row + (nc ? 6 + nc * INST.cont : 0) + INST.pad };
}

// y of the handle of the i-th port row inside an instance card.
export const portY = (i) => INST.head + i * INST.row + INST.row / 2;

// Cells of different sizes in `cols` columns: column widths and row heights follow the
// biggest cell; returns the offsets, the total size and nothing else.
export function gridLayout(sizes, cols, gap) {
  const colW = [];
  const rowH = [];
  sizes.forEach((s, i) => {
    const c = i % cols;
    const r = Math.floor(i / cols);
    colW[c] = Math.max(colW[c] || 0, s.w);
    rowH[r] = Math.max(rowH[r] || 0, s.h);
  });
  const xs = [];
  let x = 0;
  colW.forEach((w) => (xs.push(x), (x += w + gap)));
  const ys = [];
  let y = 0;
  rowH.forEach((h) => (ys.push(y), (y += h + gap)));
  const pos = sizes.map((_, i) => ({ x: xs[i % cols], y: ys[Math.floor(i / cols)] }));
  const w = colW.length ? colW.reduce((a, b) => a + b, 0) + (colW.length - 1) * gap : 0;
  const h = rowH.length ? rowH.reduce((a, b) => a + b, 0) + (rowH.length - 1) * gap : 0;
  return { pos, w, h };
}
export const MAX_COLS = 5;
export const MAX_COLS_PVE = 6;
export const TARGET_ASPECT = 1.6; // the map's width / height we aim at

const rect = (x, y, w, h) => ({ x, y, w, h });

const defaultSize = (n) => NODE_SIZE[n.type] || NODE_SIZE.host;

// Sizes and relative card positions inside one group box. sizeOf(node) gives the size of
// a child (a card, a composite host or an instance).
export function layoutGroup(group, children, sizeOf = defaultSize) {
  const header = group.data?.kind === 'proxmox' ? children.find((c) => c.data?.header) : null;
  const cards = children.filter((c) => c !== header);
  const maxCols = group.data?.kind === 'proxmox' ? MAX_COLS_PVE : MAX_COLS;
  const cols = Math.max(1, Math.min(maxCols, Math.ceil(Math.sqrt(cards.length))));
  const grid = gridLayout(cards.map(sizeOf), cols, GRID.gap);
  const hs = header ? sizeOf(header) : null;
  const gridW = cards.length || header ? grid.w : CARD.w;
  const inner = Math.max(gridW, hs ? hs.w : 0);
  const width = Math.max(GRID.minW, inner + 2 * GRID.pad);
  const left = Math.round((width - gridW) / 2);
  const pos = new Map();
  let y = GRID.label;
  if (header) {
    pos.set(header.id, { x: Math.round((width - hs.w) / 2), y });
    y += hs.h + GRID.headerGap;
  }
  cards.forEach((c, i) => pos.set(c.id, { x: left + grid.pos[i].x, y: y + grid.pos[i].y }));
  const height = y + grid.h + GRID.pad;
  return { width, height, pos, cols };
}

// A composite host: its card on top, the instances below (one column, two when there are
// many). Returns the size, the relative positions and the ports exported to the border.
export function layoutHost(host, kids) {
  const sizes = kids.map((k) => instanceSize(k.data));
  const cols = kids.length > 3 ? 2 : 1;
  const grid = gridLayout(sizes, cols, HOST_BOX.gap);
  const width = Math.max(CARD.w, grid.w + 2 * HOST_BOX.pad);
  const top = CARD.h + HOST_BOX.gap;
  const left = Math.round((width - grid.w) / 2);
  const pos = new Map();
  const exports = [];
  kids.forEach((k, i) => {
    const p = { x: left + grid.pos[i].x, y: top + grid.pos[i].y };
    pos.set(k.id, p);
    (k.data?.provides || []).forEach((port, j) => exports.push({ instance: k.data.id, port: port.name, label: port.label || port.name, y: p.y + portY(j) }));
  });
  return { width, height: top + grid.h + HOST_BOX.pad, pos, exports };
}

// Splits boxes into rows of at most k.
const chunk = (arr, k) => {
  const rows = [];
  for (let i = 0; i < arr.length; i += k) rows.push(arr.slice(i, i + k));
  return rows;
};

function placeTop(items, size, edges, plan, opts) {
  const g = new Graph();
  g.setGraph({ rankdir: 'TB', ranksep: opts.rankSep, nodesep: opts.nodeSep, marginx: 0, marginy: 0 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of items) g.setNode(n.id, { width: size.get(n.id).w, height: size.get(n.id).h });
  // root → boxes of the first row; every box of a row → every box of the next one
  // (this keeps the rows on their own ranks).
  for (const { root, rows } of plan) {
    rows.forEach((row, i) => {
      if (i === 0) {
        if (root) for (const b of row) g.setEdge(root, b);
      } else for (const a of rows[i - 1]) for (const b of row) g.setEdge(a, b);
    });
  }
  layout(g);
  const out = new Map();
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of items) {
    const p = g.node(n.id);
    const s = size.get(n.id);
    const r = rect(p.x - s.w / 2, p.y - s.h / 2, s.w, s.h);
    out.set(n.id, r);
    minX = Math.min(minX, r.x);
    minY = Math.min(minY, r.y);
    maxX = Math.max(maxX, r.x + r.w);
    maxY = Math.max(maxY, r.y + r.h);
  }
  return { out, minX, minY, w: maxX - minX, h: maxY - minY };
}

// Returns new nodes with positions (top-left corner; for children relative to the
// box) and, for boxes, width/height. Parents come before their children.
export function layoutGraph(nodes, edges, { rankSep = 56, nodeSep = 28, aspect = TARGET_ASPECT } = {}) {
  const byParent = new Map();
  for (const n of nodes) if (n.parentId) byParent.set(n.parentId, [...(byParent.get(n.parentId) || []), n]);
  const top = nodes.filter((n) => !n.parentId);
  const topIds = new Set(top.map((n) => n.id));

  // Composite hosts first: their size is needed by the boxes they stand in.
  const hostInner = new Map(); // composite id → layoutHost()
  for (const n of nodes) if (n.type === 'chost') hostInner.set(n.id, layoutHost(n, (byParent.get(n.id) || []).filter((c) => c.type === 'inst')));
  const sizeOf = (n) => {
    if (n.type === 'inst') return instanceSize(n.data);
    if (n.type === 'chost') {
      const l = hostInner.get(n.id);
      return { w: l.width, h: l.height };
    }
    return defaultSize(n);
  };

  const size = new Map();
  const inner = new Map(); // group id → layoutGroup()
  for (const n of top) {
    if (n.type === 'group') {
      const l = layoutGroup(n, byParent.get(n.id) || [], sizeOf);
      inner.set(n.id, l);
      size.set(n.id, { w: l.width, h: l.height });
    } else size.set(n.id, sizeOf(n));
  }

  // Which boxes hang under which root (the first edge wins), in node order.
  const isGroup = new Map(top.filter((n) => n.type === 'group').map((n) => [n.id, true]));
  const owner = new Map();
  for (const e of edges) if (topIds.has(e.source) && isGroup.get(e.target) && !isGroup.get(e.source) && !owner.has(e.target)) owner.set(e.target, e.source);
  const rootsOf = top.filter((n) => n.type !== 'group');
  const lists = rootsOf.map((r) => ({ root: r.id, boxes: top.filter((n) => owner.get(n.id) === r.id).map((n) => n.id) }));
  const orphans = top.filter((n) => n.type === 'group' && !owner.has(n.id)).map((n) => n.id);
  if (orphans.length) lists.push({ root: null, boxes: orphans });

  // Try every "boxes per row" and keep the layout closest to the wanted shape.
  const maxK = Math.max(1, ...lists.map((l) => l.boxes.length));
  let best = null;
  for (let k = 1; k <= maxK; k++) {
    const plan = lists.map((l) => ({ root: l.root, rows: chunk(l.boxes, k) }));
    const t = placeTop(top, size, edges, plan, { rankSep, nodeSep });
    const score = Math.abs(Math.log(t.w / t.h / aspect));
    if (!best || score < best.score - 1e-9) best = { score, t };
  }
  const placed = best ? best.t : placeTop(top, size, edges, [], { rankSep, nodeSep });

  // A composite host gets its size and the ports exported to its border.
  const emit = (n, position) => {
    if (n.type === 'group') {
      const { width, height } = inner.get(n.id);
      return { ...n, position, width, height, style: `width:${width}px;height:${height}px;` };
    }
    if (n.type === 'chost') {
      const { width, height, exports } = hostInner.get(n.id);
      return { ...n, position, width, height, style: `width:${width}px;height:${height}px;`, data: { ...n.data, exports } };
    }
    return { ...n, position };
  };
  const out = [];
  for (const n of top) {
    const r = placed.out.get(n.id);
    out.push(emit(n, { x: Math.round(r.x - placed.minX), y: Math.round(r.y - placed.minY) }));
  }
  const composites = top.filter((n) => n.type === 'chost');
  for (const n of top) {
    if (n.type !== 'group') continue;
    const { pos } = inner.get(n.id);
    for (const c of byParent.get(n.id) || []) {
      out.push(emit(c, pos.get(c.id)));
      if (c.type === 'chost') composites.push(c);
    }
  }
  for (const h of composites) {
    const { pos } = hostInner.get(h.id);
    for (const c of byParent.get(h.id) || []) if (pos.has(c.id)) out.push({ ...c, position: pos.get(c.id) });
  }
  // Children whose parent is missing are dropped from the map by xyflow; keep them out here too.
  return out;
}

// Absolute rectangle of every node, for tests and hit checks.
export function absoluteRects(placed) {
  const by = new Map(placed.map((n) => [n.id, n]));
  const sizeOf = (n) => (n.width ? { w: n.width, h: n.height } : n.type === 'inst' ? instanceSize(n.data) : NODE_SIZE[n.type] || NODE_SIZE.host);
  const abs = (n) => {
    let x = n.position.x;
    let y = n.position.y;
    for (let p = n.parentId && by.get(n.parentId); p; p = p.parentId && by.get(p.parentId)) {
      x += p.position.x;
      y += p.position.y;
    }
    return { x, y };
  };
  return placed.map((n) => ({ id: n.id, type: n.type, parentId: n.parentId, ...abs(n), ...sizeOf(n) }));
}
