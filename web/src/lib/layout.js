// Layout of the network map. Positions are not stored: it is computed again every time.
//
// Hosts live in group boxes (xyflow parent nodes): inside a box they stand in a
// grid of fixed-size cards, the box size follows from the grid. dagre only places
// the top levels — the router(s) and the boxes. When there are many boxes they
// are wrapped into several rows, so the map is close to the screen shape.
import { Graph, layout } from '@dagrejs/dagre';

export const CARD = { w: 180, h: 68 };
export const NODE_SIZE = {
  host: CARD,
  net: { w: 150, h: 44 },
};
export const GRID = { pad: 14, gap: 12, label: 34, headerGap: 20, minW: 220 };
export const MAX_COLS = 5;
export const MAX_COLS_PVE = 6;
export const TARGET_ASPECT = 1.6; // the map's width / height we aim at

const rect = (x, y, w, h) => ({ x, y, w, h });

// Sizes and relative card positions inside one group box.
export function layoutGroup(group, children) {
  const header = group.data?.kind === 'proxmox' ? children.find((c) => c.data?.header) : null;
  const cards = children.filter((c) => c !== header);
  const maxCols = group.data?.kind === 'proxmox' ? MAX_COLS_PVE : MAX_COLS;
  const cols = Math.max(1, Math.min(maxCols, Math.ceil(Math.sqrt(cards.length))));
  const used = Math.min(cols, Math.max(cards.length, 1));
  const gridW = used * CARD.w + (used - 1) * GRID.gap;
  const inner = Math.max(gridW, header ? CARD.w : 0);
  const width = Math.max(GRID.minW, inner + 2 * GRID.pad);
  const left = Math.round((width - gridW) / 2);
  const pos = new Map();
  let y = GRID.label;
  if (header) {
    pos.set(header.id, { x: Math.round((width - CARD.w) / 2), y });
    y += CARD.h + GRID.headerGap;
  }
  cards.forEach((c, i) => {
    pos.set(c.id, { x: left + (i % cols) * (CARD.w + GRID.gap), y: y + Math.floor(i / cols) * (CARD.h + GRID.gap) });
  });
  const rows = Math.ceil(cards.length / cols);
  const gridH = rows ? rows * CARD.h + (rows - 1) * GRID.gap : 0;
  const height = y + gridH + GRID.pad;
  return { width, height, pos, cols };
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

  const size = new Map();
  const inner = new Map(); // group id → layoutGroup()
  for (const n of top) {
    if (n.type === 'group') {
      const l = layoutGroup(n, byParent.get(n.id) || []);
      inner.set(n.id, l);
      size.set(n.id, { w: l.width, h: l.height });
    } else size.set(n.id, NODE_SIZE[n.type] || NODE_SIZE.host);
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

  const out = [];
  for (const n of top) {
    const r = placed.out.get(n.id);
    const position = { x: Math.round(r.x - placed.minX), y: Math.round(r.y - placed.minY) };
    if (n.type === 'group') {
      const { width, height } = inner.get(n.id);
      out.push({ ...n, position, width, height, style: `width:${width}px;height:${height}px;` });
    } else out.push({ ...n, position });
  }
  for (const n of top) {
    if (n.type !== 'group') continue;
    const { pos } = inner.get(n.id);
    for (const c of byParent.get(n.id) || []) out.push({ ...c, position: pos.get(c.id) });
  }
  // Children whose parent is missing are dropped from the map by xyflow; keep them out here too.
  return out;
}

// Absolute rectangle of every node, for tests and hit checks.
export function absoluteRects(placed) {
  const by = new Map(placed.map((n) => [n.id, n]));
  return placed.map((n) => {
    const p = n.parentId ? by.get(n.parentId) : null;
    const s = n.type === 'group' ? { w: n.width, h: n.height } : NODE_SIZE[n.type] || NODE_SIZE.host;
    return { id: n.id, type: n.type, parentId: n.parentId, x: n.position.x + (p ? p.position.x : 0), y: n.position.y + (p ? p.position.y : 0), w: s.w, h: s.h };
  });
}
