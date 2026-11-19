// Positions of the map nodes the user moved: merging with the automatic layout and saving
// with a delay. Sub-nodes (instances) are always laid out automatically.

// Whether a node of the map keeps a position the user gave it.
export const isMovable = (n) => !!n && n.type !== 'inst';

const finite = (p) => !!p && Number.isFinite(p.x) && Number.isFinite(p.y);

// Saved positions win over the automatic ones (`position` of a child is relative to its parent).
export function mergePositions(nodes, saved) {
  if (!saved) return nodes;
  return nodes.map((n) => (isMovable(n) && finite(saved[n.id]) ? { ...n, position: { x: saved[n.id].x, y: saved[n.id].y } } : n));
}

// How many nodes have a saved position (for the «Разложить заново» button).
export function savedCount(nodes, saved) {
  return (nodes || []).filter((n) => isMovable(n) && finite(saved?.[n.id])).length;
}

// The positions to save after a drag: only movable nodes.
export function dragged(nodes) {
  const out = {};
  for (const n of nodes || []) if (isMovable(n) && finite(n.position)) out[n.id] = { x: Math.round(n.position.x), y: Math.round(n.position.y) };
  return out;
}

// Collects moves and sends them in one request after `delay` ms without new moves.
export class PositionSaver {
  // The timer functions are called as plain functions: browsers refuse setTimeout with another `this`.
  constructor(save, { delay = 1000, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = (id) => clearTimeout(id), onError } = {}) {
    this.save = save;
    this.delay = delay;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.onError = onError;
    this.pending = {};
    this.timer = null;
  }

  move(positions) {
    const ids = Object.keys(positions || {});
    if (!ids.length) return;
    Object.assign(this.pending, positions);
    if (this.timer !== null) this.clearTimer(this.timer);
    const set = this.setTimer;
    this.timer = set(() => this.flush(), this.delay);
  }

  async flush() {
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
    const batch = this.pending;
    this.pending = {};
    if (!Object.keys(batch).length) return;
    try {
      await this.save(batch);
    } catch (e) {
      this.onError?.(e);
    }
  }

  // Forget what has not been sent (the layout is reset).
  cancel() {
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = null;
    this.pending = {};
  }
}
