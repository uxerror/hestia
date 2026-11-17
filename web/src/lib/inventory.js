// Pure helpers for the "Системы" screen: guests filter/sort, counters and the
// reducer for inventory events. No DOM, no network.

export const GUEST_TYPE = {
  qemu: { label: 'VM', cls: 'badge-primary' },
  lxc: { label: 'LXC', cls: 'badge-secondary' },
};

export const GUEST_STATUS = {
  running: { label: 'запущен', cls: 'badge-success' },
  stopped: { label: 'остановлен', cls: 'badge-ghost' },
  paused: { label: 'пауза', cls: 'badge-warning' },
  suspended: { label: 'приостановлен', cls: 'badge-warning' },
};

export function statusInfo(status) {
  return GUEST_STATUS[status] || { label: status || '—', cls: 'badge-ghost' };
}

export function emptyFilter() {
  return { node: '', type: '', status: '', query: '' };
}

// Filters by node, type (qemu|lxc), status and a free-text query matched
// against the name, VMID, IPs and tags (case-insensitive substring).
export function filterGuests(guests, f = emptyFilter()) {
  const q = (f.query || '').trim().toLowerCase();
  return guests.filter((g) => {
    if (f.node && g.node !== f.node) return false;
    if (f.type && g.type !== f.type) return false;
    if (f.status && g.status !== f.status) return false;
    if (!q) return true;
    return (
      String(g.name || '').toLowerCase().includes(q) ||
      String(g.vmid).includes(q) ||
      (g.ips || []).some((ip) => ip.toLowerCase().includes(q)) ||
      (g.tags || []).some((t) => t.toLowerCase().includes(q))
    );
  });
}

// IPv4 as a sortable number; anything else sorts after all IPv4 addresses.
function ipKey(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
  if (!m) return ip ? Number.MAX_SAFE_INTEGER : Infinity;
  return ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4];
}

const diskShare = (g) => (g.disk_total > 0 ? g.disk_used / g.disk_total : 0);

export const SORT_KEYS = {
  vmid: (g) => g.vmid,
  name: (g) => (g.name || '').toLowerCase(),
  type: (g) => g.type,
  status: (g) => g.status,
  node: (g) => g.node,
  cpu: (g) => g.cpu_usage || 0,
  mem: (g) => g.mem_used || 0,
  disk: (g) => (g.disk_used > 0 ? diskShare(g) : 0) || g.disk_total || 0,
  ip: (g) => ipKey((g.ips || [])[0]),
  tags: (g) => (g.tags || []).join(',').toLowerCase(),
  template: (g) => (g.template ? 1 : 0),
};

// Returns a sorted copy. Ties keep VMID order so the result is stable.
export function sortGuests(guests, key = 'vmid', dir = 'asc') {
  const get = SORT_KEYS[key] || SORT_KEYS.vmid;
  const sign = dir === 'desc' ? -1 : 1;
  return [...guests].sort((a, b) => {
    const x = get(a);
    const y = get(b);
    if (x < y) return -sign;
    if (x > y) return sign;
    return a.vmid - b.vmid;
  });
}

// Clicking a column header: same key flips the direction, a new key starts ascending.
export function nextSort(cur, key) {
  if (cur.key === key) return { key, dir: cur.dir === 'asc' ? 'desc' : 'asc' };
  return { key, dir: 'asc' };
}

// Templates are not counted: they never run.
export function guestCounts(guests, node) {
  let running = 0;
  let total = 0;
  for (const g of guests || []) {
    if (g.template || (node && g.node !== node)) continue;
    total++;
    if (g.status === 'running') running++;
  }
  return { running, total };
}

export function guestIPs(g) {
  return g.ips && g.ips.length ? g.ips.join(', ') : '';
}

// Replaces (or adds) an entry by target_id and returns a new array.
export function applyEntry(entries, entry) {
  const i = entries.findIndex((e) => e.target_id === entry.target_id);
  if (i < 0) return [...entries, entry];
  const next = [...entries];
  next[i] = entry;
  return next;
}

export function entryOf(entries, id) {
  return entries.find((e) => e.target_id === id) || null;
}

export function storageTitle(s) {
  return s.shared ? `${s.name} (общее)` : s.name;
}

export const roleBanner = (snap) => !!(snap && snap.needs_guest_agent_audit);
