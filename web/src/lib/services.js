// Pure helpers for the "Сервисы" table: flat rows from the hosts, filter and grouping.
import { CATEGORY_LABEL, CATEGORY_ORDER, compareIP, hostName } from './netmap.js';

// One row per service of every host.
export function serviceRows(hosts) {
  const rows = [];
  for (const h of hosts || []) {
    const dns = [];
    for (const n of h.names || []) {
      if ((n.source === 'ptr' || n.source === 'cert') && !dns.includes(n.name)) dns.push(n.name);
    }
    for (const s of h.services || []) {
      rows.push({
        key: `${h.ip}:${s.port}`,
        ip: h.ip,
        host: hostName(h),
        alive: !!h.alive,
        dns,
        port: s.port,
        name: s.name,
        rule: s.rule,
        category: s.category || 'other',
        detail: [s.version, s.os, s.detail].filter(Boolean).join(' · '),
        url: s.url || '',
      });
    }
  }
  return rows;
}

// Unrecognised ports are noise by default.
const UNKNOWN_RULES = new Set(['port', 'banner']);

export function filterServices(rows, { category = '', query = '', unknown = false, dead = true } = {}) {
  const q = query.trim().toLowerCase();
  return rows.filter((r) => {
    if (category && r.category !== category) return false;
    if (!unknown && UNKNOWN_RULES.has(r.rule)) return false;
    if (!dead && !r.alive) return false;
    if (!q) return true;
    return [r.name, r.host, r.ip, String(r.port), r.detail, r.category, CATEGORY_LABEL[r.category], ...r.dns].join('\n').toLowerCase().includes(q);
  });
}

// Groups by category in a fixed order; inside a group by service name, then address.
export function groupByCategory(rows) {
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.category)) by.set(r.category, []);
    by.get(r.category).push(r);
  }
  const order = [...CATEGORY_ORDER, ...[...by.keys()].filter((c) => !CATEGORY_ORDER.includes(c))];
  return order
    .filter((c) => by.has(c))
    .map((c) => ({
      category: c,
      label: CATEGORY_LABEL[c] || c,
      rows: by.get(c).sort((a, b) => a.name.localeCompare(b.name, 'ru') || compareIP(a.ip, b.ip) || a.port - b.port),
    }));
}

// Categories that occur in the rows (for the filter), in the fixed order.
export function categoriesOf(rows) {
  const have = new Set(rows.map((r) => r.category));
  return CATEGORY_ORDER.filter((c) => have.has(c)).map((c) => ({ value: c, label: CATEGORY_LABEL[c] }));
}
