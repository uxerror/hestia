// Number formatting for the inventory: binary units (ГиБ/ТиБ), integer percents.
const UNITS = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ', 'ПиБ'];

const isNum = (n) => typeof n === 'number' && Number.isFinite(n);

// 1536 → "1,5 КиБ"; 12 ГиБ → "12 ГиБ" (one decimal below 10, none above).
export function fmtBytes(n) {
  if (!isNum(n) || n < 0) return '—';
  let v = n;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  if (i === 0) return `${Math.round(v)} ${UNITS[0]}`;
  const s = v < 10 ? v.toFixed(1) : String(Math.round(v));
  return `${s.replace('.', ',').replace(/,0$/, '')} ${UNITS[i]}`;
}

// A 0..1 fraction as an integer percent: 0.426 → "43%".
export function fmtPercent(fraction) {
  if (!isNum(fraction)) return '—';
  return `${Math.round(fraction * 100)}%`;
}

// used/total as an integer 0..100, or null when the total is unknown.
export function pct(used, total) {
  if (!isNum(used) || !isNum(total) || total <= 0) return null;
  return Math.min(100, Math.max(0, Math.round((used / total) * 100)));
}

// "36 д 1 ч", "5 ч 3 мин", "2 мин", "40 с".
export function fmtUptime(sec) {
  if (!isNum(sec) || sec <= 0) return '—';
  const s = Math.floor(sec);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d} д ${h} ч`;
  if (h > 0) return `${h} ч ${m} мин`;
  if (m > 0) return `${m} мин`;
  return `${s} с`;
}

// "обновлено …" age: 20 → "20 с назад", 150 → "2 мин назад", 7300 → "2 ч назад".
export function fmtAge(sec) {
  if (!isNum(sec)) return 'не собиралось';
  const s = Math.max(0, Math.floor(sec));
  if (s < 60) return `${s} с назад`;
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
  return `${Math.floor(s / 86400)} д назад`;
}

// Seconds since an ISO timestamp (null if there is none).
export function ageSince(iso, now = Date.now()) {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : Math.max(0, Math.floor((now - t) / 1000));
}

export function fmtLoad(n) {
  return isNum(n) ? n.toFixed(2).replace('.', ',') : '—';
}
