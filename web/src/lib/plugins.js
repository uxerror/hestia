// Pure helpers for the plugins screens: labels for permissions, states and
// trust, fingerprint display, safe links, plan view, error mapping, upload.
import { ApiError } from './api.js';
import { serverErrors } from './schemaform.js';

// Permissions in human language (closed list of protocol v1).
export const PERMISSIONS = {
  'targets.read': 'Видеть выбранные серверы (имя, адрес, ОС)',
  'targets.exec': 'Выполнять команды от root на выбранных серверах',
  'deploy.docker': 'Разворачивать Docker-контейнеры',
  'net.outbound': 'Сетевые подключения напрямую',
  'inventory.read': 'Читать карту сети',
};

export function permissionLabel(p) {
  return PERMISSIONS[p] || String(p ?? '');
}

// Permissions of a preview as a list; for an update the new ones are marked.
export function permissionList(preview) {
  const fresh = new Set(preview?.update?.new_permissions || []);
  return (preview?.permissions || []).map((p) => ({ id: p, label: permissionLabel(p), isNew: fresh.has(p) }));
}

// Connection state of an installed plugin.
export const PLUGIN_STATE = {
  connected: { label: 'Работает', cls: 'badge-success' },
  unresponsive: { label: 'Не отвечает', cls: 'badge-warning' },
  disabled: { label: 'Отключён', cls: 'badge-ghost' },
  disconnected: { label: 'Не подключён', cls: 'badge-error' },
};

export function stateInfo(state) {
  return PLUGIN_STATE[state] || { label: state || '—', cls: 'badge-ghost' };
}

// Status of an instance as reported by the plugin.
export const INSTANCE_STATUS = {
  ok: { label: 'Работает', cls: 'badge-success' },
  degraded: { label: 'Работает с проблемами', cls: 'badge-warning' },
  down: { label: 'Не работает', cls: 'badge-error' },
  unknown: { label: 'Неизвестно', cls: 'badge-ghost' },
};

export function instanceStatusInfo(status) {
  return INSTANCE_STATUS[status] || { label: status || 'Неизвестно', cls: 'badge-ghost' };
}

// State of the systemd unit of a plugin (GET /plugins/{id}?unit=1).
export function unitInfo(unit) {
  if (!unit) return null;
  const a = unit.active || '';
  if (a === 'active') return { label: 'Служба запущена', cls: 'badge-success', error: unit.error || '' };
  if (a === 'failed') return { label: 'Служба упала', cls: 'badge-error', error: unit.error || '' };
  if (a === 'activating' || a === 'reloading') return { label: 'Служба запускается', cls: 'badge-info', error: unit.error || '' };
  return { label: a ? `Служба: ${a}` : 'Служба не запущена', cls: 'badge-ghost', error: unit.error || '' };
}

// Author trust in the install preview.
export const TRUST = {
  official: { label: 'Официальный', cls: 'badge-success' },
  pinned: { label: 'Сторонний, автор уже знаком', cls: 'badge-info' },
  new: { label: 'Сторонний, новый автор', cls: 'badge-warning' },
};

export function trustInfo(trust) {
  return TRUST[trust] || { label: trust || '—', cls: 'badge-ghost' };
}

// Author badge of an installed plugin.
export function authorBadge(author) {
  return author?.official ? { label: 'Официальный', cls: 'badge-success' } : { label: 'Сторонний', cls: 'badge-ghost' };
}

// "AB12CD34…" / "ab:12:cd:34" / "ab12 cd34" → "ab12 cd34 …" (groups of 4 hex digits).
export function fingerprintDisplay(fp) {
  const hex = String(fp ?? '')
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
  if (!hex) return '';
  return hex.match(/.{1,4}/g).join(' ');
}

// First groups of the fingerprint for the card (the full one goes into a tooltip).
export function shortFingerprint(fp, groups = 4) {
  const full = fingerprintDisplay(fp);
  const parts = full.split(' ').filter(Boolean);
  return parts.length > groups ? parts.slice(0, groups).join(' ') + ' …' : full;
}

// Only http/https URLs become links; anything else (javascript:, data:, …) → ''.
export function safeUrl(u) {
  if (typeof u !== 'string' || !u.trim()) return '';
  let url;
  try {
    url = new URL(u.trim());
  } catch {
    return '';
  }
  return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '';
}

// provides/requires item → "http.service" or "http.service (name)".
export function capabilityText(c) {
  if (!c) return '';
  return c.name ? `${c.type} (${c.name})` : String(c.type || '');
}

export function sourceLabel(source) {
  const s = String(source || '');
  if (s === 'catalog') return 'Из каталога';
  if (s === 'file') return 'Из файла';
  if (s === 'dev') return 'Режим разработки';
  if (s.startsWith('url:')) return 'По ссылке ' + s.slice(4);
  return s;
}

// The job id of a 202 answer ({job: Job}; older endpoints answer {job_id}).
export function jobIdOf(r) {
  return r?.job?.id ?? r?.job_id ?? '';
}

// Default name of a new instance: "<plugin name> N" that is not taken yet.
export function suggestedInstanceName(pluginName, instances = []) {
  const taken = new Set((instances || []).map((i) => i.name));
  for (let n = (instances || []).length + 1; ; n++) {
    const name = `${pluginName || 'Экземпляр'} ${n}`;
    if (!taken.has(name)) return name;
  }
}

// Risk of a plan action → its look.
export const RISK = {
  info: { label: 'Информация', cls: '', alert: '' },
  change: { label: 'Изменение', cls: 'badge-warning', alert: 'alert-warning' },
  danger: { label: 'Опасно', cls: 'badge-error', alert: 'alert-error' },
};

export function riskInfo(risk) {
  return RISK[risk] || RISK.info;
}

// What the plan screen allows: danger needs a separate confirmation.
export function planView(plan, riskConfirmed = false) {
  if (!plan) return { danger: false, canApply: false };
  const danger = !!plan.danger || (plan.plan?.actions || []).some((a) => a.risk === 'danger');
  return { danger, canApply: !danger || !!riskConfirmed };
}

// Install is allowed for an official/pinned author, or a new one the user trusts.
export function canInstall(preview, trusted) {
  if (!preview) return false;
  return preview.author?.trust !== 'new' || !!trusted;
}

export const STALE_PLAN = 'Состояние изменилось, проверьте план ещё раз';
export const EXPIRED_PLAN = 'План устарел, постройте его ещё раз';

// Error of plan/apply → what the dialog does:
//  fields  — 422 with field errors (back to the form);
//  stale   — 409 the state changed (re-plan);
//  expired — 410 the plan is too old (re-plan);
//  other   — just show the message.
export function planError(e) {
  const status = e?.status;
  if (status === 422 && Array.isArray(e?.data?.fields)) {
    return { kind: 'fields', message: e.message || 'Проверьте поля формы', fields: serverErrors(e.data) };
  }
  if (status === 409) return { kind: 'stale', message: e?.message || STALE_PLAN };
  if (status === 410) return { kind: 'expired', message: EXPIRED_PLAN };
  return { kind: 'other', message: e?.message || 'Не удалось' };
}

// 409 of DELETE /plugins/{id}: instances must go first.
export function removeBlocked(e) {
  if (e?.status !== 409) return null;
  return { message: e.message || 'Сначала удалите экземпляры', instances: Array.isArray(e.data?.instances) ? e.data.instances : [] };
}

// Uploads a package file (multipart, field "file") → {upload_id, preview}.
export async function uploadPackage(file, fetchFn = fetch) {
  const form = new FormData();
  form.append('file', file, file?.name || 'plugin.hpkg');
  let res;
  try {
    res = await fetchFn('/api/v1/plugins/packages', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json' }, body: form });
  } catch {
    throw new ApiError(0, 'Нет связи с сервером');
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || `Ошибка сервера (${res.status})`, data);
  return data;
}

// What a catalog entry offers: install, update, nothing (installed) or why
// it cannot be installed. item — CatalogItem of GET /plugins/catalog.
export function catalogAction(item) {
  if (!item) return { kind: 'none', label: '' };
  if (!item.compatible) return { kind: 'incompatible', label: item.reason || 'Нужна более новая Hestia' };
  if (item.update) return { kind: 'update', label: `Обновить до ${item.version}` };
  if (item.installed) return { kind: 'installed', label: `Установлен ${item.installed}` };
  return { kind: 'install', label: 'Установить' };
}

// Header line of the catalog: when it was fetched and the last error.
export function catalogStatus(view, now = Date.now()) {
  if (!view) return { text: '', error: '' };
  const error = view.error || '';
  if (!view.fetched_at) return { text: 'Каталог ещё не загружен', error };
  const t = new Date(view.fetched_at);
  if (Number.isNaN(t.getTime())) return { text: '', error };
  const mins = Math.max(0, Math.round((now - t.getTime()) / 60000));
  let ago;
  if (mins < 1) ago = 'только что';
  else if (mins < 60) ago = `${mins} мин назад`;
  else if (mins < 48 * 60) ago = `${Math.round(mins / 60)} ч назад`;
  else ago = `${Math.round(mins / 1440)} дн назад`;
  return { text: `Проверен ${ago}`, error };
}
