// Pure helpers for "Имя в сети": domain validation (mirrors the server), status
// texts, the state of the block in the controller card, plan summary.

// Letters, digits and hyphens in labels; at most 253 characters; no wildcard.
export function validateDomain(v) {
  const d = String(v ?? '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '');
  if (!d) return 'Введите имя';
  if (d.length > 253) return 'Имя длиннее 253 символов';
  if (d.includes('*')) return 'Имя не может содержать *';
  for (const l of d.split('.')) {
    if (!l) return 'Пустая часть имени между точками';
    if (l.length > 63) return 'Часть имени длиннее 63 символов';
    if (l.startsWith('-') || l.endsWith('-')) return 'Часть имени не может начинаться или заканчиваться дефисом';
    if (!/^[a-z0-9-]+$/.test(l)) return 'В имени допустимы только латинские буквы, цифры, дефис и точки';
  }
  return '';
}

export function normalizeDomain(v) {
  return String(v ?? '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, '');
}

// Status of the name → label, badge class, hint and the button that fixes it
// (action is the plan action; null: nothing to press).
export const NAME_STATUS = {
  ok: { label: 'Работает', cls: 'badge-success', hint: '', action: null },
  ip_changed: {
    label: 'Адрес изменился',
    cls: 'badge-warning',
    hint: 'Запись в AdGuard указывает на старый адрес Hestia.',
    action: { plan: 'update_ip', label: 'Обновить запись' },
  },
  missing: {
    label: 'Запись удалена',
    cls: 'badge-warning',
    hint: 'Записи нет в AdGuard.',
    action: { plan: 'update_ip', label: 'Восстановить' },
  },
  changed: {
    label: 'Запись изменена',
    cls: 'badge-error',
    hint: 'Запись указывает не на Hestia.',
    action: { plan: 'update_ip', label: 'Исправить запись' },
  },
  auth_failed: {
    label: 'Нет входа в AdGuard',
    cls: 'badge-error',
    hint: 'AdGuard не принимает сохранённые логин и пароль.',
    action: { plan: null, label: 'Изменить подключение' },
  },
  cert_changed: {
    label: 'Сертификат изменился',
    cls: 'badge-error',
    hint: 'Сертификат AdGuard не совпадает с закреплённым.',
    action: { plan: null, label: 'Изменить подключение' },
  },
  unreachable: { label: 'AdGuard недоступен', cls: 'badge-warning', hint: 'AdGuard не отвечает.', action: null },
};

export function statusInfo(status) {
  return NAME_STATUS[status] || { label: status || '—', cls: 'badge-ghost', hint: '', action: null };
}

// State of the block "Имя в сети" from GET /dns:
// hidden (nothing found) | found (AdGuard seen, not connected) | connected (no name yet) | named.
export function blockState(dns) {
  if (!dns) return { state: 'loading' };
  if (dns.name) return { state: 'named' };
  if (dns.integration) return { state: 'connected' };
  if (dns.candidates?.length) return { state: 'found', host: dns.candidates[0].host };
  return { state: 'hidden' };
}

// Default domain offered in the wizard.
export function suggestedDomain(dns) {
  return dns?.default_domain || 'hestia.home';
}

export function endpointLabel(e) {
  if (!e) return '';
  return e.scheme === 'https' ? `HTTPS, порт ${e.port}` : `HTTP, порт ${e.port}`;
}

// Radio list of the endpoints of a candidate; HTTPS comes first (the server sorts it so).
export function endpointChoices(candidate) {
  return (candidate?.endpoints || []).map((e) => ({ ...e, label: endpointLabel(e) }));
}

// The AdGuard row of "Сервисы": a mark when this very host is the connected AdGuard.
export function adguardMark(row, dns) {
  if (!row || row.rule !== 'adguard' || !dns?.integration) return null;
  let host = '';
  try {
    host = new URL(dns.integration.base_url).hostname;
  } catch {
    return null;
  }
  if (host !== row.ip) return null;
  const name = dns.name;
  return {
    text: name ? `подключён · ${name.domain}` : 'подключён',
    status: name ? statusInfo(name.status) : null,
  };
}

// What the plan lets the user do.
export function planView(plan) {
  if (!plan) return { canApply: false, needsReplace: false };
  const conflicts = plan.conflicts?.length > 0;
  return {
    canApply: !conflicts && plan.actions?.length > 0,
    needsReplace: conflicts && plan.action === 'add',
    noop: !!plan.noop,
  };
}

// The error of a failed wizard request → what the form does about it.
export function connectProblem(e) {
  const code = e?.data?.code;
  if (code === 'cert_changed') return { kind: 'cert', fingerprint: e.data.fingerprint, message: e.message };
  if (code === 'auth_failed') return { kind: 'auth', message: e.message };
  return { kind: 'other', message: e?.message || 'Не удалось подключиться' };
}

// Address shown for a client that opens the controller by name.
export function addressLine(remote) {
  if (!remote?.configured_url) return '';
  const main = remote.configured_url;
  return remote.fallback_url ? `Адрес: ${main} (запасной: ${remote.fallback_url})` : `Адрес: ${main}`;
}
