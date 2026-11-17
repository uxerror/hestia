// Pure helpers for the "connect a target" wizard: form validation, request
// body, flow reducer and formatting. No DOM and no network here.
export const HOST_RE = /^[A-Za-z0-9._:-]{1,253}$/;
export const USER_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;

export const KINDS = {
  proxmox: { title: 'Готовый Proxmox', apiKind: 'proxmox' },
  server: { title: 'Отдельный сервер', apiKind: 'ssh' },
};

export function emptyForm() {
  return { host: '', port: '22', username: 'root', auth: 'password', password: '', private_key: '', passphrase: '' };
}

// Returns { field: message } — empty object means valid.
export function validateConnectForm(form, kind) {
  const e = {};
  const host = (form.host || '').trim().replace(/^\[|\]$/g, '');
  if (!host) e.host = 'Введите адрес сервера';
  else if (!HOST_RE.test(host)) e.host = 'Адрес: только буквы, цифры, «.», «:», «-», «_»';

  const portStr = String(form.port ?? '').trim();
  if (portStr !== '') {
    const p = Number(portStr);
    if (!/^\d+$/.test(portStr) || p < 1 || p > 65535) e.port = 'Порт: число от 1 до 65535';
  }

  const user = (form.username || '').trim();
  if (user && !USER_RE.test(user)) e.username = 'Недопустимое имя пользователя';
  else if (kind === 'proxmox' && user && user !== 'root') e.username = 'Для Proxmox нужен пользователь root';

  if (form.auth === 'key') {
    const k = (form.private_key || '').trim();
    if (!k) e.private_key = 'Вставьте приватный ключ';
    else if (!k.includes('PRIVATE KEY')) e.private_key = 'Это не похоже на приватный ключ (-----BEGIN … PRIVATE KEY-----)';
  } else if (!form.password) {
    e.password = 'Введите пароль';
  }
  return e;
}

export function buildProbeBody(form, kind) {
  const body = {
    kind: KINDS[kind].apiKind,
    host: (form.host || '').trim().replace(/^\[|\]$/g, ''),
    port: Number(String(form.port ?? '').trim() || 22),
    username: (form.username || '').trim() || 'root',
    auth: form.auth,
  };
  if (form.auth === 'key') {
    body.private_key = form.private_key;
    if (form.passphrase) body.passphrase = form.passphrase;
  } else {
    body.password = form.password;
  }
  return body;
}

export const initialFlow = { phase: 'form', probe: null, job: null, error: '' };

// phase: form | probing | review | starting | running | done | failed
export function flowReducer(state, action) {
  switch (action.type) {
    case 'probing':
      return { ...initialFlow, phase: 'probing' };
    case 'probed':
      return { ...initialFlow, phase: 'review', probe: action.probe };
    case 'probe_failed':
      return { ...initialFlow, phase: 'form', error: action.error };
    case 'edit': // back to the form, drop the probe (credentials expire on the server)
      return { ...initialFlow };
    case 'starting':
      return { ...state, phase: 'starting', error: '' };
    case 'started':
      return { ...state, phase: 'running', job: action.job, error: '' };
    case 'start_failed':
      // 410: the probe session expired, 409: fingerprints no longer match → check again.
      if (action.status === 410 || action.status === 409) return { ...initialFlow, error: action.error };
      return { ...state, phase: 'review', error: action.error };
    case 'job': {
      const job = action.job;
      if (job.status === 'done') return { ...state, phase: 'done', job, error: '' };
      if (job.status === 'failed' || job.status === 'cancelled') return { ...state, phase: 'failed', job, error: job.error || 'Задача не выполнена' };
      return { ...state, phase: 'running', job };
    }
    case 'retry': // after a failed (rolled back) job: same probe, same fingerprints
      return state.probe ? { ...state, phase: 'review', job: null, error: '' } : { ...initialFlow };
    default:
      return state;
  }
}

export function fmtBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '—';
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ', 'ПБ'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return (v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)).toString().replace('.', ',') + ' ' + u[i];
}

// Short summary line of a target for lists.
export function targetSummary(t) {
  if (t.kind === 'proxmox') {
    const n = t.nodes?.length || 0;
    return (t.cluster ? `кластер «${t.cluster}», ` : '') + `узлов: ${n}`;
  }
  return 'SSH-сервер';
}
