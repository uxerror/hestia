// Pure helpers of the "install Hestia on a server" screen: the probe request,
// the editable fields, the flow reducer and the summary. No DOM, no network.

// Proxmox targets first: a container is the default way to run Hestia.
export function defaultTargetId(targets) {
  const list = targets || [];
  const t = list.find((x) => x.kind === 'proxmox') || list[0];
  return t ? t.id : 0;
}

const NUMERIC = ['vmid', 'cores', 'memory_mb', 'disk_gb', 'port'];
const TEXT = ['node', 'hostname', 'storage', 'template_storage', 'bridge', 'gateway'];

// Body of POST /selfinstall/probe: only what the user edited ("dirty"); every
// other value is chosen by the server.
export function buildProbeRequest(targetId, dirty = {}) {
  const body = { target_id: targetId };
  for (const k of TEXT) {
    const v = String(dirty[k] ?? '').trim();
    if (v) body[k] = v;
  }
  for (const k of NUMERIC) {
    const v = String(dirty[k] ?? '').trim();
    if (v !== '' && /^\d+$/.test(v)) body[k] = Number(v);
  }
  const ip = String(dirty.ip ?? '').trim();
  if (ip) body.ip = ip;
  return body;
}

// Fields shown under "Подробнее". `dependsOnNode` fields are forgotten when the node changes.
export const LXC_FIELDS = ['node', 'vmid', 'hostname', 'storage', 'template_storage', 'bridge', 'ip', 'gateway', 'cores', 'memory_mb', 'disk_gb'];
export const SERVER_FIELDS = ['port'];
const DEPENDS_ON_NODE = ['storage', 'template_storage', 'bridge'];

export const initialInstall = { phase: 'pick', probe: null, dirty: {}, details: false, job: null, result: null, error: '' };

// phase: pick | probing | review | starting | running | done | failed
export function installReducer(state, action) {
  switch (action.type) {
    case 'probing': // a fresh check from the target picker
      return { ...initialInstall, phase: 'probing' };
    case 'reprobing': // the edited fields are applied: keep what the user typed
      return { ...state, phase: 'probing', error: '' };
    case 'probed':
      return { ...state, phase: 'review', probe: action.probe, error: '' };
    case 'probe_failed':
      // a re-check keeps the form so the value can be corrected; the first one goes back to the picker
      return state.probe ? { ...state, phase: 'review', error: action.error } : { ...initialInstall, error: action.error };
    case 'edit_field': {
      const dirty = { ...state.dirty, [action.field]: action.value };
      if (action.field === 'node') for (const k of DEPENDS_ON_NODE) delete dirty[k];
      return { ...state, dirty };
    }
    case 'toggle_details':
      return { ...state, details: !state.details };
    case 'back':
      return { ...initialInstall };
    case 'starting':
      return { ...state, phase: 'starting', error: '' };
    case 'started':
      return { ...state, phase: 'running', job: action.job, error: '' };
    case 'start_failed':
      // 410: the check expired, 409: already installed / already running, 404: target is gone.
      if (action.status === 410 || action.status === 404) return { ...initialInstall, error: action.error };
      return { ...state, phase: 'review', error: action.error };
    case 'job': {
      const job = action.job;
      if (job.status === 'done') return { ...state, phase: 'done', job, result: job.result || null, error: '' };
      if (job.status === 'failed' || job.status === 'cancelled') return { ...state, phase: 'failed', job, error: job.error || 'Установка не выполнена' };
      return { ...state, phase: 'running', job };
    }
    case 'retry': // rolled back: the same check can be confirmed again until it expires
      return state.probe ? { ...state, phase: 'review', job: null, error: '' } : { ...initialInstall };
    default:
      return state;
  }
}

// Value of a field: what the user typed, otherwise what the server chose.
export function fieldValue(probe, dirty, field) {
  if (dirty && dirty[field] !== undefined) return dirty[field];
  const v = probe?.params?.[field];
  return v === undefined || v === null ? '' : v;
}

export const hasStaticIP = (probe, dirty) => {
  const ip = fieldValue(probe, dirty, 'ip');
  return !!ip && ip !== 'dhcp';
};

// Lines of the short summary above the plan.
export function summarize(probe) {
  if (!probe) return [];
  const p = probe.params || {};
  if (probe.kind === 'ssh') return [['Порт', String(p.port || 80)]];
  const ip = p.ip === 'dhcp' || !p.ip ? 'DHCP' : p.ip + (p.gateway ? `, шлюз ${p.gateway}` : '');
  return [
    ['Узел', p.node],
    ['VMID', String(p.vmid)],
    ['Имя', p.hostname],
    ['Адрес', ip],
    ['Ресурсы', `${p.cores} vCPU, ${p.memory_mb} МБ RAM, ${p.swap_mb} МБ swap, диск ${p.disk_gb} ГБ (${p.storage})`],
    ['Сеть', `мост ${p.bridge}`],
    ['Шаблон', p.template_present ? `${p.template} (уже скачан)` : `${p.template} (будет скачан)`],
  ];
}

// The handoff link is "<url>/#/handoff/<token>"; it is shown only as a button.
export function resultSummary(result) {
  if (!result) return [];
  const rows = [['Адрес Hestia', result.url]];
  if (result.mac) rows.push(['MAC', result.mac]);
  if (result.vmid) rows.push(['Контейнер', `${result.vmid} на узле ${result.node}`]);
  return rows;
}

// Moves the window to the new controller (token in the hash, one use).
export function handoffHref(result) {
  return result?.handoff_url || result?.url || '';
}

// Result of GET /remote on the "moved" screen.
export function movedView(remote) {
  if (!remote) return { state: 'checking', text: 'Проверяем…' };
  if (remote.reachable) return { state: 'ok', text: 'Сервер отвечает.' };
  return { state: 'down', text: 'Сервер не отвечает. Проверьте, что он включён и доступен из сети.' };
}
