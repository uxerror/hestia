// Fetch wrapper: relative /api/v1 URLs, cookie session, JSON errors {error}.
export class ApiError extends Error {
  constructor(status, message, data = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data; // the whole JSON body of the error (code, fingerprint, ...)
  }
}

let unauthorizedHandler = null;
export function onUnauthorized(fn) {
  unauthorizedHandler = fn;
}

let transferHandler = null;
export function onTransfer(fn) {
  transferHandler = fn;
}

// The server refuses writes while it copies its state to a server (503).
export function isTransferError(status, message) {
  return status === 503 && /идёт перенос/.test(message || '');
}

export async function request(method, path, body, { skip401 = false } = {}) {
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch('/api/v1' + path, init);
  } catch {
    throw new ApiError(0, 'Нет связи с сервером');
  }
  let data = null;
  if (res.status !== 204) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const msg = (data && data.error) || `Ошибка сервера (${res.status})`;
    if (res.status === 401 && !skip401 && unauthorizedHandler) unauthorizedHandler();
    if (isTransferError(res.status, msg) && transferHandler) transferHandler();
    throw new ApiError(res.status, msg, data);
  }
  return data;
}

export const api = {
  health: () => request('GET', '/health'),
  remote: () => request('GET', '/remote'),
  setup: () => request('GET', '/setup'),
  setupAdmin: (username, password) => request('POST', '/setup/admin', { username, password }),
  // 401 on login means wrong credentials, not an expired session.
  login: (username, password) => request('POST', '/auth/login', { username, password }, { skip401: true }),
  logout: () => request('POST', '/auth/logout'),
  me: () => request('GET', '/auth/me', undefined, { skip401: true }),
  jobs: () => request('GET', '/jobs'),
  job: (id) => request('GET', '/jobs/' + encodeURIComponent(id)),
  demoJob: () => request('POST', '/jobs/demo'),
  identity: () => request('GET', '/identity'),
  probeTarget: (body) => request('POST', '/targets/probe', body),
  createTarget: (body) => request('POST', '/targets', body),
  targets: () => request('GET', '/targets'),
  target: (id) => request('GET', '/targets/' + encodeURIComponent(id)),
  inventory: () => request('GET', '/inventory'),
  inventoryOf: (id) => request('GET', '/inventory/' + encodeURIComponent(id)),
  refreshInventory: (id) => request('POST', '/inventory/' + encodeURIComponent(id) + '/refresh'),
  rolePlan: (id) => request('GET', '/inventory/' + encodeURIComponent(id) + '/role-fix'),
  fixRole: (id) => request('POST', '/inventory/' + encodeURIComponent(id) + '/role-fix', { confirm: true }),
  network: () => request('GET', '/network'),
  scanNetwork: () => request('POST', '/network/scan'),
  cancelScan: () => request('DELETE', '/network/scan'),
  networkSettings: (body) => request('PUT', '/network/settings', body),
  forgetHost: (ip) => request('DELETE', '/network/hosts/' + encodeURIComponent(ip)),
  update: () => request('GET', '/update'),
  checkUpdate: () => request('POST', '/update/check'),
  startUpdate: (body) => request('POST', '/update', body),
  selfinstall: () => request('GET', '/selfinstall'),
  probeInstall: (body) => request('POST', '/selfinstall/probe', body),
  startInstall: (probeId) => request('POST', '/selfinstall', { probe_id: probeId }),
  // 401 = unknown/used/expired token, not an expired session.
  handoff: (token) => request('POST', '/auth/handoff', { token }, { skip401: true }),
  dns: () => request('GET', '/dns'),
  dnsCheck: () => request('POST', '/dns/check'),
  probeAdguard: (url) => request('POST', '/dns/adguard/probe', { url }),
  connectAdguard: (body) => request('POST', '/dns/adguard', body),
  updateAdguard: (body) => request('PUT', '/dns/adguard', body),
  disconnectAdguard: () => request('DELETE', '/dns/adguard'),
  dnsPlan: (action, domain) => request('POST', '/dns/plan', { action, domain }),
  dnsApply: (planId, hash) => request('POST', '/dns/apply', { plan_id: planId, hash }),
  plugins: () => request('GET', '/plugins'),
  plugin: (id, unit = false) => request('GET', '/plugins/' + encodeURIComponent(id) + (unit ? '?unit=1' : '')),
  enablePlugin: (id) => request('POST', '/plugins/' + encodeURIComponent(id) + '/enable'),
  disablePlugin: (id) => request('POST', '/plugins/' + encodeURIComponent(id) + '/disable'),
  removePlugin: (id) => request('DELETE', '/plugins/' + encodeURIComponent(id)),
  fetchPluginPackage: (url) => request('POST', '/plugins/packages/fetch', { url }),
  installPlugin: (uploadId, trustAuthor) => request('POST', '/plugins/install', { upload_id: uploadId, trust_author: !!trustAuthor }),
  pluginInstances: (id) => request('GET', '/plugins/' + encodeURIComponent(id) + '/instances'),
  pluginInstance: (iid, refresh = false) => request('GET', '/plugins/instances/' + encodeURIComponent(iid) + (refresh ? '?status=refresh' : '')),
  planCreateInstance: (id, name, config) => request('POST', '/plugins/' + encodeURIComponent(id) + '/instances/plan', { name, config }),
  planUpdateInstance: (iid, config) => request('POST', '/plugins/instances/' + encodeURIComponent(iid) + '/plan', { action: 'update', config }),
  planRemoveInstance: (iid) => request('POST', '/plugins/instances/' + encodeURIComponent(iid) + '/plan', { action: 'remove' }),
  applyPluginPlan: (planId, hash, confirmDanger) => request('POST', '/plugins/plans/' + encodeURIComponent(planId) + '/apply', { hash, confirm_danger: !!confirmDanger }),
  pluginTargets: () => request('GET', '/plugins/targets'),
  deleteTarget: (id, revert) => request('DELETE', '/targets/' + encodeURIComponent(id) + '?revert=' + (revert ? 'true' : 'false')),
};
