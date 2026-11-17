// Fetch wrapper: relative /api/v1 URLs, cookie session, JSON errors {error}.
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
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
    throw new ApiError(res.status, msg);
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
  selfinstall: () => request('GET', '/selfinstall'),
  probeInstall: (body) => request('POST', '/selfinstall/probe', body),
  startInstall: (probeId) => request('POST', '/selfinstall', { probe_id: probeId }),
  // 401 = unknown/used/expired token, not an expired session.
  handoff: (token) => request('POST', '/auth/handoff', { token }, { skip401: true }),
  deleteTarget: (id, revert) => request('DELETE', '/targets/' + encodeURIComponent(id) + '?revert=' + (revert ? 'true' : 'false')),
};
