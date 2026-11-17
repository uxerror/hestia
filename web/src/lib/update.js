// Pure helpers of the controller update screens. No DOM; fetch is injectable.
import { ApiError } from './api.js';

export const RELEASES_URL = 'https://github.com/uxerror/hestia/releases';

// A build made with uncommitted changes (git describe --dirty).
export const isDirty = (v) => /-dirty$/.test(String(v || ''));

// Parse the query of #/update/offer?from=…&v=…&n=… (path 1: the desktop app
// offers its embedded binary) or ?older=1&v=… (the app is older than the
// controller). The helper must live on the loopback of this very PC.
export function parseOffer(hash) {
  const q = new URLSearchParams(String(hash || '').split('?')[1] || '');
  const v = q.get('v') || '';
  if (q.get('older') === '1') return v ? { kind: 'older', version: v } : { kind: 'invalid' };
  const from = q.get('from') || '';
  const n = q.get('n') || '';
  if (!v || !/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(from) || !/^[0-9a-f]{64}$/.test(n)) return { kind: 'invalid' };
  return { kind: 'offer', version: v, from, nonce: n };
}

// Downloads the app's binary from the loopback helper.
export async function fetchPayload({ from, nonce }, fetchFn = fetch) {
  let metaRes, binRes;
  try {
    metaRes = await fetchFn(`${from}/payload/${nonce}/meta`);
    if (!metaRes.ok) throw new Error('helper');
    const meta = await metaRes.json();
    binRes = await fetchFn(`${from}/payload/${nonce}`);
    if (!binRes.ok) throw new Error('helper');
    return { meta, blob: await binRes.blob() };
  } catch {
    throw new Error('Не удалось получить файл у приложения. Закройте окно и откройте приложение заново.');
  }
}

// Uploads the binary to the controller (raw body); the controller checks it.
export async function uploadPayload(version, blob, fetchFn = fetch) {
  let res;
  try {
    res = await fetchFn('/api/v1/update/upload?version=' + encodeURIComponent(version), {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/octet-stream', Accept: 'application/json' },
      body: blob,
    });
  } catch {
    throw new ApiError(0, 'Нет связи с сервером');
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || `Ошибка сервера (${res.status})`);
  return data;
}

// Waits until health reports the wanted version. Returns 'ok' or 'timeout'.
// fetchHealth rejects while the controller is down.
export async function waitForVersion(fetchHealth, want, { timeoutMs = 90000, intervalMs = 2000, now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  const end = now() + timeoutMs;
  for (;;) {
    try {
      const h = await fetchHealth();
      if (h && h.status === 'ok' && h.version === want) return 'ok';
    } catch {
      // restarting: keep trying
    }
    if (now() >= end) return 'timeout';
    await sleep(intervalMs);
  }
}

// The job is "running" at the restart step: everything after it is the next process's work.
export function inRestart(job) {
  const s = (job?.steps || []).at(-1);
  return !!s && s.title === 'Перезапуск контроллера' && s.status === 'running';
}

export function whereText(where) {
  if (!where) return '';
  if (where.kind === 'lxc') return `контейнер ${where.vmid} на узле ${where.node} (${where.ip})`;
  return `сервер ${where.host || where.ip}`;
}

// What the "Обновление" card offers.
export function cardState(st) {
  if (!st) return { kind: 'loading' };
  if (!st.location_ok) return { kind: 'unavailable', reason: st.reason };
  if (st.running_job) return { kind: 'running', job: st.running_job };
  const g = st.github || {};
  if (!g.configured) return { kind: 'unconfigured' };
  if (g.available) return { kind: 'available', latest: g.latest };
  return { kind: 'current' };
}

// The header badge: only when an update can be started.
export const badgeText = (st) => (st?.location_ok && st.github?.available ? `Доступно обновление ${st.github.latest}` : '');
