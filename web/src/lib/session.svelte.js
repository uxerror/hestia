import { api, onUnauthorized, onTransfer } from './api.js';
import { createTransferWatch } from './transfer.js';

// phase: loading | setup | login | app | moved
// transferring: the server is copying its state to a server (writes are refused).
// remote: where Hestia lives after it moved (phase "moved").
export const session = $state({ phase: 'loading', user: null, mode: '', error: '', transferring: false, remote: null });

const watch = createTransferWatch(
  () => api.health(),
  (on) => (session.transferring = on),
);
onTransfer(() => watch.start());
export const startTransferWatch = () => watch.start();

async function route401() {
  session.user = null;
  try {
    const s = await api.setup();
    session.mode = s.mode || '';
    session.phase = s.needs_admin ? 'setup' : 'login';
  } catch {
    session.phase = 'login';
  }
}

onUnauthorized(() => {
  if (session.phase === 'app') route401();
});

export async function boot() {
  session.error = '';
  // The health endpoint needs no login: it tells whether this controller moved.
  try {
    const h = await api.health();
    if (h.status === 'moved') {
      session.remote = { url: h.remote, instance_id: h.instance_id };
      session.phase = 'moved';
      return;
    }
    if (h.transferring) watch.start();
  } catch {
    // unreachable or an old server: the usual checks below report it
  }
  try {
    const me = await api.me();
    session.user = me.user;
    session.phase = 'app';
    return;
  } catch (e) {
    if (e.status && e.status !== 401) session.error = e.message;
    if (!e.status) session.error = e.message;
  }
  await route401();
}

// Sign in with the one-time token of #/handoff/<token> (the state was moved to
// this server together with the token). An invalid token ends at the login screen.
export async function handoffLogin(token) {
  session.error = '';
  try {
    await api.handoff(token);
  } catch {
    await boot();
    return false;
  }
  await boot();
  return session.phase === 'app';
}

export async function login(username, password) {
  const r = await api.login(username, password);
  session.user = r.user;
  session.phase = 'app';
}

export async function setupAdmin(username, password) {
  const r = await api.setupAdmin(username, password);
  session.user = r.user;
  session.phase = 'app';
}

export async function logout() {
  try {
    await api.logout();
  } catch {
    // the session is dropped locally either way
  }
  await route401();
}
