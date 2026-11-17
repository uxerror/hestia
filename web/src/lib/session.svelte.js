import { api, onUnauthorized } from './api.js';

// phase: loading | setup | login | app
export const session = $state({ phase: 'loading', user: null, mode: '', error: '' });

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
