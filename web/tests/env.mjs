// Test environment: mocked fetch + EventSource; every test gets a fresh copy of src/ modules.
let n = 0;
export const tick = () => new Promise((r) => setTimeout(r, 0));

export class FakeES {
  static all = [];
  constructor(url) {
    this.url = url;
    this.l = {};
    this.closed = false;
    FakeES.all.push(this);
  }
  addEventListener(t, f) {
    (this.l[t] ||= []).push(f);
  }
  close() {
    this.closed = true;
  }
  emit(t, data) {
    for (const f of this.l[t] || []) f({ data: JSON.stringify(data) });
  }
}

// routes: { 'GET /api/v1/x': (body) => [status, json] }
export function setupEnv(routes = {}) {
  const calls = [];
  FakeES.all = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const key = `${init.method || 'GET'} ${url}`;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ key, body, init });
    const h = routes[key];
    if (!h) return new Response(JSON.stringify({ error: 'нет маршрута ' + key }), { status: 404 });
    const [status, json] = await h(body);
    return new Response(status === 204 ? null : JSON.stringify(json), { status });
  };
  globalThis.EventSource = FakeES;
  const fresh = ++n;
  return {
    calls,
    import: (p) => import(`../src/${p}?fresh=${fresh}`),
    dispose() {
      globalThis.fetch = realFetch;
      delete globalThis.EventSource;
    },
  };
}
