// Live inventory state shared by the "Системы" pages: loads the entries,
// follows the server's events (an open stream also makes the server refresh
// targets every minute) and ticks a clock for "обновлено N с назад".
import { api } from './api.js';
import { subscribeInventory } from './sse.js';
import { applyEntry } from './inventory.js';

export function createLive() {
  let entries = $state([]);
  let loaded = $state(false);
  let error = $state('');
  let now = $state(Date.now());

  async function load() {
    try {
      const r = await api.inventory();
      // Events that arrived while loading are newer than the response only
      // if they were published after it was built; keep the fresher of both.
      const fresh = r.inventory || [];
      entries = fresh.map((e) => {
        const cur = entries.find((c) => c.target_id === e.target_id);
        return cur && cur.collected_at && (!e.collected_at || cur.collected_at > e.collected_at) ? cur : e;
      });
      error = '';
    } catch (e) {
      error = e.message;
    } finally {
      loaded = true;
    }
  }

  // Starts everything; returns a stop function (use it from $effect).
  function start() {
    let opened = false;
    const stopSSE = subscribeInventory({
      onEntry: (e) => (entries = applyEntry(entries, e)),
      onOpen: () => {
        if (opened) load(); // reconnected: events may have been missed
        opened = true;
      },
    });
    load();
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => {
      stopSSE();
      clearInterval(timer);
    };
  }

  return {
    get entries() { return entries; },
    get loaded() { return loaded; },
    get error() { return error; },
    get now() { return now; },
    load,
    start,
    // Optimistic update after a refresh was requested.
    markCollecting(id) {
      entries = entries.map((e) => (e.target_id === id ? { ...e, collecting: true } : e));
    },
  };
}
