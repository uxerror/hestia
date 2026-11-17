// Poll of GET /health while the server copies its state: the banner stays
// until the server says the transfer mode is over.
export function createTransferWatch(fetchHealth, onChange, { interval = 2000, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let timer = null;
  let running = false;
  async function tick() {
    timer = null;
    let on = true;
    try {
      const h = await fetchHealth();
      on = !!h.transferring;
    } catch {
      on = true; // unreachable while transferring: keep the banner, try again
    }
    onChange(on);
    if (on && running) timer = setTimer(tick, interval);
    else running = false;
  }
  return {
    start() {
      onChange(true);
      if (running) return;
      running = true;
      timer = setTimer(tick, interval);
    },
    stop() {
      running = false;
      if (timer) clearTimer(timer);
      timer = null;
    },
    get active() {
      return running;
    },
  };
}
