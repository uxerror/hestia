import { applyEvent, isFinal } from './jobs.js';

// Subscribe to job events. onUpdate(job) gets the reduced job after each event;
// onError() is called when the connection drops before the final status.
// Returns a close() function.
export function subscribeJob(id, { onUpdate, onError }) {
  const es = new EventSource(`/api/v1/jobs/${encodeURIComponent(id)}/events`);
  let job = null;
  let closed = false;
  const close = () => {
    closed = true;
    es.close();
  };
  for (const type of ['snapshot', 'step', 'log', 'status']) {
    es.addEventListener(type, (ev) => {
      if (closed) return;
      let data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        return;
      }
      job = applyEvent(job, type, data);
      if (job) onUpdate(job);
      if (type === 'status' && job && isFinal(job.status)) close();
      if (type === 'snapshot' && isFinal(job.status)) close();
    });
  }
  es.onerror = () => {
    if (closed) return;
    // The browser retries by itself and a new snapshot replaces local state;
    // the caller may check the session meanwhile.
    onError?.();
  };
  return close;
}
