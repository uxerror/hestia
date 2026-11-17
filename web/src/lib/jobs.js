// Pure helpers for jobs: reducer for SSE events and display metadata.
export const FINAL = ['done', 'failed', 'cancelled'];
export const isFinal = (s) => FINAL.includes(s);

export const JOB_STATUS = {
  queued: { label: 'В очереди', cls: 'badge-ghost' },
  running: { label: 'Выполняется', cls: 'badge-info' },
  done: { label: 'Готово', cls: 'badge-success' },
  failed: { label: 'Ошибка', cls: 'badge-error' },
  cancelled: { label: 'Отменена', cls: 'badge-warning' },
};
export const STEP_STATUS = {
  pending: { label: 'Ожидает', cls: 'badge-ghost' },
  running: { label: 'Выполняется', cls: 'badge-info' },
  done: { label: 'Готово', cls: 'badge-success' },
  failed: { label: 'Ошибка', cls: 'badge-error' },
  skipped: { label: 'Пропущен', cls: 'badge-warning' },
};

export function normalizeJob(j) {
  return { ...j, steps: j.steps ? [...j.steps] : [], log: j.log ? [...j.log] : [] };
}

// Returns a new job with the event applied. type: snapshot|step|log|status.
export function applyEvent(job, type, data) {
  if (type === 'snapshot') return normalizeJob(data);
  if (!job) return job;
  if (type === 'step') {
    const steps = [...job.steps];
    const i = steps.findIndex((s) => s.idx === data.idx);
    if (i >= 0) steps[i] = { ...steps[i], ...data };
    else steps.push(data);
    steps.sort((a, b) => a.idx - b.idx);
    return { ...job, steps };
  }
  if (type === 'log') return { ...job, log: [...job.log, data] };
  if (type === 'status') {
    const { status, error, started_at, finished_at, result } = data;
    const next = { ...job, status: status ?? job.status };
    if (error !== undefined) next.error = error;
    if (started_at !== undefined) next.started_at = started_at;
    if (finished_at !== undefined) next.finished_at = finished_at;
    if (result !== undefined) next.result = result; // in-memory result (e.g. the handoff link)
    return next;
  }
  return job;
}

export function fmtTime(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d)) return String(s);
  return d.toLocaleString('ru-RU');
}
