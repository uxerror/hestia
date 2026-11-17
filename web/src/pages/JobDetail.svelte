<script>
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { JOB_STATUS, STEP_STATUS, fmtTime, isFinal } from '../lib/jobs.js';
  import { ArrowLeft } from 'lucide-svelte';

  let { id } = $props();
  let job = $state(null);
  let error = $state('');
  let live = $state(false);
  let logEl = $state();

  $effect(() => {
    const jobId = id;
    job = null;
    error = '';
    let close = () => {};
    let gone = false;
    api
      .job(jobId)
      .then((r) => {
        if (gone) return;
        job = r.job;
        if (isFinal(r.job.status)) return;
        live = true;
        close = subscribeJob(jobId, {
          onUpdate: (j) => {
            job = j;
            live = !isFinal(j.status);
          },
          onError: () => {
            // dropped connection: EventSource reconnects; verify the session/job still exists
            api.job(jobId).then((r2) => { if (!gone) job = r2.job; }).catch(() => {});
          },
        });
      })
      .catch((e) => {
        if (!gone) error = e.status === 404 ? 'Задача не найдена' : e.message;
      });
    return () => {
      gone = true;
      live = false;
      close();
    };
  });

  $effect(() => {
    job?.log.length;
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
  });

  const st = $derived(job ? JOB_STATUS[job.status] || { label: job.status, cls: '' } : null);
</script>

<a href="#/jobs" class="btn btn-ghost btn-sm mb-4"><ArrowLeft size={16} /> К задачам</a>

{#if error}
  <div class="alert alert-error" role="alert">{error}</div>
{:else if !job}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  <div class="flex flex-wrap items-center gap-3 mb-1">
    <h1 class="text-2xl font-bold">{job.title}</h1>
    <span class="badge {st.cls}" data-testid="job-status">{st.label}</span>
    {#if live}<span class="loading loading-dots loading-sm" title="Обновляется в реальном времени"></span>{/if}
  </div>
  <p class="text-sm opacity-70 mb-4">Создана: {fmtTime(job.created_at)} · Завершена: {fmtTime(job.finished_at)}</p>
  {#if job.error}<div class="alert alert-error mb-4" role="alert">{job.error}</div>{/if}

  <h2 class="font-semibold mb-2">Шаги</h2>
  <ul class="steps steps-vertical mb-6">
    {#each job.steps as s (s.idx)}
      {@const ss = STEP_STATUS[s.status] || { label: s.status, cls: '' }}
      <li class="step" class:step-primary={s.status === 'done' || s.status === 'running'} class:step-error={s.status === 'failed'}>
        <div class="text-left">
          <span>{s.title}</span> <span class="badge badge-sm {ss.cls}">{ss.label}</span>
          {#if s.status === 'running'}<span class="loading loading-spinner loading-xs ml-1"></span>{/if}
          {#if s.error}<div class="text-error text-sm">{s.error}</div>{/if}
        </div>
      </li>
    {/each}
  </ul>

  <h2 class="font-semibold mb-2">Журнал</h2>
  <div bind:this={logEl} class="bg-neutral text-neutral-content rounded-box p-3 font-mono text-sm h-72 overflow-auto" data-testid="log">
    {#each job.log as l, i (i)}
      <div class:text-error={l.level === 'error'} class:text-warning={l.level === 'warn'}>
        <span class="opacity-50">{l.at ? new Date(l.at).toLocaleTimeString('ru-RU') : ''}</span> {l.line}
      </div>
    {:else}
      <span class="opacity-50">Пока пусто…</span>
    {/each}
  </div>
{/if}
