<script>
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { STEP_STATUS, isFinal } from '../lib/jobs.js';
  import { CircleCheck, TriangleAlert } from 'lucide-svelte';

  // Follows a job through SSE: steps, the tail of the log and the result.
  // onfinish(job) is called once when the job reaches a final status.
  let { id, doneText = 'Готово.', failText = 'Не удалось.', onfinish, compact = false } = $props();

  let job = $state(null);
  let logEl = $state();

  $effect(() => {
    const jobId = id;
    let gone = false;
    let reported = false;
    const finish = (j) => {
      if (reported || !isFinal(j.status)) return;
      reported = true;
      onfinish?.(j);
    };
    job = null;
    const close = subscribeJob(jobId, {
      onUpdate: (j) => {
        job = j;
        finish(j);
      },
      onError: () => {
        // The browser reconnects by itself; meanwhile take the stored state.
        api
          .job(jobId)
          .then((r) => {
            if (gone || !r?.job) return;
            if (!job || isFinal(r.job.status)) job = { ...r.job, steps: r.job.steps || [], log: r.job.log || [] };
            finish(r.job);
          })
          .catch(() => {});
      },
    });
    return () => {
      gone = true;
      close();
    };
  });

  $effect(() => {
    job?.log?.length;
    if (logEl) logEl.scrollTop = logEl.scrollHeight;
  });

  const failed = $derived(job?.status === 'failed' || job?.status === 'cancelled');
</script>

<div class="grid gap-2" data-testid="job-progress">
  <ul class="grid gap-1 text-sm">
    {#each job?.steps || [] as s (s.idx)}
      {@const st = STEP_STATUS[s.status] || { label: s.status, cls: '' }}
      <li class="flex items-center gap-2">
        <span class="badge badge-sm {st.cls}">{st.label}</span> {s.title}
        {#if s.status === 'running'}<span class="loading loading-spinner loading-xs"></span>{/if}
        {#if s.error}<span class="text-error text-xs">{s.error}</span>{/if}
      </li>
    {/each}
  </ul>
  {#if !compact && job?.log?.length}
    <div bind:this={logEl} class="bg-neutral text-neutral-content rounded-box p-2 font-mono text-xs max-h-48 overflow-auto" data-testid="job-log">
      {#each job.log as l, i (i)}
        <div class="whitespace-pre-wrap break-all" class:text-error={l.level === 'error'} class:text-warning={l.level === 'warn'}>{l.line}</div>
      {/each}
    </div>
  {/if}
  {#if job?.status === 'done'}
    <div class="alert alert-success text-sm" role="status" data-testid="job-done"><CircleCheck size={18} /> {doneText}</div>
  {:else if failed}
    <div class="alert alert-error text-sm" role="alert" data-testid="job-failed">
      <TriangleAlert size={18} />
      <span>{job.error || failText} <a class="link" href={'#/jobs/' + encodeURIComponent(id)}>Журнал задачи</a></span>
    </div>
  {:else}
    <div class="flex items-center gap-2 text-sm"><span class="loading loading-spinner loading-sm"></span> Выполняется…</div>
  {/if}
</div>
