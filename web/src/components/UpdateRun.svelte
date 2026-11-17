<script>
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { STEP_STATUS } from '../lib/jobs.js';
  import { inRestart, waitForVersion } from '../lib/update.js';
  import { CircleCheck, TriangleAlert } from 'lucide-svelte';

  // Follows an update job through the restart of the controller and reloads
  // the page when the new version answers.
  let { job, expect } = $props();

  let j = $state(null);
  let phase = $state('running'); // running | restarting | done | failed
  let error = $state('');
  let waiting = false;

  async function afterRestart() {
    if (waiting) return;
    waiting = true;
    phase = 'restarting';
    const r = await waitForVersion(() => api.health(), expect);
    if (r === 'ok') {
      phase = 'done';
      setTimeout(() => {
        location.hash = '#/targets';
        location.reload();
      }, 1500);
      return;
    }
    phase = 'failed';
    error = 'Контроллер не ответил с новой версией за 90 секунд.';
    try {
      const x = (await api.job(job.id)).job;
      if (x?.error) error = x.error;
    } catch {
      // still down: the generic text stays
    }
  }

  $effect(() => {
    const close = subscribeJob(job.id, {
      onUpdate: (x) => {
        j = x;
        if (inRestart(x)) afterRestart();
        else if (x.status === 'failed') {
          phase = 'failed';
          error = x.error || 'Обновление не удалось.';
        }
      },
      // The connection drops when the service stops: wait for the new version.
      onError: () => afterRestart(),
    });
    return close;
  });
  const steps = $derived(j?.steps || []);
</script>

<div class="card bg-base-200" data-testid="update-run">
  <div class="card-body gap-3">
    <ul class="grid gap-1 text-sm">
      {#each steps as s (s.idx)}
        {@const st = STEP_STATUS[s.status] || { label: s.status, cls: '' }}
        <li class="flex items-center gap-2"><span class="badge badge-sm {st.cls}">{st.label}</span> {s.title}</li>
      {/each}
    </ul>
    {#if phase === 'running'}
      <div class="flex items-center gap-2 text-sm"><span class="loading loading-spinner loading-sm"></span> Идёт обновление…</div>
    {:else if phase === 'restarting'}
      <div class="flex items-center gap-2 text-sm" role="status" data-testid="update-restarting"><span class="loading loading-spinner loading-sm"></span> Перезапуск контроллера… ждём новую версию {expect}</div>
    {:else if phase === 'done'}
      <div class="alert alert-success text-sm" role="status"><CircleCheck size={18} /> Контроллер обновлён до {expect}. Страница сейчас перезагрузится.</div>
    {:else}
      <div class="alert alert-error text-sm" role="alert" data-testid="update-failed"><TriangleAlert size={18} /> {error}</div>
      <a class="link text-sm" href={'#/jobs/' + encodeURIComponent(job.id)}>Журнал задачи</a>
    {/if}
  </div>
</div>
