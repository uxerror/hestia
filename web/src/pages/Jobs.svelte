<script>
  import { api } from '../lib/api.js';
  import { JOB_STATUS, fmtTime } from '../lib/jobs.js';
  import { Play } from 'lucide-svelte';

  let jobs = $state([]);
  let loading = $state(true);
  let error = $state('');
  let starting = $state(false);

  async function load() {
    try {
      jobs = (await api.jobs()).jobs || [];
      error = '';
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }
  async function demo() {
    starting = true;
    error = '';
    try {
      const r = await api.demoJob();
      location.hash = '#/jobs/' + encodeURIComponent(r.job.id);
    } catch (e) {
      error = e.message;
    } finally {
      starting = false;
    }
  }
  $effect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  });
</script>

<div class="flex items-center justify-between mb-4">
  <h1 class="text-2xl font-bold">Задачи</h1>
  <button class="btn btn-primary btn-sm" onclick={demo} disabled={starting}>
    {#if starting}<span class="loading loading-spinner loading-xs"></span>{:else}<Play size={16} />{/if}
    Демо-задача
  </button>
</div>

{#if error}<div class="alert alert-error mb-4" role="alert">{error}</div>{/if}

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if jobs.length === 0}
  <p class="opacity-70 py-8 text-center">Задач пока нет. Запустите демо-задачу, чтобы посмотреть, как это выглядит.</p>
{:else}
  <div class="overflow-x-auto">
    <table class="table">
      <thead><tr><th>Задача</th><th>Статус</th><th>Создана</th></tr></thead>
      <tbody>
        {#each jobs as j (j.id)}
          {@const st = JOB_STATUS[j.status] || { label: j.status, cls: '' }}
          <tr class="hover:bg-base-200 cursor-pointer" onclick={() => (location.hash = '#/jobs/' + encodeURIComponent(j.id))}>
            <td><a class="link link-hover font-medium" href={'#/jobs/' + encodeURIComponent(j.id)}>{j.title}</a></td>
            <td><span class="badge {st.cls}">{st.label}</span></td>
            <td class="text-sm opacity-70">{fmtTime(j.created_at)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
