<script>
  import { api } from '../lib/api.js';
  import { fmtTime, JOB_STATUS } from '../lib/jobs.js';
  import { cardState, whereText } from '../lib/update.js';
  import { updateInfo, loadUpdateInfo } from '../lib/updateinfo.svelte.js';
  import UpdateRun from './UpdateRun.svelte';
  import { RefreshCw, Download } from 'lucide-svelte';

  // The "Обновление" section of the controller (shown in «Системы»).
  let history = $state([]);
  let error = $state('');
  let checking = $state(false);
  let starting = $state(false);
  let run = $state(null); // { job, expect }
  let dlg = $state();

  const st = $derived(updateInfo.status);
  const card = $derived(cardState(st));

  async function loadHistory() {
    try {
      history = ((await api.jobs()).jobs || []).filter((x) => x.kind === 'update').slice(0, 5);
    } catch {
      /* the list is optional */
    }
  }
  $effect(() => {
    loadUpdateInfo();
    loadHistory();
  });

  async function check() {
    checking = true;
    error = '';
    try {
      await api.checkUpdate();
      await loadUpdateInfo();
    } catch (e) {
      error = e.message;
    } finally {
      checking = false;
    }
  }
  async function start() {
    starting = true;
    error = '';
    const target = st.github.latest;
    try {
      const r = await api.startUpdate({ source: 'github', version: target });
      dlg?.close();
      run = { job: r.job, expect: target };
    } catch (e) {
      error = e.message;
      dlg?.close();
    } finally {
      starting = false;
    }
  }
</script>

<div class="card bg-base-200 mb-4" data-testid="update-card">
  <div class="card-body gap-3">
    <h2 class="card-title text-base">Обновление Hestia</h2>
    {#if error}<div class="alert alert-error text-sm" role="alert">{error}</div>{/if}
    {#if run}
      <UpdateRun job={run.job} expect={run.expect} />
    {:else if card.kind === 'loading'}
      <span class="loading loading-spinner"></span>
    {:else}
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="opacity-70">Версия</dt><dd data-testid="update-current">{st.current}</dd>
        {#if st.where}<dt class="opacity-70">Работает на</dt><dd>{whereText(st.where)}</dd>{/if}
        {#if card.kind !== 'unavailable'}
          <dt class="opacity-70">GitHub</dt>
          <dd data-testid="update-github">
            {#if card.kind === 'unconfigured'}канал не настроен (в этой сборке нет ключа релизов)
            {:else if st.github.error}{st.github.error}{#if st.github.latest} (последняя известная: {st.github.latest}){/if}
            {:else if card.kind === 'available'}доступна {card.latest}{#if st.github.notes_url} · <a class="link" href={st.github.notes_url} target="_blank" rel="noreferrer">что нового</a>{/if}
            {:else if st.github.latest}установлена последняя версия ({st.github.latest})
            {:else}ещё не проверялось{/if}
            {#if st.github.checked_at && st.github.configured}<span class="opacity-60"> · проверено {fmtTime(st.github.checked_at)}</span>{/if}
          </dd>
        {/if}
      </dl>
      {#if card.kind === 'unavailable'}
        <p class="text-sm opacity-70" data-testid="update-reason">{card.reason}</p>
      {:else if card.kind === 'running'}
        <p class="text-sm">Обновление уже идёт: <a class="link" href={'#/jobs/' + encodeURIComponent(card.job)}>задача</a>.</p>
      {:else if card.kind !== 'unconfigured'}
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-sm" onclick={check} disabled={checking} data-testid="update-check">
            {#if checking}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={16} />{/if}
            Проверить сейчас
          </button>
          {#if card.kind === 'available'}
            <button class="btn btn-primary btn-sm" onclick={() => dlg?.showModal()} data-testid="update-go"><Download size={16} /> Обновить до {card.latest}</button>
          {/if}
        </div>
      {/if}
      {#if card.kind !== 'unavailable'}
        <p class="text-xs opacity-60">Обновить можно и из приложения: откройте на этом ПК новую версию Hestia — она предложит обновить контроллер без интернета.</p>
      {/if}
      {#if history.length}
        <div>
          <h3 class="font-semibold text-sm mb-1">История</h3>
          <ul class="grid gap-1 text-sm">
            {#each history as h (h.id)}
              {@const s = JOB_STATUS[h.status] || { label: h.status, cls: '' }}
              <li class="flex items-center gap-2"><span class="badge badge-sm {s.cls}">{s.label}</span><a class="link link-hover" href={'#/jobs/' + encodeURIComponent(h.id)}>{h.title}</a><span class="opacity-60 text-xs">{fmtTime(h.created_at)}</span></li>
            {/each}
          </ul>
        </div>
      {/if}
    {/if}
  </div>
</div>

<dialog bind:this={dlg} class="modal">
  <div class="modal-box">
    <h3 class="font-bold text-lg mb-2">Обновить контроллер до {st?.github?.latest}?</h3>
    <p class="text-sm">Hestia скачает релиз, проверит подпись и перезапустится. Если новая версия не запустится, вернутся прежний бинарник и база. Окно на минуту потеряет связь — это нормально.</p>
    <div class="modal-action">
      <button class="btn" onclick={() => dlg?.close()} disabled={starting}>Отмена</button>
      <button class="btn btn-primary" onclick={start} disabled={starting} data-testid="update-confirm">
        {#if starting}<span class="loading loading-spinner loading-sm"></span>{/if}
        Обновить
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
