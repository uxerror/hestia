<script>
  import { untrack, onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { fmtTime } from '../lib/jobs.js';
  import { linkStatusInfo, linkSides, removeAction, KIND_LABEL } from '../lib/linkpanel.js';
  import PlanRun from './PlanRun.svelte';
  import { TriangleAlert, X, RefreshCw, Trash2 } from 'lucide-svelte';

  // Panel of a link (a click on its edge): the sides, the status, «Проверить», «Удалить».
  // The removal is a plan → a job, like everything that changes the sides.
  //  link — a link of GET /graph; onclose(); onchanged() — the job finished.
  //  autoRemove — start with the removal plan (the plugin page's «Удалить»).
  let { link, onclose, onchanged, autoRemove = false } = $props();

  let fresh = $state(null); // after «Проверить»
  let busy = $state(false);
  let error = $state('');
  let confirm = $state(false);
  let plan = $state(null);

  const cur = $derived(fresh && fresh.id === link.id ? fresh : link);
  const st = $derived(linkStatusInfo(cur.status));
  const sides = $derived(linkSides(cur));
  const act = $derived(removeAction(cur));

  async function check() {
    busy = true;
    error = '';
    try {
      fresh = await api.link(link.id, true);
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function makeRemovePlan() {
    busy = true;
    error = '';
    try {
      plan = await api.planRemoveLink(link.id);
      confirm = false;
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    if (autoRemove) makeRemovePlan();
  });

  // Another link: forget what was shown for the previous one.
  $effect(() => {
    link.id;
    untrack(() => {
      fresh = null;
      plan = null;
      confirm = false;
      error = '';
    });
  });
</script>

<div class="card bg-base-200 h-full" data-testid="link-panel">
  <div class="card-body p-4 gap-3">
    <div class="flex items-start justify-between gap-2">
      <h2 class="font-bold text-lg">Связь</h2>
      <button class="btn btn-ghost btn-xs btn-circle" onclick={() => onclose?.()} aria-label="Закрыть"><X size={16} /></button>
    </div>

    <div class="grid gap-1 text-sm">
      <div class="flex gap-2"><span class="opacity-60 w-24 shrink-0">Поставщик</span><span class="font-medium break-words" data-testid="link-provider">{sides.provider}</span></div>
      <div class="flex gap-2"><span class="opacity-60 w-24 shrink-0">{sides.consumerLabel}</span><span class="font-medium break-words" data-testid="link-consumer">{sides.consumer}</span></div>
      <div class="flex gap-2"><span class="opacity-60 w-24 shrink-0">Вид</span><span>{KIND_LABEL[cur.kind] || cur.kind}{cur.type ? ' · ' + cur.type : ''}</span></div>
      <div class="flex items-center gap-2"><span class="opacity-60 w-24 shrink-0">Состояние</span><span class="badge badge-sm {st.cls}" data-testid="link-status">{st.label}</span></div>
      {#if cur.detail}<div class="text-sm whitespace-pre-wrap break-words opacity-80" data-testid="link-detail">{cur.detail}</div>{/if}
      {#if cur.checked_at}<div class="text-xs opacity-60">Проверена: {fmtTime(cur.checked_at)}</div>{/if}
    </div>

    {#if error}<div class="alert alert-warning text-sm" role="alert"><TriangleAlert size={16} /> {error}</div>{/if}

    {#if plan}
      <PlanRun {plan} applyText={act.label} danger doneText={cur.status === 'orphaned' ? 'Запись удалена.' : 'Связь удалена.'} onback={() => (plan = null)} onreplan={makeRemovePlan} onfinish={() => onchanged?.()} />
    {:else if confirm}
      <div class="alert alert-warning text-sm grid gap-2" role="alert">
        <span>{act.confirm}</span>
        <div class="flex gap-2">
          <button class="btn btn-sm btn-error" onclick={makeRemovePlan} disabled={busy} data-testid="link-remove-plan">Показать план</button>
          <button class="btn btn-sm btn-ghost" onclick={() => (confirm = false)}>Нет</button>
        </div>
      </div>
    {:else}
      <div class="flex flex-wrap gap-2">
        <button class="btn btn-sm" onclick={check} disabled={busy || cur.status === 'orphaned'} data-testid="link-check">
          {#if busy}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={14} />{/if} Проверить
        </button>
        <button class="btn btn-sm btn-ghost text-error" onclick={() => (confirm = true)} disabled={busy} data-testid="link-remove"><Trash2 size={14} /> {act.label}</button>
      </div>
    {/if}
  </div>
</div>
