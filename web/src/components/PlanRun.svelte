<script>
  import { api } from '../lib/api.js';
  import { planView, planError, jobIdOf } from '../lib/plugins.js';
  import PlanList from './PlanList.svelte';
  import JobProgress from './JobProgress.svelte';
  import { TriangleAlert } from 'lucide-svelte';

  // A plan of a link or a composite plan inside a panel: the plan → «Применить» → the job
  // through SSE. The plan itself is built by the parent.
  //  plan — the answer of …/plan; applyText — the text of the button (danger → red);
  //  onreplan() — «Проверить план ещё раз» (409/410); onback() — «Назад» (optional);
  //  onfinish(job) — the job finished (done or not).
  let { plan, applyText = 'Применить', doneText = 'Готово.', failText = 'Не удалось применить план.', danger = false, onreplan, onback, onfinish } = $props();

  let riskOk = $state(false);
  let busy = $state(false);
  let error = $state('');
  let stale = $state(false);
  let jobId = $state('');

  const pv = $derived(planView(plan, riskOk));

  async function apply() {
    error = '';
    busy = true;
    try {
      const r = await api.applyPluginPlan(plan.plan_id, plan.hash, riskOk);
      jobId = jobIdOf(r);
    } catch (e) {
      const pe = planError(e);
      stale = pe.kind === 'stale' || pe.kind === 'expired';
      error = pe.message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="grid gap-3" data-testid="plan-run">
  {#if error}
    <div class="alert alert-warning text-sm" role="alert" data-testid="plan-run-error">
      <TriangleAlert size={16} />
      <span>{error}</span>
      {#if stale}<button class="btn btn-sm" onclick={() => onreplan?.()} data-testid="replan">Проверить план ещё раз</button>{/if}
    </div>
  {/if}
  {#if !jobId}
    <PlanList {plan} />
    {#if pv.danger}
      <label class="label cursor-pointer justify-start gap-3 bg-error/10 rounded p-2">
        <input type="checkbox" class="checkbox checkbox-sm checkbox-error" bind:checked={riskOk} data-testid="risk-ok" />
        <span class="label-text text-sm">Я понимаю риск</span>
      </label>
    {/if}
    <div class="flex flex-wrap justify-end gap-2">
      {#if onback}<button class="btn btn-sm mr-auto" onclick={onback} disabled={busy}>Назад</button>{/if}
      <button class="btn btn-sm {danger || pv.danger ? 'btn-error' : 'btn-primary'}" onclick={apply} disabled={busy || !pv.canApply || stale} data-testid="apply-plan">
        {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if} {applyText}
      </button>
    </div>
  {:else}
    <JobProgress id={jobId} {doneText} {failText} {onfinish} />
  {/if}
</div>
