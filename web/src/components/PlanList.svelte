<script>
  import { riskInfo } from '../lib/plugins.js';
  import { TriangleAlert, Info, Undo2 } from 'lucide-svelte';

  // The visible part of a plan (GET of POST …/plan): actions with their risk, the steps of a
  // composite plan (each with its own actions and what is rolled back on a failure) and warnings.
  let { plan } = $props();
  const steps = $derived(plan?.steps || []);
  const KIND = { instance: 'экземпляр', link: 'связь' };
</script>

{#snippet action(a, i)}
  {@const r = riskInfo(a.risk)}
  <li class="alert text-sm items-start {r.alert}" data-testid={'plan-action-' + (a.risk || 'info')}>
    {#if a.risk === 'danger' || a.risk === 'change'}<TriangleAlert size={16} />{:else}<Info size={16} />{/if}
    <div class="grid gap-0.5">
      <span class="font-medium">{a.title}</span>
      {#if a.detail}<span class="text-xs opacity-80 whitespace-pre-wrap break-words">{a.detail}</span>{/if}
    </div>
  </li>
{/snippet}

<div class="grid gap-2" data-testid="plan-list">
  {#if steps.length}
    <ol class="grid gap-3" data-testid="plan-steps">
      {#each steps as s, i (i)}
        <li class="grid gap-1" data-testid="plan-step">
          <div class="text-sm font-semibold flex flex-wrap items-center gap-2">
            <span class="badge badge-sm badge-outline">{i + 1}</span>
            {s.title}
            <span class="badge badge-ghost badge-sm">{KIND[s.kind] || s.kind}</span>
          </div>
          {#if s.plan?.actions?.length}
            <ol class="grid gap-1 ml-4">
              {#each s.plan.actions as a, j (j)}{@render action(a, j)}{/each}
            </ol>
          {/if}
          {#if s.rollback}
            <div class="ml-4 text-xs opacity-70 flex items-start gap-1" data-testid="plan-rollback"><Undo2 size={12} class="mt-0.5 shrink-0" /> При ошибке: {s.rollback}</div>
          {/if}
        </li>
      {/each}
    </ol>
  {:else if plan?.plan?.actions?.length}
    <ol class="grid gap-2">
      {#each plan.plan.actions as a, i (i)}{@render action(a, i)}{/each}
    </ol>
  {:else}
    <p class="text-sm opacity-70">Изменений не требуется.</p>
  {/if}
  {#if plan?.plan?.warnings?.length}
    <div class="grid gap-1" data-testid="plan-warnings">
      <span class="text-sm font-semibold">Предупреждения</span>
      <ul class="list-disc ml-5 text-sm">
        {#each plan.plan.warnings as w, i (i)}<li>{w}</li>{/each}
      </ul>
    </div>
  {/if}
</div>
