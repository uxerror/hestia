<script>
  import { onMount, untrack } from 'svelte';
  import { api } from '../lib/api.js';
  import { fieldsOf, presetsOf, initialValues, secretsSetOf, validate, toConfig } from '../lib/schemaform.js';
  import { planView, riskInfo, planError, jobIdOf, suggestedInstanceName } from '../lib/plugins.js';
  import SchemaForm from './SchemaForm.svelte';
  import JobProgress from './JobProgress.svelte';
  import { TriangleAlert, Info } from 'lucide-svelte';

  // Create / change / remove an instance: form → plan → apply → job.
  //  plugin — GET /plugins/{id} (with manifest.schema);
  //  instance — the instance to change or remove (null for create);
  //  mode — 'create' | 'update' | 'remove';
  //  instances — the existing ones (for the default name);
  //  onchanged() — the job finished (refresh the list); onclose(changed).
  let { plugin, instance = null, mode = 'create', instances = [], onchanged, onclose } = $props();
  const p0 = untrack(() => plugin);
  const i0 = untrack(() => instance);
  const m0 = untrack(() => mode);

  const fields = fieldsOf(p0?.manifest?.schema);
  const presets = presetsOf(p0?.manifest?.schema);
  const secretsSet = secretsSetOf(fields, i0?.config);
  const needTargets = fields.some((f) => f.type === 'target');

  let dlg = $state();
  let step = $state(m0 === 'remove' ? 'plan' : 'form'); // form | plan | job
  let busy = $state(false);
  let error = $state('');
  let stale = $state(false); // 409/410: the plan must be built again
  let name = $state(m0 === 'create' ? suggestedInstanceName(p0?.name, untrack(() => instances)) : i0?.name || '');
  let values = $state(initialValues(fields, m0 === 'create' ? null : i0?.config));
  let errors = $state({});
  let targets = $state(needTargets ? null : []);
  let plan = $state(null);
  let riskOk = $state(false);
  let jobId = $state('');
  let changed = $state(false);

  const pv = $derived(planView(plan, riskOk));
  const title = m0 === 'create' ? `Новый экземпляр: ${p0?.name}` : m0 === 'update' ? `Изменить «${i0?.name}»` : `Удалить «${i0?.name}»`;

  onMount(() => {
    dlg?.showModal();
    if (needTargets) {
      api
        .pluginTargets()
        .then((r) => (targets = r.targets || []))
        .catch((e) => {
          targets = [];
          error = 'Не удалось загрузить список серверов: ' + e.message;
        });
    }
    if (m0 === 'remove') makePlan();
  });

  function close() {
    dlg?.close();
  }

  function requestPlan() {
    if (m0 === 'remove') return api.planRemoveInstance(i0.id);
    const config = toConfig(fields, values);
    if (m0 === 'update') return api.planUpdateInstance(i0.id, config);
    return api.planCreateInstance(p0.id, name.trim(), config);
  }

  async function makePlan() {
    error = '';
    stale = false;
    if (m0 !== 'remove') {
      const e = validate(fields, values, { secretsSet, targets });
      if (m0 === 'create' && !name.trim()) e.__name = 'Введите имя';
      errors = e;
      if (Object.keys(e).length) {
        step = 'form';
        error = 'Проверьте поля формы';
        return;
      }
    }
    busy = true;
    try {
      plan = await requestPlan();
      riskOk = false;
      step = 'plan';
    } catch (e) {
      const pe = planError(e);
      if (pe.kind === 'fields') {
        errors = pe.fields;
        step = m0 === 'remove' ? 'plan' : 'form';
      }
      error = pe.message;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    error = '';
    busy = true;
    try {
      const r = await api.applyPluginPlan(plan.plan_id, plan.hash, riskOk);
      jobId = jobIdOf(r);
      changed = true;
      step = 'job';
    } catch (e) {
      const pe = planError(e);
      if (pe.kind === 'stale' || pe.kind === 'expired') stale = true;
      if (pe.kind === 'fields' && m0 !== 'remove') {
        errors = pe.fields;
        step = 'form';
      }
      error = pe.message;
    } finally {
      busy = false;
    }
  }

  function onJobFinish() {
    onchanged?.();
  }

  const doneText = m0 === 'create' ? 'Экземпляр создан.' : m0 === 'update' ? 'Изменения применены.' : 'Экземпляр удалён.';
</script>

<dialog bind:this={dlg} class="modal" onclose={() => onclose?.(changed)}>
  <div class="modal-box max-w-2xl" data-testid="instance-wizard">
    <h3 class="font-bold text-lg mb-3">{title}</h3>

    {#if error}
      <div class="alert alert-warning text-sm mb-3" role="alert" data-testid="wizard-error">
        <TriangleAlert size={16} />
        <span>{error}</span>
        {#if stale}<button class="btn btn-sm" onclick={makePlan} disabled={busy} data-testid="replan">Проверить план ещё раз</button>{/if}
      </div>
    {/if}

    {#if step === 'form'}
      <form class="grid gap-3" onsubmit={(e) => (e.preventDefault(), makePlan())}>
        {#if m0 === 'create'}
          <div class="grid gap-1">
            <label class="label-text text-sm" for="instance-name">Название<span class="text-error"> *</span></label>
            <input id="instance-name" class="input input-bordered input-sm w-full" class:input-error={errors.__name || errors.name} maxlength="100" bind:value={name} data-testid="instance-name" />
            {#if errors.__name || errors.name}<span class="text-error text-xs">{errors.__name || errors.name}</span>{/if}
          </div>
        {/if}
        <SchemaForm {fields} {presets} bind:values {errors} {targets} {secretsSet} disabled={busy} />
        <div class="modal-action mt-0">
          <button type="button" class="btn" onclick={close}>Отмена</button>
          <button type="submit" class="btn btn-primary" disabled={busy || targets === null} data-testid="make-plan">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Показать план
          </button>
        </div>
      </form>
    {:else if step === 'plan'}
      {#if !plan}
        <div class="flex items-center gap-2 text-sm py-4">
          {#if busy}<span class="loading loading-spinner loading-sm"></span> Строим план…{/if}
        </div>
      {:else}
        <div class="grid gap-2" data-testid="instance-plan">
          {#if plan.plan?.actions?.length}
            <ol class="grid gap-2">
              {#each plan.plan.actions as a, i (i)}
                {@const r = riskInfo(a.risk)}
                <li class="alert text-sm items-start {r.alert}" data-testid={'plan-action-' + (a.risk || 'info')}>
                  {#if a.risk === 'danger' || a.risk === 'change'}<TriangleAlert size={16} />{:else}<Info size={16} />{/if}
                  <div class="grid gap-0.5">
                    <span class="font-medium">{a.title}</span>
                    {#if a.detail}<span class="text-xs opacity-80 whitespace-pre-wrap break-words">{a.detail}</span>{/if}
                  </div>
                </li>
              {/each}
            </ol>
          {:else}
            <p class="text-sm opacity-70">Изменений не требуется.</p>
          {/if}
          {#if plan.plan?.warnings?.length}
            <div class="grid gap-1" data-testid="plan-warnings">
              <span class="text-sm font-semibold">Предупреждения</span>
              <ul class="list-disc ml-5 text-sm">
                {#each plan.plan.warnings as w, i (i)}<li>{w}</li>{/each}
              </ul>
            </div>
          {/if}
          {#if pv.danger}
            <label class="label cursor-pointer justify-start gap-3 bg-error/10 rounded p-2">
              <input type="checkbox" class="checkbox checkbox-sm checkbox-error" bind:checked={riskOk} data-testid="risk-ok" />
              <span class="label-text text-sm">Я понимаю риск</span>
            </label>
          {/if}
        </div>
      {/if}
      <div class="modal-action">
        {#if m0 !== 'remove'}
          <button class="btn mr-auto" onclick={() => ((step = 'form'), (error = ''), (stale = false))} disabled={busy}>Назад</button>
        {/if}
        <button class="btn" onclick={close}>Отмена</button>
        <button
          class="btn {m0 === 'remove' || pv.danger ? 'btn-error' : 'btn-primary'}"
          onclick={apply}
          disabled={busy || !plan || !pv.canApply || stale}
          data-testid="apply-plan"
        >
          {#if busy && plan}<span class="loading loading-spinner loading-sm"></span>{/if} {m0 === 'remove' ? 'Удалить' : 'Применить'}
        </button>
      </div>
    {:else}
      <JobProgress id={jobId} {doneText} failText="Не удалось применить план." onfinish={onJobFinish} />
      <div class="modal-action">
        <button class="btn" onclick={close}>Закрыть</button>
      </div>
    {/if}
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
