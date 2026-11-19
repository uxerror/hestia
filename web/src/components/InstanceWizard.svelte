<script>
  import { onMount, untrack } from 'svelte';
  import { api } from '../lib/api.js';
  import { fieldsOf, presetsOf, initialValues, secretsSetOf, toConfig } from '../lib/schemaform.js';
  import { planView, planError, jobIdOf, suggestedInstanceName } from '../lib/plugins.js';
  import { newNode, findNode, pathTo, walk, validateTree, buildCompose, needsCompose, distributeErrors, firstErrorStep, inheritedTarget, nodeName, breadcrumb, requiresOf } from '../lib/deps.js';
  import SchemaForm from './SchemaForm.svelte';
  import DepsStep from './DepsStep.svelte';
  import PlanList from './PlanList.svelte';
  import JobProgress from './JobProgress.svelte';
  import { TriangleAlert, ChevronRight } from 'lucide-svelte';

  // Create / change / remove an instance: form → [dependencies] → plan → apply → job.
  // Creating a plugin that requires other services adds the «Зависимости» step: each requires
  // port is closed with an existing provider or with a new instance (a nested wizard of the same
  // shape, up to 3 levels deep); everything becomes one composite plan.
  //  plugin — GET /plugins/{id} (with manifest.schema);
  //  instance — the instance to change or remove (null for create);
  //  mode — 'create' | 'update' | 'remove';
  //  instances — the existing ones (for the default name);
  //  onchanged() — the job finished (refresh the list); onclose(changed).
  let { plugin, instance = null, mode = 'create', instances = [], onchanged, onclose } = $props();
  const p0 = untrack(() => plugin);
  const i0 = untrack(() => instance);
  const m0 = untrack(() => mode);

  // Details (manifest, schema) of the plugins in the tree: the root and the new providers.
  const details = new Map([[p0.id, p0]]);
  const fieldsBy = (id) => fieldsOf(details.get(id)?.manifest?.schema);
  const rootFields = fieldsBy(p0.id);
  const presets = presetsOf(p0?.manifest?.schema);
  const secretsSet = secretsSetOf(rootFields, i0?.config);
  const hasDeps = m0 === 'create' && requiresOf(p0).length > 0;

  // The tree: the root is the instance of this wizard; nested nodes are new providers.
  const makeRoot = () => {
    const r = newNode(p0, { name: m0 === 'create' ? suggestedInstanceName(p0?.name, untrack(() => instances)) : i0?.name || '' });
    if (m0 !== 'create') r.deps = []; // changing an instance does not touch its links here
    if (m0 === 'update') r.values = initialValues(rootFields, i0?.config);
    return r;
  };
  let root = $state(makeRoot());
  let curKey = $state(root.key); // the node whose step is shown
  const cur = $derived(findNode(root, curKey) || root);
  const isRoot = $derived(cur.key === root.key);
  const ancestors = $derived((pathTo(root, cur.key) || [root]).slice(0, -1));
  const curFields = $derived(fieldsBy(cur.pluginId));
  const inherited = $derived(isRoot ? '' : inheritedTarget(ancestors, fieldsBy));
  // With «тот же сервер» the target fields of a nested node are hidden.
  const shownFields = $derived(!isRoot && inherited && cur.sameTarget ? curFields.filter((f) => f.type !== 'target') : curFields);
  // Whether some node of the tree has a server field (the plugin details are not reactive, so a
  // plain function, not a derived value).
  function needTargets() {
    let need = false;
    walk(root, (n) => {
      if (fieldsBy(n.pluginId).some((f) => f.type === 'target')) need = true;
    });
    return need;
  }

  let dlg = $state();
  let step = $state(m0 === 'remove' ? 'plan' : 'form'); // form | deps | plan | job (form/deps of the node `cur`)
  let busy = $state(false);
  let error = $state('');
  let stale = $state(false); // 409/410: the plan must be built again
  let errors = $state({ fields: {}, deps: {}, nodeDeps: {} }); // by node key / dependency key
  let route = null; // the dependency indexes of the last request (to place the server's errors)
  let targets = $state(null);
  let catalog = $state(null); // {plugins, graph} for the dependency choice
  let plan = $state(null);
  let riskOk = $state(false);
  let jobId = $state('');
  let changed = $state(false);

  const pv = $derived(planView(plan, riskOk));
  const title = m0 === 'create' ? `Новый экземпляр: ${p0?.name}` : m0 === 'update' ? `Изменить «${i0?.name}»` : `Удалить «${i0?.name}»`;
  const crumbs = $derived(breadcrumb(root, cur.key));
  const nodeErrors = $derived(errors.fields[cur.key] || {});

  onMount(() => {
    dlg?.showModal();
    if (m0 === 'remove') makePlan();
    else loadTargets();
    if (hasDeps) loadCatalog();
  });

  // The list of servers is loaded once, when the first node that has a server field needs it
  // (the root or a nested provider).
  let targetsAsked = false;
  function loadTargets() {
    if (!needTargets()) {
      if (!targetsAsked) targets = [];
      return;
    }
    if (targetsAsked) return;
    targetsAsked = true;
    targets = null;
    api
      .pluginTargets()
      .then((r) => (targets = r.targets || []))
      .catch((e) => {
        targets = [];
        error = 'Не удалось загрузить список серверов: ' + e.message;
      });
  }

  function loadCatalog() {
    Promise.all([api.plugins(), api.graph().catch(() => ({ instances: [] }))])
      .then(([pl, g]) => (catalog = { plugins: pl.plugins || [], graph: g }))
      .catch((e) => {
        catalog = { plugins: [], graph: { instances: [] } };
        error = 'Не удалось загрузить список поставщиков: ' + e.message;
      });
  }

  function close() {
    dlg?.close();
  }

  // A new provider for a dependency: the nested wizard opens at once.
  async function createNew(dep, offer) {
    if (!offer) return;
    busy = true;
    error = '';
    try {
      let d = details.get(offer.pluginId);
      if (!d) {
        d = await api.plugin(offer.pluginId);
        details.set(offer.pluginId, d);
      }
      const node = newNode(d, { depth: cur.depth + 1, chain: cur.chain, port: offer.port });
      node.name = nodeName(d.name, d.id, catalog?.graph, root);
      dep.choice = { kind: 'new', node };
      curKey = node.key;
      step = 'form';
      loadTargets();
    } catch (e) {
      error = 'Не удалось загрузить плагин: ' + e.message;
    } finally {
      busy = false;
    }
  }

  function openDep(dep) {
    curKey = dep.choice.node.key;
    step = 'form';
    error = '';
  }

  // Back from a nested node to the dependency that created it.
  function leaveNode() {
    const p = pathTo(root, cur.key);
    curKey = p && p.length > 1 ? p[p.length - 2].key : root.key;
    step = 'deps';
    error = '';
  }

  function dropNode() {
    const parent = ancestors[ancestors.length - 1];
    const dep = parent?.deps.find((d) => d.choice?.kind === 'new' && d.choice.node.key === cur.key);
    if (dep) dep.choice = null;
    leaveNode();
  }

  const subKeys = (node) => {
    const keys = new Set();
    walk(node, (n) => keys.add(n.key));
    return keys;
  };

  // Check what the user has filled; shows the first problem in its own step. keys — only these
  // nodes; withDeps — the required dependencies of those nodes must be closed too.
  function check(keys = null, withDeps = true) {
    const v = validateTree(root, fieldsBy, { targets, secretsSet });
    const only = (o) => Object.fromEntries(Object.entries(o).filter(([k]) => !keys || keys.has(k)));
    const depKeys = new Set();
    walk(root, (n) => keys?.has(n.key) && n.deps.forEach((d) => depKeys.add(d.key)));
    const f = only(v.fields);
    const d = !withDeps ? {} : keys ? Object.fromEntries(Object.entries(v.deps).filter(([k]) => depKeys.has(k))) : v.deps;
    errors = { fields: f, deps: d, nodeDeps: {} };
    if (!Object.keys(f).length && !Object.keys(d).length) return true;
    const first = firstErrorStep(root, { fields: f, deps: d, nodeDeps: {} });
    if (first) {
      curKey = first.key;
      step = first.step === 'deps' && findNode(root, first.key).deps.length ? 'deps' : 'form';
    }
    error = 'Проверьте поля формы';
    return false;
  }

  function next() {
    error = '';
    if (!check(new Set([cur.key]), false)) return;
    step = 'deps';
  }

  function done() {
    error = '';
    if (!check(subKeys(cur))) return;
    leaveNode();
  }

  async function requestPlan() {
    if (m0 === 'remove') return api.planRemoveInstance(i0.id);
    if (m0 === 'update') return api.planUpdateInstance(i0.id, toConfig(rootFields, root.values));
    if (needsCompose(root)) {
      const c = buildCompose(root, fieldsBy);
      route = c.route;
      return api.planCompose(c.body);
    }
    route = null;
    return api.planCreateInstance(p0.id, root.name.trim(), toConfig(rootFields, root.values));
  }

  async function makePlan() {
    error = '';
    stale = false;
    if (m0 !== 'remove' && !check()) return;
    busy = true;
    try {
      plan = await requestPlan();
      riskOk = false;
      step = 'plan';
    } catch (e) {
      placeErrors(planError(e));
    } finally {
      busy = false;
    }
  }

  // 422 with paths: the fields go to the nodes they belong to; the step of the first one opens.
  function placeErrors(pe) {
    if (pe.kind === 'fields' && m0 !== 'remove') {
      const raw = pe.fields;
      const list = Object.entries(raw).map(([field, msg]) => ({ field, msg }));
      const dist = route ? distributeErrors(route, list) : { fields: { [root.key]: raw }, deps: {}, nodeDeps: {}, general: [] };
      errors = { fields: dist.fields, deps: dist.deps, nodeDeps: dist.nodeDeps };
      const first = firstErrorStep(root, dist);
      if (first) {
        curKey = first.key;
        step = first.step === 'deps' && findNode(root, first.key).deps.length ? 'deps' : 'form';
      } else step = m0 === 'remove' ? 'plan' : 'form';
      error = dist.general?.length ? dist.general.join('; ') : pe.message;
      return;
    }
    if (pe.kind === 'stale' || pe.kind === 'expired') stale = true;
    error = pe.message;
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
      placeErrors(planError(e));
    } finally {
      busy = false;
    }
  }

  function backFromPlan() {
    curKey = root.key;
    step = hasDeps && needsCompose(root) ? 'deps' : 'form';
    error = '';
    stale = false;
  }

  function onJobFinish() {
    onchanged?.();
  }

  const doneText = m0 === 'create' ? 'Экземпляр создан.' : m0 === 'update' ? 'Изменения применены.' : 'Экземпляр удалён.';
  const rootHasDeps = $derived(root.deps.length > 0 && m0 === 'create');
  const curHasDeps = $derived(cur.deps.length > 0);
</script>

<dialog bind:this={dlg} class="modal" onclose={() => onclose?.(changed)}>
  <div class="modal-box max-w-2xl" data-testid="instance-wizard">
    <h3 class="font-bold text-lg mb-3">{title}</h3>

    {#if crumbs.length > 1 && (step === 'form' || step === 'deps')}
      <div class="flex flex-wrap items-center gap-1 text-sm mb-3 opacity-80" data-testid="wizard-crumbs">
        {#each crumbs as c, i (i)}
          {#if i > 0}<ChevronRight size={14} />{/if}
          <span class:font-semibold={i === crumbs.length - 1}>{c}</span>
        {/each}
      </div>
    {/if}

    {#if error}
      <div class="alert alert-warning text-sm mb-3" role="alert" data-testid="wizard-error">
        <TriangleAlert size={16} />
        <span>{error}</span>
        {#if stale}<button class="btn btn-sm" onclick={makePlan} disabled={busy} data-testid="replan">Проверить план ещё раз</button>{/if}
      </div>
    {/if}

    {#if step === 'form'}
      <form class="grid gap-3" onsubmit={(e) => (e.preventDefault(), isRoot ? (curHasDeps && rootHasDeps ? next() : makePlan()) : curHasDeps ? next() : done())}>
        {#if m0 === 'create'}
          <div class="grid gap-1">
            <label class="label-text text-sm" for="instance-name">Название<span class="text-error"> *</span></label>
            <input id="instance-name" class="input input-bordered input-sm w-full" class:input-error={nodeErrors.__name || nodeErrors.name} maxlength="100" bind:value={cur.name} data-testid="instance-name" />
            {#if nodeErrors.__name || nodeErrors.name}<span class="text-error text-xs">{nodeErrors.__name || nodeErrors.name}</span>{/if}
          </div>
        {/if}
        {#if !isRoot && inherited}
          <label class="label cursor-pointer justify-start gap-3" data-testid="other-server">
            <input type="checkbox" class="toggle toggle-sm" checked={!cur.sameTarget} onchange={(e) => (cur.sameTarget = !e.currentTarget.checked)} />
            <span class="label-text text-sm">Другой сервер (по умолчанию — тот же, что у «{ancestors[ancestors.length - 1].name || ancestors[ancestors.length - 1].pluginName}»)</span>
          </label>
        {/if}
        <SchemaForm fields={shownFields} presets={isRoot ? presets : []} bind:values={cur.values} errors={nodeErrors} {targets} {secretsSet} disabled={busy} />
        <div class="modal-action mt-0">
          {#if !isRoot}
            <button type="button" class="btn btn-ghost text-error mr-auto" onclick={dropNode} disabled={busy} data-testid="drop-new">Убрать</button>
            <button type="button" class="btn" onclick={leaveNode} disabled={busy}>Назад</button>
          {:else}
            <button type="button" class="btn" onclick={close}>Отмена</button>
          {/if}
          {#if curHasDeps && (isRoot ? rootHasDeps : true)}
            <button type="submit" class="btn btn-primary" disabled={busy || targets === null} data-testid="to-deps">Далее</button>
          {:else if isRoot}
            <button type="submit" class="btn btn-primary" disabled={busy || targets === null} data-testid="make-plan">
              {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Показать план
            </button>
          {:else}
            <button type="submit" class="btn btn-primary" disabled={busy || targets === null} data-testid="node-done">Готово</button>
          {/if}
        </div>
      </form>
    {:else if step === 'deps'}
      <DepsStep node={cur} {root} {catalog} errors={{ deps: errors.deps, nodeDeps: errors.nodeDeps[cur.key] || '' }} {busy} onnew={createNew} onopen={openDep} disabled={busy} />
      <div class="modal-action">
        <button class="btn mr-auto" onclick={() => ((step = 'form'), (error = ''))} disabled={busy}>Назад</button>
        {#if isRoot}
          <button class="btn" onclick={close}>Отмена</button>
          <button class="btn btn-primary" onclick={makePlan} disabled={busy || targets === null || !catalog} data-testid="make-plan">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Показать план
          </button>
        {:else}
          <button class="btn btn-primary" onclick={done} disabled={busy} data-testid="node-done">Готово</button>
        {/if}
      </div>
    {:else if step === 'plan'}
      {#if !plan}
        <div class="flex items-center gap-2 text-sm py-4">
          {#if busy}<span class="loading loading-spinner loading-sm"></span> Строим план…{/if}
        </div>
      {:else}
        <div class="grid gap-2" data-testid="instance-plan">
          <PlanList {plan} />
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
          <button class="btn mr-auto" onclick={backFromPlan} disabled={busy}>Назад</button>
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
