<script>
  import { existingProviders, newProviderOffers, usedProviders } from '../lib/deps.js';
  import { instanceStatusInfo } from '../lib/plugins.js';
  import { Plus, Settings, TriangleAlert } from 'lucide-svelte';

  // The «Зависимости» step: for every requires port of the node a provider — an existing
  // instance (busy ones are grey) or «Создать новый …» (a nested wizard). Required ones are
  // shown at once, optional ones under «Подробнее».
  //  node — the node of the tree (deps live in node.deps and are changed here);
  //  root — the tree (to know the providers already taken); catalog — {plugins, graph} or null;
  //  errors — {deps: {depKey: msg}, nodeDeps: msg} of the last check;
  //  onnew(dep, offer) — create a new provider (the wizard builds the nested node);
  //  onopen(dep) — open the nested wizard of a chosen new provider.
  let { node, root, catalog, errors = { deps: {}, nodeDeps: '' }, busy = false, onnew, onopen, disabled = false } = $props();

  const required = $derived(node.deps.filter((d) => !d.optional));
  const optional = $derived(node.deps.filter((d) => d.optional));
  let showOptional = $state(false);
  $effect(() => {
    if (optional.some((d) => d.choice || errors.deps[d.key])) showOptional = true;
  });

  const used = $derived(usedProviders(root));
  const existing = (dep) => (catalog ? existingProviders(catalog.graph, dep.type, used) : []);
  const offers = (dep) => (catalog ? newProviderOffers(catalog.plugins, dep.type, node) : []);

  // The radio value of a choice.
  const valueOf = (dep) => (!dep.choice ? 'none' : dep.choice.kind === 'existing' ? `e|${dep.choice.instance}|${dep.choice.port}` : `n|${dep.choice.node.pluginId}`);
  function pick(dep, v) {
    if (v === 'none') dep.choice = null;
    else if (v.startsWith('e|')) {
      const [, instance, port] = v.split('|');
      dep.choice = { kind: 'existing', instance: Number(instance), port };
    } else if (v.startsWith('n|')) {
      const pid = v.slice(2);
      if (dep.choice?.kind === 'new' && dep.choice.node.pluginId === pid) return;
      onnew?.(dep, offers(dep).find((o) => o.pluginId === pid));
    }
  }
</script>

{#snippet slot(dep)}
  {@const ex = existing(dep)}
  {@const of = offers(dep)}
  {@const err = errors.deps[dep.key]}
  <div class="card bg-base-200" data-testid={'dep-' + dep.port}>
    <div class="card-body p-3 gap-2">
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-medium">{dep.label}</span>
        <span class="badge badge-ghost badge-sm">{dep.type}</span>
        {#if !dep.optional}<span class="badge badge-warning badge-sm">обязательно</span>{/if}
      </div>
      {#if !catalog}
        <div class="flex items-center gap-2 text-sm opacity-70"><span class="loading loading-spinner loading-xs"></span> Ищем подходящих поставщиков…</div>
      {:else}
        <div class="grid gap-1">
          {#each ex as p (p.instance + ':' + p.port)}
            {@const st = instanceStatusInfo(p.status)}
            <label class="flex items-start gap-2 text-sm cursor-pointer rounded p-1 hover:bg-base-300/50 {p.disabled ? 'opacity-50 cursor-not-allowed' : ''}" title={p.reason}>
              <input type="radio" class="radio radio-sm mt-0.5" name={dep.key} value={`e|${p.instance}|${p.port}`} checked={valueOf(dep) === `e|${p.instance}|${p.port}`} disabled={p.disabled || disabled} onchange={() => pick(dep, `e|${p.instance}|${p.port}`)} data-testid="dep-existing" />
              <span class="grid">
                <span>{p.name} <span class="opacity-60">· {p.pluginName}{p.label ? ' · ' + p.label : ''}</span></span>
                <span class="text-xs opacity-70">{p.controller ? 'на сервере Hestia' : p.hostIP ? 'на ' + p.hostIP : 'без сервера'} · <span class="badge badge-xs {st.cls}">{st.label}</span>{#if p.reason} · {p.reason}{/if}</span>
              </span>
            </label>
          {/each}
          {#each of as o (o.pluginId)}
            <label class="flex items-start gap-2 text-sm cursor-pointer rounded p-1 hover:bg-base-300/50 {o.reason ? 'opacity-50 cursor-not-allowed' : ''}" title={o.reason}>
              <input type="radio" class="radio radio-sm mt-0.5" name={dep.key} value={`n|${o.pluginId}`} checked={valueOf(dep) === `n|${o.pluginId}`} disabled={!!o.reason || disabled || busy} onchange={() => pick(dep, `n|${o.pluginId}`)} data-testid="dep-new" />
              <span class="grid">
                <span class="flex items-center gap-1"><Plus size={14} /> Создать новый «{o.name}»</span>
                {#if o.reason}<span class="text-xs opacity-70">{o.reason}</span>{/if}
              </span>
            </label>
          {/each}
          {#if dep.optional}
            <label class="flex items-center gap-2 text-sm cursor-pointer rounded p-1 hover:bg-base-300/50">
              <input type="radio" class="radio radio-sm" name={dep.key} value="none" checked={valueOf(dep) === 'none'} disabled={disabled} onchange={() => pick(dep, 'none')} />
              <span>Не подключать</span>
            </label>
          {/if}
        </div>
        {#if ex.length === 0 && of.length === 0}
          <div class="text-sm opacity-80" data-testid="dep-nothing">
            Нет экземпляров и установленных плагинов, которые предоставляют «{dep.type}».
            <a class="link" href="#/plugins" data-testid="dep-catalog">Установить из каталога</a>
          </div>
        {/if}
      {/if}
      {#if dep.choice?.kind === 'new'}
        <div class="flex flex-wrap items-center gap-2 text-sm bg-base-100 rounded p-2" data-testid="dep-new-summary">
          <span>Будет создан: <span class="font-medium">{dep.choice.node.name || dep.choice.node.pluginName}</span></span>
          <button class="btn btn-xs ml-auto" onclick={() => onopen?.(dep)} {disabled} data-testid="dep-open"><Settings size={12} /> Настроить</button>
        </div>
      {/if}
      {#if err}<span class="text-error text-xs flex items-center gap-1" data-testid="dep-error"><TriangleAlert size={12} /> {err}</span>{/if}
    </div>
  </div>
{/snippet}

<div class="grid gap-3" data-testid="deps-step">
  <p class="text-sm opacity-80">«{node.name || node.pluginName}» подключается к другим сервисам. Выберите, к каким именно, или создайте новые — всё применится одним планом.</p>
  {#if errors.nodeDeps}<div class="alert alert-warning text-sm" role="alert"><TriangleAlert size={16} /> {errors.nodeDeps}</div>{/if}
  {#each required as dep (dep.key)}{@render slot(dep)}{/each}
  {#if optional.length}
    <div class="collapse collapse-arrow bg-base-200" class:collapse-open={showOptional}>
      <button type="button" class="collapse-title text-sm font-medium min-h-0 py-2 text-left" onclick={() => (showOptional = !showOptional)} aria-expanded={showOptional}>Подробнее</button>
      {#if showOptional}
        <div class="collapse-content grid gap-3">
          {#each optional as dep (dep.key)}{@render slot(dep)}{/each}
        </div>
      {/if}
    </div>
  {/if}
</div>
