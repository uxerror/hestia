<script>
  import { api } from '../lib/api.js';
  import { fmtBytes } from '../lib/format.js';
  import { catalogAction, catalogStatus, permissionLabel, capabilityText } from '../lib/plugins.js';
  import { RefreshCw, TriangleAlert, Download, ArrowUpCircle, Check, Puzzle } from 'lucide-svelte';

  // The official catalog: GET /plugins/catalog (cache), «Обновить» asks
  // GitHub now. oninstall(id) opens the install dialog for an entry.
  let { available = false, oninstall } = $props();

  let view = $state(null);
  let error = $state('');
  let refreshing = $state(false);

  function load() {
    return api
      .pluginCatalog()
      .then((v) => ((view = v), (error = '')))
      .catch((e) => (error = e.message));
  }

  async function refresh() {
    refreshing = true;
    try {
      view = await api.refreshPluginCatalog();
      error = '';
    } catch (e) {
      error = e.message;
    } finally {
      refreshing = false;
    }
  }

  $effect(() => {
    load();
  });

  const status = $derived(catalogStatus(view));
  const items = $derived(view?.plugins || []);
</script>

<div class="grid gap-3" data-testid="plugins-catalog">
  <div class="flex flex-wrap items-center gap-2 text-sm">
    <span class="opacity-70 flex-1" data-testid="catalog-status">Официальные плагины Hestia. {status.text}</span>
    <button class="btn btn-sm" onclick={refresh} disabled={refreshing} data-testid="catalog-refresh">
      {#if refreshing}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={14} />{/if} Проверить сейчас
    </button>
  </div>

  {#if error}<div class="alert alert-error text-sm" role="alert"><TriangleAlert size={16} /> {error}</div>{/if}
  {#if status.error}<div class="alert alert-warning text-sm" role="alert" data-testid="catalog-error"><TriangleAlert size={16} /> {status.error}</div>{/if}

  {#if !view && !error}
    <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
  {:else if view && items.length === 0}
    <div class="opacity-70 py-8 text-center grid justify-items-center gap-2" data-testid="catalog-empty">
      <Puzzle size={36} />
      <span>{view.fetched_at ? 'В каталоге пока нет плагинов.' : 'Каталог ещё не загружен — нажмите «Проверить сейчас».'}</span>
    </div>
  {:else}
    {#each items as it (it.id)}
      {@const act = catalogAction(it)}
      <div class="card bg-base-200" data-testid="catalog-item">
        <div class="card-body p-4 gap-2">
          <div class="flex flex-wrap items-start gap-3">
            <div class="flex-1 min-w-0 grid gap-1">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-semibold text-lg">{it.name}</span>
                <span class="badge badge-ghost badge-sm">{it.version}</span>
                <span class="badge badge-success badge-xs">Официальный</span>
                <span class="font-mono text-xs opacity-60">{it.id}</span>
              </div>
              {#if it.description}<p class="text-sm opacity-80">{it.description}</p>{/if}
              <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs opacity-70">
                {#if it.provides?.length}<span>Предоставляет: {it.provides.map(capabilityText).join(', ')}</span>{/if}
                <span>Размер: {fmtBytes(it.size)}</span>
                {#if it.min_hestia}<span>Нужна Hestia {it.min_hestia}+</span>{/if}
              </div>
              {#if it.permissions?.length}
                <div class="text-xs opacity-70">Права: {it.permissions.map(permissionLabel).join('; ')}</div>
              {/if}
              {#if act.kind === 'update' && it.new_permissions?.length}
                <div class="text-xs text-warning">Новые права: {it.new_permissions.map(permissionLabel).join('; ')}</div>
              {/if}
            </div>
            <div class="flex items-center gap-2">
              {#if act.kind === 'install'}
                <button class="btn btn-sm btn-primary" disabled={!available} onclick={() => oninstall?.(it.id)} data-testid="catalog-install"><Download size={14} /> {act.label}</button>
              {:else if act.kind === 'update'}
                <button class="btn btn-sm btn-info" disabled={!available} onclick={() => oninstall?.(it.id)} data-testid="catalog-update"><ArrowUpCircle size={14} /> {act.label}</button>
              {:else if act.kind === 'installed'}
                <span class="badge badge-success gap-1"><Check size={12} /> {act.label}</span>
              {:else if act.kind === 'incompatible'}
                <span class="text-xs text-warning max-w-xs">{act.label}</span>
              {/if}
            </div>
          </div>
        </div>
      </div>
    {/each}
  {/if}
</div>
