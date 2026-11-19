<script>
  import { api } from '../lib/api.js';
  import PluginCard from '../components/PluginCard.svelte';
  import PluginInstall from '../components/PluginInstall.svelte';
  import PluginCatalog from '../components/PluginCatalog.svelte';
  import { Upload, Puzzle } from 'lucide-svelte';

  let view = $state(null); // GET /plugins
  let error = $state('');
  let tab = $state('installed'); // installed | catalog
  let installing = $state(false);
  let catalogId = $state(''); // install/update from the catalog
  let catalogKey = $state(0); // remount the catalog after an install

  function load() {
    return api
      .plugins()
      .then((v) => {
        view = v;
        error = '';
      })
      .catch((e) => (error = e.message));
  }

  $effect(() => {
    load();
  });

  const plugins = $derived(view?.plugins || []);
  const available = $derived(view ? view.available !== false : false);
</script>

<div class="flex flex-wrap items-center gap-3 mb-4">
  <h1 class="text-2xl font-bold flex-1">Плагины</h1>
  {#if available}
    <button class="btn btn-primary btn-sm" onclick={() => (installing = true)} data-testid="plugin-install-open"><Upload size={16} /> Установить из файла/ссылки</button>
  {/if}
</div>

{#if error}<div class="alert alert-error mb-4" role="alert">{error}</div>{/if}
{#if view && !available}
  <div class="alert alert-info mb-4" role="status" data-testid="plugins-unavailable">{view.reason || 'Плагины сейчас недоступны.'}</div>
{/if}

<div role="tablist" class="tabs tabs-border mb-4">
  <button role="tab" class="tab" class:tab-active={tab === 'installed'} onclick={() => (tab = 'installed')}>Установленные</button>
  <button role="tab" class="tab" class:tab-active={tab === 'catalog'} onclick={() => (tab = 'catalog')} data-testid="tab-catalog">Каталог</button>
</div>

{#if tab === 'catalog'}
  {#key catalogKey}
    <PluginCatalog {available} oninstall={(id) => (catalogId = id)} />
  {/key}
{:else if !view && !error}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if view && plugins.length === 0}
  <div class="opacity-70 py-8 text-center grid justify-items-center gap-2" data-testid="plugins-empty">
    <Puzzle size={36} />
    <span>Плагинов пока нет.{#if available} Установите плагин из файла или по ссылке.{/if}</span>
  </div>
{:else}
  <div class="grid gap-3">
    {#each plugins as p (p.id)}
      <PluginCard plugin={p} onchanged={load} />
    {/each}
  </div>
{/if}

{#if installing}
  <PluginInstall onchanged={load} onclose={(changed) => ((installing = false), changed && load())} />
{/if}
{#if catalogId}
  {#key catalogId}
    <PluginInstall catalogId={catalogId} onchanged={load} onclose={(changed) => ((catalogId = ''), changed && (load(), catalogKey++))} />
  {/key}
{/if}
