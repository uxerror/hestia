<script>
  import { untrack } from 'svelte';
  import { api } from '../lib/api.js';
  import { fmtTime } from '../lib/jobs.js';
  import { instanceStatusInfo, safeUrl } from '../lib/plugins.js';
  import { linkStatusInfo, linkSides } from '../lib/linkpanel.js';
  import { X, RefreshCw, ExternalLink, Box, Settings } from 'lucide-svelte';

  // Panel of an instance (a click on its card): status, endpoints, ports, containers, links
  // and the way to the plugin page. instance — an instance of GET /graph; links — its links.
  let { instance, links = [], onclose, onselectlink } = $props();

  let detail = $state(null); // GET /plugins/instances/{id}: endpoints, checked_at
  let busy = $state(false);
  let error = $state('');

  async function load(refresh) {
    busy = refresh;
    error = '';
    try {
      detail = await api.pluginInstance(instance.id, refresh);
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    instance.id;
    untrack(() => {
      detail = null;
      load(false);
    });
  });

  const cur = $derived(detail && detail.id === instance.id ? detail : null);
  const st = $derived(instanceStatusInfo(cur?.status || instance.status));
  const detailText = $derived(cur ? cur.detail : instance.detail);
</script>

<div class="card bg-base-200 h-full overflow-y-auto" data-testid="instance-panel">
  <div class="card-body p-4 gap-3">
    <div class="flex items-start justify-between gap-2">
      <div class="min-w-0">
        <h2 class="font-bold text-lg truncate">{instance.name}</h2>
        <div class="text-xs opacity-70">{instance.plugin_name || instance.plugin_id}</div>
      </div>
      <button class="btn btn-ghost btn-xs btn-circle" onclick={() => onclose?.()} aria-label="Закрыть"><X size={16} /></button>
    </div>

    <div class="flex flex-wrap items-center gap-2 text-sm">
      <span class="badge badge-sm {st.cls}" data-testid="instance-panel-status">{st.label}</span>
      <button class="btn btn-ghost btn-xs" onclick={() => load(true)} disabled={busy} title="Проверить состояние">
        {#if busy}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={14} />{/if}
      </button>
      {#if cur?.checked_at}<span class="text-xs opacity-60">Проверено: {fmtTime(cur.checked_at)}</span>{/if}
    </div>
    {#if detailText}<div class="text-sm whitespace-pre-wrap break-words opacity-80">{detailText}</div>{/if}
    {#if error}<div class="alert alert-warning text-sm" role="alert">{error}</div>{/if}

    {#if cur?.endpoints?.length}
      <div class="grid gap-1 text-sm" data-testid="instance-endpoints">
        <span class="font-semibold">Адреса</span>
        {#each cur.endpoints as ep, i (i)}
          {@const href = safeUrl(ep.url)}
          {#if href}
            <a class="link inline-flex items-center gap-1 break-all" {href} target="_blank" rel="noopener noreferrer">{ep.name || ep.url} <ExternalLink size={12} /></a>
          {:else}
            <span class="font-mono text-xs opacity-70 break-all">{ep.name ? ep.name + ': ' : ''}{ep.url}</span>
          {/if}
        {/each}
      </div>
    {/if}

    {#if instance.provides.length || instance.requires.length}
      <div class="grid gap-1 text-sm" data-testid="instance-ports">
        <span class="font-semibold">Порты</span>
        {#each instance.provides as p (p.name)}
          <div class="flex justify-between gap-2"><span>→ {p.label || p.name} <span class="opacity-60">({p.type})</span></span><span class="opacity-70">связей: {p.linked}</span></div>
        {/each}
        {#each instance.requires as p (p.name)}
          <div class="flex justify-between gap-2" class:text-error={!p.optional && !p.linked}>
            <span>← {p.label || p.name} <span class="opacity-60">({p.type})</span></span>
            <span>{p.linked ? `связей: ${p.linked}` : p.optional ? 'не подключён' : 'не подключён!'}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if instance.containers.length}
      <div class="grid gap-1 text-sm" data-testid="instance-containers">
        <span class="font-semibold">Контейнеры</span>
        {#each instance.containers as c (c.name)}
          <div class="flex items-center gap-1 min-w-0"><Box size={12} class={c.state === 'running' ? 'text-success shrink-0' : 'opacity-50 shrink-0'} /> <span class="truncate">{c.name}</span> <span class="opacity-60 text-xs truncate">{c.image} · {c.state}</span></div>
        {/each}
      </div>
    {/if}

    <div class="grid gap-1 text-sm" data-testid="instance-links">
      <span class="font-semibold">Связи</span>
      {#if links.length === 0}
        <span class="opacity-70">Связей нет. Потяните от порта экземпляра, чтобы создать.</span>
      {/if}
      {#each links as l (l.id)}
        {@const s = linkSides(l)}
        {@const ls = linkStatusInfo(l.status)}
        <button class="btn btn-ghost btn-sm justify-start h-auto py-1 text-left font-normal" onclick={() => onselectlink?.(l.id)}>
          <span class="badge badge-xs {ls.cls}"></span>
          <span class="truncate">{s.provider} → {s.consumer}</span>
        </button>
      {/each}
    </div>

    <a class="btn btn-sm" href={'#/plugins/' + encodeURIComponent(instance.plugin_id)} data-testid="instance-plugin-link"><Settings size={14} /> Страница плагина</a>
  </div>
</div>
