<script>
  import { api } from '../lib/api.js';
  import { fmtTime } from '../lib/jobs.js';
  import { instanceStatusInfo, safeUrl } from '../lib/plugins.js';
  import PluginCard from '../components/PluginCard.svelte';
  import InstanceWizard from '../components/InstanceWizard.svelte';
  import LinkDialog from '../components/LinkDialog.svelte';
  import { linkStatusInfo, linkSides } from '../lib/linkpanel.js';
  import { linksOfInstance, instanceById } from '../lib/mapgraph.js';
  import { ArrowLeft, Plus, Pencil, Trash2, ExternalLink, RefreshCw, Link2 } from 'lucide-svelte';

  let { id } = $props();

  let plugin = $state(null); // GET /plugins/{id} (+ unit)
  let error = $state('');
  let instances = $state(null);
  let instError = $state('');
  let refreshing = $state({}); // instance id → status refresh in flight
  let wizard = $state(null); // {mode, instance}
  let graph = $state(null); // GET /graph: the links of the instances
  let linkDlg = $state(null); // {mode: 'new', instanceId} | {mode: 'remove', link}

  function loadGraph() {
    return api
      .graph()
      .then((g) => (graph = g))
      .catch(() => {});
  }

  function loadPlugin() {
    return api
      .plugin(id)
      .then((p) => {
        plugin = { ...p, unit: plugin?.unit ?? p.unit };
        error = '';
        // The unit state is slower (systemctl); it comes separately and only for non-dev plugins.
        if (!p.dev) {
          api
            .plugin(id, true)
            .then((u) => {
              if (plugin && plugin.id === u.id) plugin = { ...plugin, unit: u.unit };
            })
            .catch(() => {});
        }
      })
      .catch((e) => (error = e.status === 404 ? 'Плагин не найден' : e.message));
  }

  // Each instance asks the plugin for its live status, without blocking the page.
  function refreshStatus(inst) {
    refreshing = { ...refreshing, [inst.id]: true };
    api
      .pluginInstance(inst.id, true)
      .then((fresh) => {
        if (instances) instances = instances.map((x) => (x.id === fresh.id ? fresh : x));
      })
      .catch(() => {})
      .finally(() => {
        const rest = { ...refreshing };
        delete rest[inst.id];
        refreshing = rest;
      });
  }

  function loadInstances(refresh = false) {
    return api
      .pluginInstances(id)
      .then((r) => {
        instances = r.instances || [];
        instError = '';
        if (refresh) for (const i of instances) refreshStatus(i);
      })
      .catch((e) => (instError = e.message));
  }

  $effect(() => {
    loadPlugin();
    loadInstances(true);
    loadGraph();
  });

  function changed(kind) {
    if (kind === 'remove') location.hash = '#/plugins';
    else loadPlugin();
  }

  function afterApply() {
    loadInstances(true);
    loadPlugin();
    loadGraph();
  }

  const canManage = $derived(!!plugin && plugin.enabled && plugin.state === 'connected');
  const canCreate = $derived(canManage && (plugin.multi_instance || (instances?.length ?? 0) === 0));
</script>

<a href="#/plugins" class="btn btn-ghost btn-sm mb-4"><ArrowLeft size={16} /> К плагинам</a>

{#if error}
  <div class="alert alert-error" role="alert">{error}</div>
{:else if !plugin}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  <PluginCard {plugin} link={false} onchanged={changed} />

  <div class="flex flex-wrap items-center gap-3 mt-6 mb-3">
    <h2 class="text-xl font-semibold flex-1">Экземпляры</h2>
    <button class="btn btn-primary btn-sm" onclick={() => (wizard = { mode: 'create', instance: null })} disabled={!canCreate} data-testid="instance-create"><Plus size={16} /> Создать</button>
  </div>
  {#if !canManage}
    <p class="text-sm opacity-70 mb-3">Плагин не работает — создавать и менять экземпляры можно, когда он включён и на связи.</p>
  {:else if !canCreate}
    <p class="text-sm opacity-70 mb-3">Этот плагин поддерживает только один экземпляр.</p>
  {/if}
  {#if instError}<div class="alert alert-error mb-3" role="alert">{instError}</div>{/if}

  {#if instances === null && !instError}
    <div class="flex justify-center py-6"><span class="loading loading-spinner"></span></div>
  {:else if instances?.length === 0}
    <p class="opacity-70 py-4" data-testid="instances-empty">Экземпляров пока нет.</p>
  {:else if instances}
    <div class="grid gap-2" data-testid="instances">
      {#each instances as inst (inst.id)}
        {@const st = instanceStatusInfo(inst.status)}
        <div class="card bg-base-200" data-testid="instance">
          <div class="card-body p-3 gap-1">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-semibold">{inst.name}</span>
              <span class="badge badge-sm {st.cls}" data-testid="instance-status">{st.label}</span>
              {#if refreshing[inst.id]}<span class="loading loading-spinner loading-xs" title="Проверяем состояние"></span>{/if}
              <span class="flex-1"></span>
              <button class="btn btn-ghost btn-xs" onclick={() => refreshStatus(inst)} disabled={!!refreshing[inst.id]} title="Проверить состояние"><RefreshCw size={14} /></button>
              <button class="btn btn-xs" onclick={() => (wizard = { mode: 'update', instance: inst })} disabled={!canManage} data-testid="instance-edit"><Pencil size={14} /> Изменить</button>
              <button class="btn btn-xs btn-ghost text-error" onclick={() => (wizard = { mode: 'remove', instance: inst })} disabled={!canManage} data-testid="instance-remove"><Trash2 size={14} /> Удалить</button>
            </div>
            {#if inst.detail}<div class="text-sm opacity-80 whitespace-pre-wrap break-words">{inst.detail}</div>{/if}
            {#if inst.endpoints?.length}
              <div class="flex flex-wrap gap-3 text-sm">
                {#each inst.endpoints as ep, i (i)}
                  {@const href = safeUrl(ep.url)}
                  {#if href}
                    <a class="link inline-flex items-center gap-1" {href} target="_blank" rel="noopener noreferrer">{ep.name || ep.url} <ExternalLink size={12} /></a>
                  {:else}
                    <span class="font-mono text-xs opacity-70">{ep.name ? ep.name + ': ' : ''}{ep.url}</span>
                  {/if}
                {/each}
              </div>
            {/if}
            <div class="text-xs opacity-60">Проверено: {fmtTime(inst.checked_at)} · Создан: {fmtTime(inst.created_at)}</div>
            {#if graph}
              {@const gi = instanceById(graph, inst.id)}
              {@const links = linksOfInstance(graph, inst.id)}
              {#if gi && (gi.provides.length || gi.requires.length || links.length)}
                <div class="grid gap-1 mt-1 border-t border-base-300 pt-2" data-testid="instance-links">
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-semibold">Связи</span>
                    <span class="flex-1"></span>
                    <button class="btn btn-xs" onclick={() => (linkDlg = { mode: 'new', instanceId: inst.id })} disabled={!canManage} data-testid="link-new"><Link2 size={14} /> Связать…</button>
                  </div>
                  {#if links.length === 0}
                    <span class="text-xs opacity-70">Связей нет.</span>
                  {/if}
                  {#each links as l (l.id)}
                    {@const s = linkSides(l)}
                    {@const ls = linkStatusInfo(l.status)}
                    <div class="flex flex-wrap items-center gap-2 text-sm" data-testid="link-row">
                      <span class="badge badge-sm {ls.cls}" data-testid="link-row-status">{ls.label}</span>
                      <span class="break-words min-w-0">{s.provider} → {s.consumer}</span>
                      {#if l.detail}<span class="text-xs opacity-70 break-words">{l.detail}</span>{/if}
                      <span class="flex-1"></span>
                      <button class="btn btn-ghost btn-xs text-error" onclick={() => (linkDlg = { mode: 'remove', link: l })} disabled={!canManage} data-testid="link-row-remove"><Trash2 size={12} /> {l.status === 'orphaned' ? 'Удалить запись' : 'Удалить'}</button>
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}

  {#if plugin.readme}
    <h2 class="text-xl font-semibold mt-6 mb-2">Описание</h2>
    <!-- Markdown is shown as plain text: plugin content never becomes HTML. -->
    <div class="bg-base-200 rounded-box p-4 text-sm whitespace-pre-wrap break-words font-mono" data-testid="plugin-readme">{plugin.readme}</div>
  {/if}
{/if}

{#if wizard && plugin}
  <InstanceWizard {plugin} instance={wizard.instance} mode={wizard.mode} instances={instances || []} onchanged={afterApply} onclose={(c) => ((wizard = null), c && afterApply())} />
{/if}

{#if linkDlg}
  {#key linkDlg}
    <LinkDialog {graph} mode={linkDlg.mode} instanceId={linkDlg.instanceId || 0} link={linkDlg.link || null} onchanged={afterApply} onclose={(c) => ((linkDlg = null), c && afterApply())} />
  {/key}
{/if}
