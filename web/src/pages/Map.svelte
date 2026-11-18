<script>
  import { SvelteFlow, Background, Controls, MiniMap } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { isFinal, fmtTime } from '../lib/jobs.js';
  import { buildGraph, defaultFilters, hostByNodeId, untilText } from '../lib/netmap.js';
  import { layoutGraph } from '../lib/layout.js';
  import FlowNode from '../components/FlowNode.svelte';
  import HostPanel from '../components/HostPanel.svelte';
  import ScanSettings from '../components/ScanSettings.svelte';
  import { Radar, Search, Square, Settings } from 'lucide-svelte';
  import { untrack } from 'svelte';

  const nodeTypes = { host: FlowNode, net: FlowNode, group: FlowNode };
  const fitViewOptions = { padding: 0.1 };

  let view = $state(null);
  let error = $state('');
  let starting = $state(false);
  let filters = $state(defaultFilters());
  let selectedId = $state('');
  let job = $state(null); // live state of the running scan job
  let now = $state(Date.now());
  let nodes = $state.raw([]);
  let edges = $state.raw([]);

  async function load() {
    try {
      view = await api.network();
      error = '';
    } catch (e) {
      error = e.message;
    }
  }

  // Load, then keep fresh: every 30 s, every 3 s while a scan runs; one clock for "через …".
  $effect(() => {
    load();
    const t = setInterval(() => {
      now = Date.now();
    }, 1000);
    return () => clearInterval(t);
  });
  $effect(() => {
    const ms = view?.scanning ? 3000 : 30000;
    const t = setInterval(load, ms);
    return () => clearInterval(t);
  });

  // Follow the scan job: current step and last log line.
  $effect(() => {
    const id = view?.scanning ? view.job_id : '';
    if (!id) {
      job = null;
      return;
    }
    return subscribeJob(id, {
      onUpdate: (j) => {
        job = j;
        if (isFinal(j.status)) load();
      },
    });
  });

  async function scan() {
    starting = true;
    try {
      await api.scanNetwork();
      error = '';
    } catch (e) {
      error = e.message;
    } finally {
      starting = false;
      load();
    }
  }
  async function stop() {
    try {
      await api.cancelScan();
    } catch (e) {
      error = e.message;
    }
    load();
  }

  const graph = $derived(view ? buildGraph(view, filters) : { nodes: [], edges: [], counts: { total: 0, shown: 0, alive: 0 } });
  const laidOut = $derived(layoutGraph(graph.nodes, graph.edges));
  // A new layout needs a new viewport fit: the flow is rebuilt when the set of nodes changes.
  const flowKey = $derived(laidOut.map((n) => n.id).join('|'));
  $effect(() => {
    const sel = untrack(() => selectedId);
    nodes = laidOut.map((n) => ({ ...n, selected: n.id === sel }));
    edges = graph.edges;
  });

  const selected = $derived(hostByNodeId(view, selectedId));
  $effect(() => {
    if (selectedId && !selected) selectedId = '';
  });

  async function forget() {
    if (!selected) return;
    try {
      await api.forgetHost(selected.ip);
      selectedId = '';
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  const step = $derived(job?.steps?.length ? job.steps[job.steps.length - 1].title : '');
  const lastLog = $derived(job?.log?.length ? job.log[job.log.length - 1].line : '');
  let showSettings = $state(false);
</script>

<div class="flex flex-col h-[calc(100vh-4rem-1.5rem)] min-h-[420px]" data-testid="map-page">
<div class="flex flex-wrap items-center justify-between gap-2 mb-2">
  <h1 class="text-2xl font-bold">Карта сети</h1>
  <div class="flex items-center gap-2">
    <span class="text-xs opacity-70" data-testid="scan-state">
      {#if view?.scanning}
        Сканирование{step ? ': ' + step : ''}{lastLog ? ' — ' + lastLog : '…'}
      {:else if view?.last_scan?.finished_at}
        Скан: {fmtTime(view.last_scan.finished_at)}{view.last_scan.error ? ' (' + view.last_scan.error + ')' : ''}{#if view.next_scan_at} · следующий {untilText(view.next_scan_at, now)}{/if}
      {:else if view}
        Ещё не сканировалось{#if view.next_scan_at} · автозапуск {untilText(view.next_scan_at, now)}{/if}
      {/if}
    </span>
    {#if view?.scanning}
      <button class="btn btn-sm" onclick={stop}><Square size={14} /> Остановить</button>
    {/if}
    <button class="btn btn-sm btn-primary" onclick={scan} disabled={starting || view?.scanning} data-testid="scan">
      {#if view?.scanning}<span class="loading loading-spinner loading-xs"></span>{:else}<Radar size={16} />{/if}
      Сканировать
    </button>
  </div>
</div>

{#if error}<div class="alert alert-error mb-4" role="alert">{error}</div>{/if}

{#if !view}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  {#if view.last_scan?.error}
    <div class="alert alert-warning mb-4 text-sm" role="alert">Последний скан не завершён: {view.last_scan.error}</div>
  {/if}

  <div class="flex flex-wrap items-center gap-3 mb-2">
    <label class="input input-sm input-bordered flex items-center gap-2">
      <Search size={14} />
      <input type="search" placeholder="Имя, IP, MAC, сервис" bind:value={filters.query} data-testid="map-search" />
    </label>
    <label class="label cursor-pointer gap-2 text-sm"><input type="checkbox" class="checkbox checkbox-sm" bind:checked={filters.clients} data-testid="f-clients" /> клиенты</label>
    <label class="label cursor-pointer gap-2 text-sm"><input type="checkbox" class="checkbox checkbox-sm" bind:checked={filters.stopped} data-testid="f-stopped" /> остановленные и молчащие</label>
    <span class="text-xs opacity-70">Показано {graph.counts.shown} из {graph.counts.total}, отвечают {graph.counts.alive}</span>
    <button class="btn btn-ghost btn-sm ml-auto" onclick={() => (showSettings = !showSettings)} aria-expanded={showSettings}><Settings size={14} /> Настройки сканирования</button>
  </div>

  {#if showSettings}
    <div class="card bg-base-200 p-4 mb-3"><ScanSettings {view} onsaved={load} /></div>
  {/if}

  {#if view.hosts.length === 0}
    <div class="text-center py-16 opacity-80" data-testid="map-empty">
      {#if view.subnets.length === 0}
        Подсетей для сканирования нет. Подключите Proxmox или SSH-сервер (раздел «Подключение»), либо добавьте подсеть в настройках.
      {:else}
        Сеть ещё не сканировалась — нажмите «Сканировать».
      {/if}
    </div>
  {:else}
    <div class="relative flex-1 min-h-0 flex gap-3">
      <div class="flex-1 min-w-0 rounded-lg border border-base-300 bg-base-100" data-testid="map-flow">
        {#key flowKey}
          <SvelteFlow
            bind:nodes
            bind:edges
            {nodeTypes}
            fitView
            {fitViewOptions}
            minZoom={0.2}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={true}
            deleteKey={null}
            onnodeclick={({ node }) => (selectedId = node.id)}
            onpaneclick={() => (selectedId = '')}
            colorMode="system"
          >
            <Background />
            <Controls showLock={false} />
            <MiniMap pannable zoomable />
          </SvelteFlow>
        {/key}
      </div>
      {#if selected}
        <!-- ~360 px on the right; on a narrow window it lies over the map -->
        <div class="absolute inset-y-0 right-0 z-10 w-[min(360px,100%)] overflow-y-auto shadow-xl lg:static lg:z-auto lg:w-[360px] lg:shrink-0 lg:shadow-none" data-testid="host-drawer">
          <HostPanel host={selected} onclose={() => (selectedId = '')} onforget={forget} />
        </div>
      {/if}
    </div>
  {/if}
{/if}
</div>
