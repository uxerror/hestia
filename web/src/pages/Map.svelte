<script>
  import { SvelteFlow, Background, Controls, MiniMap } from '@xyflow/svelte';
  import '@xyflow/svelte/dist/style.css';
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { isFinal, fmtTime } from '../lib/jobs.js';
  import { defaultFilters, hostByNodeId, untilText } from '../lib/netmap.js';
  import { buildMapGraph, parseNodeId, linkById, instanceById, linksOfInstance, linkEdgeId } from '../lib/mapgraph.js';
  import { layoutGraph } from '../lib/layout.js';
  import { mergePositions, dragged, savedCount, PositionSaver } from '../lib/positions.js';
  import { compatibility, mergeCandidates, dragOrigin, resolveConnection, connectionAllowed } from '../lib/compat.js';
  import FlowNode from '../components/FlowNode.svelte';
  import InstNode from '../components/InstNode.svelte';
  import LinkEdge from '../components/LinkEdge.svelte';
  import HostPanel from '../components/HostPanel.svelte';
  import InstancePanel from '../components/InstancePanel.svelte';
  import LinkPanel from '../components/LinkPanel.svelte';
  import NewLink from '../components/NewLink.svelte';
  import ScanSettings from '../components/ScanSettings.svelte';
  import { Radar, Search, Square, Settings, LayoutGrid } from 'lucide-svelte';
  import { untrack, setContext, onDestroy } from 'svelte';

  const nodeTypes = { host: FlowNode, chost: FlowNode, net: FlowNode, group: FlowNode, inst: InstNode };
  const edgeTypes = { link: LinkEdge };
  const fitViewOptions = { padding: 0.1 };

  // The drag of a link: the compatible handles and hosts light up (read by the nodes).
  const drag = $state({ compat: null });
  setContext('mapdrag', drag);
  setContext('maplink', (id) => {
    if (id) selectEdge({ id: linkEdgeId(id) });
  });
  let dragSeq = 0;

  let view = $state(null);
  let graph = $state(null); // GET /graph (null: no plugins — the plain map)
  let error = $state('');
  let starting = $state(false);
  let filters = $state(defaultFilters());
  let job = $state(null); // live state of the running scan job
  let now = $state(Date.now());
  let nodes = $state.raw([]);
  let edges = $state.raw([]);

  let positions = $state({}); // positions the user gave to nodes (saved on the server)
  let sel = $state(null); // {kind: 'host'|'instance'|'link', id}
  let newLink = $state(null); // {own, peer, key}
  let confirmReset = $state(false);
  let snapLink = $state(null); // the link of the open panel (stays while its removal job shows)
  let snapInst = $state(null);

  const saver = new PositionSaver((p) => api.saveGraphPositions(p), { onError: (e) => (error = 'Не удалось сохранить позиции: ' + e.message) });
  onDestroy(() => saver.flush());

  async function load() {
    try {
      const [v, g] = await Promise.all([api.network(), api.graph().catch(() => null)]);
      view = v;
      graph = g;
      positions = { ...(g?.positions || {}), ...saver.pending };
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

  const built = $derived(view ? buildMapGraph(view, graph, filters) : { nodes: [], edges: [], linkEdges: [], counts: { total: 0, shown: 0, alive: 0, instances: 0 } });
  const laidOut = $derived(layoutGraph(built.nodes, built.edges));
  // The user's positions win over the automatic ones.
  const placed = $derived(mergePositions(laidOut, positions));
  // A new layout needs a new viewport fit: the flow is rebuilt when the set of nodes changes.
  const flowKey = $derived(laidOut.map((n) => n.id).join('|'));
  const selNodeId = $derived(sel ? (sel.kind === 'host' ? 'h:' + sel.id : sel.kind === 'instance' ? 'i:' + sel.id : '') : '');
  $effect(() => {
    const id = selNodeId;
    nodes = placed.map((n) => ({ ...n, selected: n.id === id, draggable: n.type !== 'inst' }));
  });
  $effect(() => {
    const id = sel?.kind === 'link' ? linkEdgeId(sel.id) : '';
    edges = [...built.edges, ...built.linkEdges.map((e) => ({ ...e, selected: e.id === id }))];
  });

  const selectedHost = $derived(sel?.kind === 'host' ? hostByNodeId(view, 'h:' + sel.id) : null);
  const selLink = $derived(sel?.kind === 'link' ? linkById(graph, sel.id) : null);
  const selInst = $derived(sel?.kind === 'instance' ? instanceById(graph, sel.id) : null);
  $effect(() => {
    if (selLink) snapLink = selLink;
    if (selInst) snapInst = selInst;
  });
  const shownLink = $derived(selLink || (sel?.kind === 'link' && snapLink?.id === sel.id ? snapLink : null));
  const shownInst = $derived(selInst || (sel?.kind === 'instance' && snapInst?.id === sel.id ? snapInst : null));
  $effect(() => {
    // A host that vanished (forgotten, filtered out) closes its panel.
    if (sel?.kind === 'host' && !selectedHost) sel = null;
    if (sel?.kind === 'instance' && !shownInst) sel = null;
    if (sel?.kind === 'link' && !shownLink) sel = null;
  });

  async function forget() {
    if (!selectedHost) return;
    try {
      await api.forgetHost(selectedHost.ip);
      sel = null;
      await load();
    } catch (e) {
      error = e.message;
    }
  }

  function selectNode(id) {
    const p = parseNodeId(id);
    newLink = null;
    sel = p && (p.kind === 'host' || p.kind === 'instance') ? p : null;
  }
  function selectEdge(edge) {
    const p = parseNodeId(edge?.id);
    if (p?.kind !== 'link') return;
    newLink = null;
    sel = p;
  }
  function closePanel() {
    sel = null;
    newLink = null;
  }

  // Dragging a link from a port: highlight what it fits, refine with the server's candidates.
  function connectStart(_e, params) {
    const origin = dragOrigin(params?.nodeId, params?.handleId);
    if (!origin || !graph) return;
    const base = compatibility(graph, origin);
    drag.compat = base;
    const seq = ++dragSeq;
    api
      .linkCandidates(origin.instance, origin.port, origin.dir)
      .then((c) => {
        if (seq === dragSeq && drag.compat) drag.compat = mergeCandidates(base, c, graph);
      })
      .catch(() => {});
  }
  function connectEnd() {
    dragSeq++;
    drag.compat = null;
  }
  const validConnection = (conn) => connectionAllowed(drag.compat, resolveConnection(graph, conn));
  function connected(conn) {
    const r = resolveConnection(graph, conn);
    const from = drag.compat?.from;
    if (!r || !from || !connectionAllowed(drag.compat, r)) return;
    let peer;
    if (r.kind === 'device') peer = { kind: 'device', ref: r.device.ref };
    else peer = from.dir === 'provides' ? { kind: 'port', ...r.consumer } : { kind: 'port', ...r.provider };
    sel = null;
    newLink = { own: from, peer, key: Date.now() };
  }

  // Moving a host or a box saves its position a second after the last move.
  function nodeDragStop({ targetNode, nodes: moved }) {
    const list = moved?.length ? moved : targetNode ? [targetNode] : [];
    const p = dragged(list);
    if (!Object.keys(p).length) return;
    positions = { ...positions, ...p };
    saver.move(p);
  }
  async function resetLayout() {
    confirmReset = false;
    saver.cancel();
    try {
      await api.resetGraphPositions();
      positions = {};
    } catch (e) {
      error = e.message;
    }
  }
  const moved = $derived(savedCount(laidOut, positions));
  const hasPanel = $derived(!!(newLink || selectedHost || shownLink || shownInst));
  const mapHasContent = $derived(!!view && (view.hosts.length > 0 || (graph?.instances?.length ?? 0) > 0));

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
    <span class="text-xs opacity-70">Показано {built.counts.shown} из {built.counts.total}, отвечают {built.counts.alive}{#if built.counts.instances}, экземпляров плагинов {built.counts.instances}{/if}</span>
    {#if moved > 0}
      {#if confirmReset}
        <span class="flex items-center gap-1 text-sm ml-auto">Сбросить расположение узлов?
          <button class="btn btn-error btn-xs" onclick={resetLayout} data-testid="reset-layout-yes">Да</button>
          <button class="btn btn-ghost btn-xs" onclick={() => (confirmReset = false)}>Нет</button>
        </span>
      {:else}
        <button class="btn btn-ghost btn-sm ml-auto" onclick={() => (confirmReset = true)} data-testid="reset-layout"><LayoutGrid size={14} /> Разложить заново</button>
      {/if}
    {/if}
    <button class="btn btn-ghost btn-sm {moved > 0 ? '' : 'ml-auto'}" onclick={() => (showSettings = !showSettings)} aria-expanded={showSettings}><Settings size={14} /> Настройки сканирования</button>
  </div>

  {#if showSettings}
    <div class="card bg-base-200 p-4 mb-3"><ScanSettings {view} onsaved={load} /></div>
  {/if}

  {#if !mapHasContent}
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
            {edgeTypes}
            fitView
            {fitViewOptions}
            minZoom={0.2}
            nodesDraggable={true}
            nodesConnectable={true}
            connectionRadius={28}
            elementsSelectable={true}
            deleteKey={null}
            isValidConnection={validConnection}
            onconnectstart={connectStart}
            onconnectend={connectEnd}
            onconnect={connected}
            onnodedragstop={nodeDragStop}
            onnodeclick={({ node }) => selectNode(node.id)}
            onedgeclick={({ edge }) => selectEdge(edge)}
            onpaneclick={closePanel}
            colorMode="system"
          >
            <Background />
            <Controls showLock={false} />
            <MiniMap pannable zoomable />
          </SvelteFlow>
        {/key}
      </div>
      {#if hasPanel}
        <!-- ~360 px on the right; on a narrow window it lies over the map -->
        <div class="absolute inset-y-0 right-0 z-10 w-[min(360px,100%)] overflow-y-auto shadow-xl lg:static lg:z-auto lg:w-[360px] lg:shrink-0 lg:shadow-none" data-testid="host-drawer">
          {#if newLink}
            {#key newLink.key}
              <NewLink {graph} own={newLink.own} peer={newLink.peer} onclose={closePanel} onchanged={load} />
            {/key}
          {:else if shownLink}
            <LinkPanel link={shownLink} onclose={closePanel} onchanged={load} />
          {:else if shownInst}
            <InstancePanel instance={shownInst} links={linksOfInstance(graph, shownInst.id)} onclose={closePanel} onselectlink={(id) => (sel = { kind: 'link', id })} />
          {:else if selectedHost}
            <HostPanel host={selectedHost} onclose={closePanel} onforget={forget} />
          {/if}
        </div>
      {/if}
    </div>
  {/if}
{/if}
</div>
