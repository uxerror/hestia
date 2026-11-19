<script>
  // An instance of a plugin inside a host of the map: name, status frame, `requires` ports on the
  // left, `provides` ports on the right (handles), the rows of its containers.
  import { Handle, Position } from '@xyflow/svelte';
  import { getContext } from 'svelte';
  import { instanceStatusInfo } from '../lib/plugins.js';
  import { statusColor } from '../lib/mapgraph.js';
  import { handleMark } from '../lib/compat.js';
  import { INST, portY, containerRows } from '../lib/layout.js';
  import { Puzzle, Box } from 'lucide-svelte';

  let { data, selected = false } = $props();
  // Shared drag state of the map: {compat} while a link is dragged.
  const drag = getContext('mapdrag');

  const st = $derived(instanceStatusInfo(data.status));
  const rows = $derived(Math.max(data.provides.length, data.requires.length));
  const shown = $derived(data.containers.slice(0, INST.maxCont));
  const hidden = $derived(data.containers.length - shown.length);
  const contTop = $derived(INST.head + rows * INST.row + 6);
  let iconFailed = $state(false);

  // Handle look by the drag: the compatible ones glow, the others fade.
  const HANDLE = {
    source: '!bg-primary !ring-4 !ring-primary/40',
    ok: '!bg-success !ring-4 !ring-success/50 scale-150',
    blocked: '!bg-warning !opacity-60',
    dim: '!opacity-20',
    '': '',
  };
  const mark = (dir, port) => handleMark(drag?.compat, dir, data.id, port);
</script>

<div
  class="rounded-md border-2 bg-base-100 shadow-sm overflow-hidden relative {selected ? 'ring-2 ring-primary' : ''}"
  style="width:{INST.w}px;height:{INST.head + rows * INST.row + (containerRows(data.containers) ? 6 + containerRows(data.containers) * INST.cont : 0) + INST.pad}px;border-color:{statusColor(data.status)}"
  title="{data.label} · {st.label}{data.detail ? ' · ' + data.detail : ''}"
  data-testid="instance-node"
  data-status={data.status}
>
  <div class="flex items-center gap-1.5 px-2 pt-1 h-[44px] min-w-0">
    <div class="size-6 shrink-0 rounded bg-base-200 flex items-center justify-center overflow-hidden">
      {#if data.iconUrl && !iconFailed}
        <img src={data.iconUrl} alt="" class="size-5" onerror={() => (iconFailed = true)} />
      {:else}
        <Puzzle size={14} class="opacity-60" />
      {/if}
    </div>
    <div class="min-w-0 leading-tight">
      <div class="text-sm font-medium truncate">{data.label}</div>
      <div class="text-[10px] opacity-70 truncate">{data.plugin} · {st.label}</div>
    </div>
  </div>

  {#each { length: rows } as _, i (i)}
    {@const req = data.requires[i]}
    {@const prov = data.provides[i]}
    <div class="absolute left-0 right-0 flex items-center justify-between text-[11px] leading-none px-3" style="top:{INST.head + i * INST.row}px;height:{INST.row}px">
      <span class="truncate max-w-[48%] {req?.open ? 'text-error font-semibold' : ''}" title={req ? `${req.label || req.name} (${req.type})${req.open ? ' — не подключён' : ''}` : ''} data-testid={req ? 'port-requires' : undefined} data-open={req?.open ? 'true' : undefined}>
        {req ? req.label || req.name : ''}
      </span>
      <span class="truncate max-w-[48%] text-right" title={prov ? `${prov.label || prov.name} (${prov.type})${prov.linked ? ', связей: ' + prov.linked : ''}` : ''} data-testid={prov ? 'port-provides' : undefined}>
        {prov ? prov.label || prov.name : ''}
      </span>
    </div>
  {/each}

  {#if shown.length}
    <div class="absolute left-0 right-0 border-t border-base-300 px-2 text-[10px]" style="top:{contTop - 3}px" data-testid="container-rows">
      {#each shown as c (c.name)}
        <div class="flex items-center gap-1 truncate" style="height:{INST.cont}px" title="{c.name} · {c.image} · {c.state}">
          <Box size={10} class="shrink-0 {c.state === 'running' ? 'text-success' : 'opacity-50'}" />
          <span class="truncate">{c.name}</span>
          <span class="opacity-50 truncate">{c.image}</span>
        </div>
      {/each}
      {#if hidden > 0}<div class="opacity-60" style="height:{INST.cont}px">ещё {hidden}</div>{/if}
    </div>
  {/if}
</div>

{#each data.requires as p, i (p.name)}
  <Handle
    id={'r:' + p.name}
    type="target"
    position={Position.Left}
   
    style="top:{portY(i)}px"
    class="!size-3 {p.open && !mark('requires', p.name) ? '!bg-error' : ''} {HANDLE[mark('requires', p.name)]}"
  />
{/each}
{#each data.provides as p, i (p.name)}
  <Handle id={'p:' + p.name} type="source" position={Position.Right} isConnectableEnd={false} style="top:{portY(i)}px" class="!size-3 {HANDLE[mark('provides', p.name)]}" />
{/each}
