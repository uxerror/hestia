<script>
  // One node of the network map: a compact device card, a subnet box or a group box.
  // A host with plugin instances ('chost') is the same card on top of a frame that holds the
  // instance nodes; it has the device handle (the target of «сервис → устройство» links) and
  // the `provides` ports of its instances exported to the right border.
  import { Handle, Position } from '@xyflow/svelte';
  import { getContext } from 'svelte';
  import { CATEGORY_LABEL, STATUS_LABEL } from '../lib/netmap.js';
  import { hostMark } from '../lib/compat.js';
  import { Server, Network, HardDrive, Film, Code, Activity, House, Database, Terminal, Circle, Router, Globe, Crown } from 'lucide-svelte';

  let { data, type, selected = false } = $props();
  const drag = getContext('mapdrag');
  const hmark = $derived(type === 'host' || type === 'chost' ? hostMark(drag?.compat, data.ip) : '');
  const DEV = { ok: '!bg-success !ring-4 !ring-success/50 scale-150', blocked: '!bg-warning !opacity-60', dim: '!opacity-20', '': '' };

  const ICON = { infra: Server, network: Network, storage: HardDrive, media: Film, dev: Code, monitoring: Activity, home: House, db: Database, remote: Terminal, other: Circle };
  const BORDER = { alive: 'border-success/70', down: 'border-error/70', stopped: 'border-base-300 opacity-60' };
  const DOT = { alive: 'bg-success', down: 'bg-error', stopped: 'bg-base-content/30' };
  const MAX_BADGES = 4;
  const badges = $derived((data.categories || []).slice(0, MAX_BADGES));
  const more = $derived(Math.max(0, (data.categories || []).length - MAX_BADGES));
  const sub = $derived(data.hint || data.vendor || '');
</script>

<Handle type="target" position={Position.Top} isConnectable={false} />
{#if type === 'group'}
  <div class="w-full h-full rounded-xl border border-dashed border-base-content/30 bg-base-200/60" data-testid="group-node">
    <div class="px-3 pt-2 text-sm font-semibold truncate">{data.label} <span class="font-normal opacity-60">· {data.count}</span></div>
  </div>
{:else if type === 'net'}
  <div class="rounded-lg border border-base-content/30 bg-base-200 px-3 py-2 text-sm text-center w-[150px] flex items-center justify-center gap-2" data-testid="net-node">
    <Globe size={14} /> {data.label}
  </div>
{:else}
  <div class={type === 'chost' ? 'w-full h-full rounded-lg border-2 bg-base-200/70 ' + (BORDER[data.status] || 'border-base-300') + (selected ? ' ring-2 ring-primary' : '') : ''} data-testid={type === 'chost' ? 'host-composite' : undefined}>
    <div
      class="rounded-lg border-2 bg-base-100 px-2 py-1 w-[180px] h-[68px] shadow-sm overflow-hidden {BORDER[data.status] || 'border-base-300'} {selected && type !== 'chost' ? 'ring-2 ring-primary' : ''} {type === 'chost' ? '!border-0 !shadow-none !bg-transparent mx-auto' : ''}"
      title="{data.label} · {data.ip} · {STATUS_LABEL[data.status] || ''}{data.hint ? ' · ' + data.hint : ''}"
      data-testid="host-node"
      data-status={data.status}
    >
      <div class="flex items-center gap-1.5 font-medium text-sm leading-5">
        <span class="inline-block size-2 rounded-full shrink-0 {DOT[data.status] || 'bg-base-300'}" data-testid="status-dot"></span>
        {#if data.router}<Router size={13} class="shrink-0 text-primary" />{/if}
        {#if data.controller}<span title="Здесь работает Hestia" data-testid="controller-badge"><Crown size={13} class="shrink-0 text-warning" /></span>{/if}
        <span class="truncate">{data.label}</span>
      </div>
      <div class="flex items-center justify-between gap-1 text-xs leading-4">
        <span class="opacity-70 shrink-0">{data.ip}</span>
        <span class="flex items-center gap-0.5 opacity-80">
          {#each badges as c (c)}
            {@const Icon = ICON[c] || Circle}
            <span title={CATEGORY_LABEL[c] || c}><Icon size={12} /></span>
          {/each}
          {#if more}<span class="text-[10px]">+{more}</span>{/if}
        </span>
      </div>
      <div class="text-[10px] leading-4 opacity-60 truncate">{sub}</div>
    </div>
  </div>
  <Handle id="dev" type="target" position={Position.Left} isConnectableStart={false} style="top:34px" class="!size-3 {DEV[hmark]}" />
  {#if type === 'chost'}
    {#each data.exports || [] as ex (ex.instance + ':' + ex.port)}
      <Handle id={'out:' + ex.instance + ':' + ex.port} type="source" position={Position.Right} isConnectableEnd={false} style="top:{ex.y}px" class="!size-3 !opacity-70" />
    {/each}
  {/if}
{/if}
<Handle type="source" position={Position.Bottom} isConnectable={false} />
