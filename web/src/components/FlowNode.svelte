<script>
  // One node of the network map: a compact device card, a subnet box or a group box.
  import { Handle, Position } from '@xyflow/svelte';
  import { CATEGORY_LABEL, STATUS_LABEL } from '../lib/netmap.js';
  import { Server, Network, HardDrive, Film, Code, Activity, House, Database, Terminal, Circle, Router, Globe } from 'lucide-svelte';

  let { data, type, selected = false } = $props();

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
  <div
    class="rounded-lg border-2 bg-base-100 px-2 py-1 w-[180px] h-[68px] shadow-sm overflow-hidden {BORDER[data.status] || 'border-base-300'} {selected ? 'ring-2 ring-primary' : ''}"
    title="{data.label} · {data.ip} · {STATUS_LABEL[data.status] || ''}{data.hint ? ' · ' + data.hint : ''}"
    data-testid="host-node"
    data-status={data.status}
  >
    <div class="flex items-center gap-1.5 font-medium text-sm leading-5">
      <span class="inline-block size-2 rounded-full shrink-0 {DOT[data.status] || 'bg-base-300'}" data-testid="status-dot"></span>
      {#if data.router}<Router size={13} class="shrink-0 text-primary" />{/if}
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
{/if}
<Handle type="source" position={Position.Bottom} isConnectable={false} />
