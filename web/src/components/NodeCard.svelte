<script>
  import Meter from './Meter.svelte';
  import { fmtBytes, fmtPercent, fmtUptime, fmtLoad, pct } from '../lib/format.js';
  import { guestCounts } from '../lib/inventory.js';
  import { Server, ChevronRight } from 'lucide-svelte';

  // node: inventory node; guests: all guests of the target; href: link to the guest table (none for a standalone server).
  let { node, guests = [], href = '' } = $props();
  const counts = $derived(guestCounts(guests, node.name));
  const cpuTitle = $derived(
    [node.sockets ? `${node.sockets} сокет.` : '', node.cores ? `${node.cores} ядер` : ''].filter(Boolean).join(', '),
  );
</script>

<svelte:element this={href ? 'a' : 'div'} {href} class="card bg-base-100 border border-base-300 {href ? 'hover:border-primary' : ''} {node.online ? '' : 'opacity-60'}" data-node={node.name}>
  <div class="card-body gap-2 p-4">
    <div class="flex items-center justify-between gap-2">
      <h3 class="font-semibold flex items-center gap-2"><Server size={16} /> {node.name}
        <span class="badge badge-sm {node.online ? 'badge-success' : 'badge-warning'}">{node.online ? 'в сети' : 'не в сети'}</span>
      </h3>
      {#if href}<ChevronRight size={16} class="opacity-50" />{/if}
    </div>
    <div class="text-xs opacity-70">
      {#if node.ip}{node.ip} · {/if}{node.os || (node.pve_version ? 'Proxmox VE ' + node.pve_version : '')}
      {#if node.kernel}· {node.kernel}{/if}
    </div>
    {#if node.cpu_model}
      <div class="text-xs" title={node.cpu_model}>
        <span class="opacity-70">CPU:</span> {node.cpu_model}{#if node.threads}, потоков: {node.threads}{/if}{#if cpuTitle} ({cpuTitle}){/if}
      </div>
    {:else if node.threads}
      <div class="text-xs"><span class="opacity-70">Потоков:</span> {node.threads}</div>
    {/if}
    {#if node.online}
      <Meter label="CPU" value={Math.round((node.cpu_usage || 0) * 100)} text="{fmtPercent(node.cpu_usage)} · load {fmtLoad(node.load1)}" />
      <Meter label="RAM" value={pct(node.mem_used, node.mem_total)} text="{fmtBytes(node.mem_used)} / {fmtBytes(node.mem_total)}" />
      {#if node.rootfs_total}
        <Meter label="Диск /" value={pct(node.rootfs_used, node.rootfs_total)} text="{fmtBytes(node.rootfs_used)} / {fmtBytes(node.rootfs_total)}" />
      {/if}
      {#if node.swap_total}
        <Meter label="Swap" value={pct(node.swap_used, node.swap_total)} text="{fmtBytes(node.swap_used)} / {fmtBytes(node.swap_total)}" />
      {/if}
      <div class="flex flex-wrap gap-x-4 text-xs opacity-80">
        <span>Load: {fmtLoad(node.load1)} · {fmtLoad(node.load5)} · {fmtLoad(node.load15)}</span>
        <span>Аптайм: {fmtUptime(node.uptime)}</span>
        {#if node.docker}<span>Docker</span>{/if}
        {#if href}<span data-testid="guest-count">Гости: {counts.running}/{counts.total}</span>{/if}
      </div>
    {/if}
  </div>
</svelte:element>
