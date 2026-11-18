<script>
  // Side panel of the map: everything known about one host.
  import { hostName, hostStatus, STATUS_LABEL, CATEGORY_LABEL, linkText, linkHref } from '../lib/netmap.js';
  import { fmtTime } from '../lib/jobs.js';
  import { ExternalLink, Trash2, X } from 'lucide-svelte';

  let { host, onclose, onforget } = $props();

  const NAME_SRC = { ptr: 'DNS', inventory: 'Proxmox', cert: 'сертификат', title: 'заголовок страницы' };
  const status = $derived(hostStatus(host));
  const STATUS_CLS = { alive: 'badge-success', down: 'badge-error', stopped: 'badge-ghost' };
</script>

<aside class="card bg-base-200 p-4 text-sm flex flex-col gap-3" data-testid="host-panel">
  <div class="flex items-start justify-between gap-2">
    <div class="min-w-0">
      <h2 class="font-bold text-lg truncate">{hostName(host)}</h2>
      <div class="opacity-70">{host.ip}</div>
    </div>
    <button class="btn btn-ghost btn-xs btn-square" onclick={onclose} aria-label="Закрыть"><X size={16} /></button>
  </div>

  <div class="flex flex-wrap gap-1">
    <span class="badge {STATUS_CLS[status]}">{STATUS_LABEL[status]}</span>
    {#if host.no_response}<span class="badge badge-warning">не отвечает на порты из списка</span>{/if}
    {#if host.source === 'inventory'}<span class="badge badge-ghost">из инвентаря Proxmox</span>{/if}
  </div>

  {#if host.link}
    <div>
      <div class="opacity-60 text-xs">Связь с инвентарём</div>
      <a class="link" href={linkHref(host.link)}>{linkText(host.link)}</a>
    </div>
  {/if}

  <div>
    <div class="opacity-60 text-xs">MAC</div>
    {#if host.mac}
      <span class="font-mono">{host.mac}</span>
      {#if host.random_mac}<span class="badge badge-sm badge-ghost ml-1">случайный MAC</span>
      {:else if host.vendor}<span class="opacity-80"> · {host.vendor}</span>{/if}
    {:else}—{/if}
  </div>

  {#if host.names?.length}
    <div>
      <div class="opacity-60 text-xs">Имена</div>
      <ul>
        {#each host.names as n (n.source + n.name)}
          <li>{n.name} <span class="opacity-60">({NAME_SRC[n.source] || n.source})</span></li>
        {/each}
      </ul>
    </div>
  {/if}

  <div>
    <div class="opacity-60 text-xs">Открытые порты</div>
    {#if host.ports?.length}<span class="font-mono">{host.ports.join(', ')}</span>{:else}—{/if}
  </div>

  {#if host.services?.length}
    <div>
      <div class="opacity-60 text-xs mb-1">Сервисы</div>
      <ul class="flex flex-col gap-2">
        {#each host.services as s (s.port)}
          <li class="rounded bg-base-100 p-2" data-testid="panel-service">
            <div class="flex items-center justify-between gap-2">
              <span class="font-medium">{s.name}</span>
              <span class="badge badge-sm badge-outline">{CATEGORY_LABEL[s.category] || s.category}</span>
            </div>
            <div class="opacity-70 text-xs">
              порт {s.port}{#if s.version} · {s.version}{/if}{#if s.os} · {s.os}{/if}{#if s.detail} · {s.detail}{/if}
            </div>
            {#if s.url}
              <a class="link text-xs inline-flex items-center gap-1" href={s.url} target="_blank" rel="noreferrer noopener">Открыть <ExternalLink size={12} /></a>
            {/if}
          </li>
        {/each}
      </ul>
    </div>
  {/if}

  <div class="opacity-70 text-xs">
    Впервые: {fmtTime(host.first_seen)}<br />
    Последний раз: {fmtTime(host.last_seen)}
  </div>

  {#if host.source === 'scan'}
    <button class="btn btn-sm btn-ghost text-error self-start" onclick={onforget}><Trash2 size={14} /> Забыть</button>
  {/if}
</aside>
