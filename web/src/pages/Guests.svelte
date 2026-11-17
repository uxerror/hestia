<script>
  import { api } from '../lib/api.js';
  import { fmtBytes, fmtPercent, ageSince, fmtAge } from '../lib/format.js';
  import { emptyFilter, filterGuests, sortGuests, nextSort, statusInfo, GUEST_TYPE, guestIPs, entryOf, guestCounts } from '../lib/inventory.js';
  import { createLive } from '../lib/live.svelte.js';
  import { ArrowLeft, RefreshCw, ArrowUp, ArrowDown, Search } from 'lucide-svelte';

  let { id, node = '' } = $props();
  const live = createLive();
  let targetName = $state('');
  let filter = $state(emptyFilter());
  let sort = $state({ key: 'vmid', dir: 'asc' });
  let error = $state('');

  $effect(() => {
    api.target(id).then((r) => (targetName = r.target.name)).catch((e) => (error = e.message));
    return live.start();
  });
  // Following another node link (same page) resets the node filter.
  $effect(() => {
    filter.node = node;
  });

  const entry = $derived(entryOf(live.entries, Number(id)));
  const snap = $derived(entry?.snapshot);
  const rows = $derived(snap ? sortGuests(filterGuests(snap.guests, filter), sort.key, sort.dir) : []);
  const age = $derived(ageSince(entry?.collected_at, live.now));
  const counts = $derived(snap ? guestCounts(snap.guests, filter.node) : { running: 0, total: 0 });

  async function refresh() {
    try {
      live.markCollecting(Number(id));
      await api.refreshInventory(id);
    } catch (e) {
      error = e.message;
      live.load();
    }
  }

  const cols = [
    ['vmid', 'VMID'], ['name', 'Имя'], ['type', 'Тип'], ['status', 'Статус'], ['node', 'Узел'], ['cpu', 'CPU'],
    ['mem', 'RAM'], ['disk', 'Диск'], ['ip', 'IP'], ['tags', 'Теги'], ['template', 'Шаблон'],
  ];
</script>

<div class="flex flex-wrap items-center justify-between gap-2 mb-4">
  <div class="flex items-center gap-2">
    <a class="btn btn-ghost btn-sm btn-square" href="#/targets" aria-label="К системам"><ArrowLeft size={18} /></a>
    <h1 class="text-2xl font-bold">Гости{targetName ? ' · ' + targetName : ''}{filter.node ? ' · ' + filter.node : ''}</h1>
  </div>
  <div class="flex items-center gap-2">
    <span class="text-xs opacity-70">
      {#if entry?.collecting}Обновляется…{:else if age != null}Обновлено {fmtAge(age)}{/if}
    </span>
    <button class="btn btn-sm" onclick={refresh} disabled={entry?.collecting}>
      {#if entry?.collecting}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={16} />{/if}
      Обновить
    </button>
  </div>
</div>

{#if error || live.error}<div class="alert alert-error mb-4" role="alert">{error || live.error}</div>{/if}
{#if entry?.error}<div class="alert alert-error mb-4 text-sm" role="alert">Сбор данных не удался: {entry.error}</div>{/if}

{#if !live.loaded}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if !snap}
  <p class="opacity-70 py-8 text-center">Данных пока нет — нажмите «Обновить».</p>
{:else}
  <div class="flex flex-wrap items-end gap-2 mb-3">
    <label class="input input-sm input-bordered flex items-center gap-2">
      <Search size={14} />
      <input type="search" placeholder="Имя, IP, VMID, тег" bind:value={filter.query} data-testid="search" />
    </label>
    <select class="select select-sm select-bordered" bind:value={filter.node} aria-label="Узел" data-testid="f-node">
      <option value="">Все узлы</option>
      {#each snap.nodes as n (n.name)}<option value={n.name}>{n.name}</option>{/each}
    </select>
    <select class="select select-sm select-bordered" bind:value={filter.type} aria-label="Тип" data-testid="f-type">
      <option value="">VM и LXC</option>
      <option value="qemu">VM</option>
      <option value="lxc">LXC</option>
    </select>
    <select class="select select-sm select-bordered" bind:value={filter.status} aria-label="Статус" data-testid="f-status">
      <option value="">Любой статус</option>
      <option value="running">Запущены</option>
      <option value="stopped">Остановлены</option>
    </select>
    <span class="text-sm opacity-70 ml-auto">Показано {rows.length} из {snap.guests.length} · запущено {counts.running}/{counts.total}</span>
  </div>

  <div class="overflow-x-auto bg-base-200 rounded-box">
    <table class="table table-sm" data-testid="guests">
      <thead>
        <tr>
          {#each cols as [key, title] (key)}
            <th>
              <button class="flex items-center gap-1 font-semibold" onclick={() => (sort = nextSort(sort, key))} aria-label="Сортировать: {title}">
                {title}
                {#if sort.key === key}{#if sort.dir === 'asc'}<ArrowUp size={12} />{:else}<ArrowDown size={12} />{/if}{/if}
              </button>
            </th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each rows as g (g.node + '/' + g.vmid)}
          {@const st = statusInfo(g.status)}
          {@const ty = GUEST_TYPE[g.type] || { label: g.type, cls: 'badge-ghost' }}
          <tr class={g.status === 'running' ? '' : 'opacity-50'} data-vmid={g.vmid}>
            <td class="tabular-nums">{g.vmid}</td>
            <td>{g.name}</td>
            <td><span class="badge badge-sm {ty.cls}">{ty.label}</span></td>
            <td><span class="badge badge-sm {st.cls}">{st.label}</span></td>
            <td>{g.node}</td>
            <td class="tabular-nums whitespace-nowrap">{g.cpus} · {g.status === 'running' ? fmtPercent(g.cpu_usage) : '—'}</td>
            <td class="tabular-nums whitespace-nowrap">
              {#if g.status === 'running'}{fmtBytes(g.mem_used)} / {/if}{fmtBytes(g.mem_total)}
            </td>
            <td class="tabular-nums whitespace-nowrap">
              {#if g.disk_used > 0}{fmtBytes(g.disk_used)} / {/if}{fmtBytes(g.disk_total)}
            </td>
            <td class="whitespace-nowrap">
              {#if guestIPs(g)}{guestIPs(g)}{:else if g.ip_error}<span class="opacity-60 text-xs" title={g.ip_error}>{g.ip_error}</span>{:else}—{/if}
            </td>
            <td>
              <div class="flex flex-wrap gap-1">{#each g.tags as tag (tag)}<span class="badge badge-sm badge-outline">{tag}</span>{/each}</div>
            </td>
            <td>{#if g.template}<span class="badge badge-sm badge-accent">шаблон</span>{/if}</td>
          </tr>
        {:else}
          <tr><td colspan={cols.length} class="text-center opacity-70 py-6">Ничего не найдено</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
