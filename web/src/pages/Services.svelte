<script>
  import { api } from '../lib/api.js';
  import { serviceRows, filterServices, groupByCategory, categoriesOf } from '../lib/services.js';
  import { adguardMark } from '../lib/dnsname.js';
  import { Search, ExternalLink, Globe } from 'lucide-svelte';

  let view = $state(null);
  let dns = $state(null);
  let error = $state('');
  let query = $state('');
  let category = $state('');
  let unknown = $state(false);
  let dead = $state(true);

  $effect(() => {
    api.network().then((v) => (view = v)).catch((e) => (error = e.message));
    api.dns().then((d) => (dns = d)).catch(() => {});
  });

  const rows = $derived(serviceRows(view?.hosts));
  const shown = $derived(filterServices(rows, { category, query, unknown, dead }));
  const groups = $derived(groupByCategory(shown));
  const cats = $derived(categoriesOf(rows));
</script>

<h1 class="text-2xl font-bold mb-4">Сервисы</h1>
{#if error}<div class="alert alert-error mb-4" role="alert">{error}</div>{/if}

{#if !view}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if rows.length === 0}
  <p class="opacity-70 py-8 text-center" data-testid="services-empty">
    Сервисов пока нет — запустите сканирование на экране <a class="link" href="#/map">«Карта сети»</a>.
  </p>
{:else}
  <div class="flex flex-wrap items-center gap-3 mb-3">
    <label class="input input-sm input-bordered flex items-center gap-2">
      <Search size={14} />
      <input type="search" placeholder="Сервис, хост, IP, имя" bind:value={query} data-testid="svc-search" />
    </label>
    <select class="select select-sm select-bordered" bind:value={category} aria-label="Категория" data-testid="svc-category">
      <option value="">Все категории</option>
      {#each cats as c (c.value)}<option value={c.value}>{c.label}</option>{/each}
    </select>
    <label class="label cursor-pointer gap-2 text-sm"><input type="checkbox" class="checkbox checkbox-sm" bind:checked={unknown} /> неопознанные порты</label>
    <label class="label cursor-pointer gap-2 text-sm"><input type="checkbox" class="checkbox checkbox-sm" bind:checked={dead} /> с молчащих хостов</label>
    <span class="text-xs opacity-70">{shown.length} из {rows.length}</span>
  </div>

  <div class="overflow-x-auto">
    <table class="table table-sm" data-testid="services-table">
      <thead>
        <tr><th>Сервис</th><th>Хост</th><th>Порт</th><th>Версия и детали</th><th>DNS-имена</th><th></th></tr>
      </thead>
      {#each groups as g (g.category)}
        <tbody>
          <tr class="bg-base-200"><th colspan="6">{g.label} <span class="opacity-60 font-normal">· {g.rows.length}</span></th></tr>
          {#each g.rows as r (r.key)}
            <tr class:opacity-60={!r.alive} data-testid="service-row">
              <td class="font-medium">
                {r.name}
                {#if adguardMark(r, dns)}
                  {@const m = adguardMark(r, dns)}
                  <a class="badge badge-sm badge-success gap-1 ml-1" href="#/targets" data-testid="adguard-mark"><Globe size={10} /> {m.text}</a>
                  {#if m.status && m.status.label !== 'Работает'}<span class="badge badge-sm {m.status.cls}">{m.status.label}</span>{/if}
                {/if}
              </td>
              <td>{r.host}{#if r.host !== r.ip} <span class="opacity-60 text-xs">{r.ip}</span>{/if}</td>
              <td class="font-mono">{r.port}</td>
              <td class="text-xs opacity-80">{r.detail}</td>
              <td class="text-xs">{r.dns.join(', ')}</td>
              <td>
                {#if r.url}
                  <a class="link inline-flex items-center gap-1" href={r.url} target="_blank" rel="noreferrer noopener">Открыть <ExternalLink size={12} /></a>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      {/each}
    </table>
  </div>
{/if}
