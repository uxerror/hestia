<script>
  import { api } from '../lib/api.js';
  import { fmtTime } from '../lib/jobs.js';
  import { blockState, statusInfo, suggestedDomain } from '../lib/dnsname.js';
  import DnsWizard from './DnsWizard.svelte';
  import { Globe, RefreshCw, TriangleAlert } from 'lucide-svelte';

  // Block "Имя в сети" of the controller card.
  let dns = $state(null);
  let error = $state('');
  let wiz = $state(null); // { start }
  let checking = $state(false);

  async function load() {
    try {
      dns = await api.dns();
      error = '';
    } catch (e) {
      error = e.message;
    }
  }
  $effect(() => {
    load();
  });

  async function check() {
    checking = true;
    try {
      dns = await api.dnsCheck();
    } catch (e) {
      error = e.message;
    } finally {
      checking = false;
    }
  }

  const b = $derived(blockState(dns));
  const st = $derived(dns?.name ? statusInfo(dns.name.status) : null);
  const fix = $derived(st?.action);

  function onFix() {
    wiz = { start: fix.plan ? 'fix' : 'connection' };
  }
  function closed() {
    wiz = null;
    load();
  }
</script>

{#if error}
  <div class="alert alert-warning mb-4 text-sm" role="alert">Имя в сети: {error}</div>
{:else if b.state === 'found'}
  <div class="card bg-base-200 mb-4" data-testid="dns-found">
    <div class="card-body gap-2 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex gap-3 items-start">
        <Globe size={22} class="text-primary mt-0.5" />
        <p class="text-sm">Найден AdGuard Home на {b.host}. Дать Hestia имя <b class="font-mono">{suggestedDomain(dns)}</b>?</p>
      </div>
      <button class="btn btn-primary btn-sm" onclick={() => (wiz = { start: 'setup' })} data-testid="dns-setup">Настроить</button>
    </div>
  </div>
{:else if b.state === 'connected'}
  <div class="card bg-base-200 mb-4" data-testid="dns-connected-card">
    <div class="card-body gap-2 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex gap-3 items-start">
        <Globe size={22} class="text-primary mt-0.5" />
        <p class="text-sm">AdGuard Home ({dns.integration.base_url}) подключён. Имя Hestia ещё не задано.</p>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-ghost btn-sm" onclick={() => (wiz = { start: 'connection' })}>Изменить подключение</button>
        <button class="btn btn-primary btn-sm" onclick={() => (wiz = { start: 'name' })}>Дать имя</button>
      </div>
    </div>
  </div>
{:else if b.state === 'named'}
  <div class="card bg-base-200 mb-4" data-testid="dns-named">
    <div class="card-body gap-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h2 class="card-title text-base"><Globe size={18} class="text-primary" /> Имя в сети</h2>
        <div class="flex items-center gap-2">
          <span class="badge {st.cls}" data-testid="dns-status">{st.label}</span>
          <button class="btn btn-ghost btn-xs" onclick={check} disabled={checking} aria-label="Проверить имя">
            {#if checking}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={14} />{/if}
          </button>
        </div>
      </div>
      <div class="text-sm">
        <a class="link font-mono" href={'http://' + dns.name.domain} target="_blank" rel="noreferrer noopener">http://{dns.name.domain}</a>
        <span class="opacity-70"> → {dns.name.answer} через {dns.integration.name}</span>
      </div>
      {#if dns.name.status !== 'ok'}
        <div class="alert alert-warning text-sm" role="alert" data-testid="dns-problem">
          <TriangleAlert size={16} />
          <span>{dns.name.status_detail || st.hint}</span>
        </div>
      {/if}
      <div class="text-xs opacity-60">
        {#if dns.name.verified_at}Проверено при настройке: {fmtTime(dns.name.verified_at)}.{/if}
        {#if dns.name.checked_at} Последняя проверка: {fmtTime(dns.name.checked_at)}.{/if}
      </div>
      <div class="flex flex-wrap gap-2">
        {#if fix}<button class="btn btn-primary btn-sm" onclick={onFix} data-testid="dns-fix">{fix.label}</button>{/if}
        <button class="btn btn-ghost btn-sm" onclick={() => (wiz = { start: 'remove' })}>Убрать запись</button>
      </div>
    </div>
  </div>
{/if}

{#if wiz}<DnsWizard {dns} start={wiz.start} onclose={closed} />{/if}
