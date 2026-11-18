<script>
  import { api } from '../lib/api.js';
  import { targetSummary } from '../lib/connect.js';
  import { fmtTime } from '../lib/jobs.js';
  import { ageSince, fmtAge } from '../lib/format.js';
  import { entryOf, roleBanner } from '../lib/inventory.js';
  import { createLive } from '../lib/live.svelte.js';
  import NodeCard from '../components/NodeCard.svelte';
  import StorageList from '../components/StorageList.svelte';
  import RoleFix from '../components/RoleFix.svelte';
  import UpdateCard from '../components/UpdateCard.svelte';
  import DnsName from '../components/DnsName.svelte';
  import { Boxes, Server, Trash2, Plus, KeyRound, RefreshCw, List, CloudUpload } from 'lucide-svelte';

  const live = createLive();
  let targets = $state([]);
  let identity = $state(null);
  let loading = $state(true);
  let error = $state('');
  let confirming = $state(null); // target pending deletion
  let revert = $state(true);
  let deleting = $state(false);
  let dlg = $state();
  let place = $state(null); // GET /selfinstall: where this Hestia runs

  $effect(() => {
    api.selfinstall().then((r) => (place = r)).catch(() => {});
  });

  async function loadTargets() {
    try {
      targets = (await api.targets()).targets || [];
      error = '';
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }
  $effect(() => {
    loadTargets();
    api.identity().then((i) => (identity = i)).catch(() => {});
    return live.start();
  });

  async function refresh(t) {
    try {
      live.markCollecting(t.id);
      await api.refreshInventory(t.id);
    } catch (e) {
      error = e.message;
      live.load();
    }
  }

  function ask(t) {
    confirming = t;
    revert = true;
    dlg?.showModal();
  }
  async function del() {
    deleting = true;
    try {
      const r = await api.deleteTarget(confirming.id, revert);
      dlg?.close();
      location.hash = '#/jobs/' + encodeURIComponent(r.job.id);
    } catch (e) {
      error = e.message;
      dlg?.close();
    } finally {
      deleting = false;
    }
  }
</script>

<div class="flex items-center justify-between mb-4">
  <h1 class="text-2xl font-bold">Системы</h1>
  <a class="btn btn-primary btn-sm" href="#/wizard"><Plus size={16} /> Подключить</a>
</div>

{#if error}<div class="alert alert-error mb-4" role="alert">{error}</div>{/if}

{#if place?.state === 'local'}
  <div class="card bg-base-200 mb-4" data-testid="install-card">
    <div class="card-body gap-2 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex gap-3 items-start">
        <CloudUpload size={22} class="text-primary mt-0.5" />
        <p class="text-sm">Hestia сейчас работает на этом ПК. Установите её на сервер, чтобы она работала постоянно.</p>
      </div>
      <a class="btn btn-primary btn-sm" href={targets.length ? '#/install' : '#/wizard'} data-testid="install-btn">
        {targets.length ? 'Установить на сервер' : 'Подключить систему'}
      </a>
    </div>
  </div>
{:else if place?.state === 'installed'}
  <div class="alert mb-4 text-sm" data-testid="installed-note">Hestia работает на сервере: {place.location?.ip}{place.location?.vmid ? ` (контейнер ${place.location.vmid})` : ''}.</div>
{/if}
{#if place?.state === 'installed'}<UpdateCard />{/if}
<DnsName />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if targets.length === 0}
  <p class="opacity-70 py-8 text-center">Пока ничего не подключено. <a class="link" href="#/wizard">Подключить Proxmox или сервер</a>.</p>
{:else}
  <div class="grid gap-4">
    {#each targets as t (t.id)}
      {@const e = entryOf(live.entries, t.id)}
      {@const snap = e?.snapshot}
      {@const age = ageSince(e?.collected_at, live.now)}
      <div class="card bg-base-200" data-target={t.name}>
        <div class="card-body gap-3">
          <div class="flex flex-wrap items-start justify-between gap-2">
            <div>
              <h2 class="card-title">
                {#if t.kind === 'proxmox'}<Boxes size={20} class="text-primary" />{:else}<Server size={20} class="text-primary" />{/if}
                {t.name}
              </h2>
              <div class="text-sm opacity-70">
                {t.ssh_user}@{t.host}:{t.port} · {targetSummary(t)}
                {#if snap?.clustered}
                  <span class="badge badge-sm {snap.quorate ? 'badge-success' : 'badge-error'}" data-testid="quorum">{snap.quorate ? 'кворум есть' : 'нет кворума'}</span>
                {/if}
                {#if snap?.version}· Proxmox VE {snap.version}{/if}
              </div>
            </div>
            <div class="flex items-center gap-2">
              <span class="text-xs opacity-70" data-testid="age">
                {#if e?.collecting}Обновляется…{:else if age != null}Обновлено {fmtAge(age)}{:else}Данные не собирались{/if}
              </span>
              <button class="btn btn-ghost btn-sm" onclick={() => refresh(t)} disabled={e?.collecting} aria-label="Обновить {t.name}">
                {#if e?.collecting}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={16} />{/if}
                Обновить
              </button>
              <button class="btn btn-ghost btn-sm btn-square" aria-label="Удалить {t.name}" onclick={() => ask(t)}><Trash2 size={16} /></button>
            </div>
          </div>

          {#if e?.error}
            <div class="alert alert-error text-sm" role="alert" data-testid="inv-error">Сбор данных не удался: {e.error}</div>
          {/if}
          {#if t.kind === 'proxmox' && roleBanner(snap)}<RoleFix targetId={t.id} />{/if}
          {#if snap?.warnings?.length && !roleBanner(snap)}
            <div class="text-xs opacity-70">{snap.warnings.join(' · ')}</div>
          {/if}

          {#if snap}
            <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {#each snap.nodes as n (n.name)}
                <NodeCard node={n} guests={snap.guests} href={t.kind === 'proxmox' ? `#/targets/${t.id}/${encodeURIComponent(n.name)}` : ''} />
              {/each}
            </div>
            {#if snap.storages.length}
              <div>
                <h3 class="font-semibold text-sm mb-1">Хранилища</h3>
                <StorageList storages={snap.storages} />
              </div>
            {/if}
            {#if snap.guests.length}
              <a class="btn btn-sm btn-ghost self-start" href="#/targets/{t.id}"><List size={16} /> Все гости ({snap.guests.length})</a>
            {/if}
          {:else if !e?.error && !e?.collecting && live.loaded}
            <p class="text-sm opacity-70">Данных пока нет — нажмите «Обновить».</p>
          {:else if e?.collecting}
            <div class="flex justify-center py-4"><span class="loading loading-spinner"></span></div>
          {/if}
          <div class="text-xs opacity-60">Подключено: {fmtTime(t.created_at)}</div>
        </div>
      </div>
    {/each}
  </div>
{/if}

{#if identity}
  <div class="card bg-base-200 mt-6">
    <div class="card-body gap-2">
      <h2 class="card-title text-base"><KeyRound size={18} /> SSH-ключ Hestia</h2>
      <code class="text-xs break-all bg-base-300 rounded p-2" data-testid="identity-key">{identity.ssh_public_key}</code>
      <div class="text-xs opacity-60">Отпечаток: {identity.fingerprint}</div>
    </div>
  </div>
{/if}

<dialog bind:this={dlg} class="modal" onclose={() => (confirming = null)}>
  <div class="modal-box">
    <h3 class="font-bold text-lg mb-2">Удалить «{confirming?.name}»?</h3>
    <label class="label cursor-pointer justify-start gap-3">
      <input type="checkbox" class="checkbox" bind:checked={revert} />
      <span class="label-text">Откатить изменения на сервере (токен, права, пользователь, роль, ключ Hestia)</span>
    </label>
    {#if !revert}<p class="text-sm opacity-70 mt-2">Запись будет удалена только из Hestia; созданное на сервере останется.</p>{/if}
    <div class="modal-action">
      <button class="btn" onclick={() => dlg?.close()} disabled={deleting}>Отмена</button>
      <button class="btn btn-error" onclick={del} disabled={deleting}>
        {#if deleting}<span class="loading loading-spinner loading-sm"></span>{/if}
        Удалить
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
