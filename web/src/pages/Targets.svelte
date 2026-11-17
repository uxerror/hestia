<script>
  import { api } from '../lib/api.js';
  import { targetSummary } from '../lib/connect.js';
  import { fmtTime } from '../lib/jobs.js';
  import { Boxes, Server, Trash2, Plus, KeyRound } from 'lucide-svelte';

  let targets = $state([]);
  let identity = $state(null);
  let loading = $state(true);
  let error = $state('');
  let confirming = $state(null); // target pending deletion
  let revert = $state(true);
  let deleting = $state(false);
  let dlg = $state();

  async function load() {
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
    load();
    api.identity().then((i) => (identity = i)).catch(() => {});
  });

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

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if targets.length === 0}
  <p class="opacity-70 py-8 text-center">Пока ничего не подключено. <a class="link" href="#/wizard">Подключить Proxmox или сервер</a>.</p>
{:else}
  <div class="grid gap-4 sm:grid-cols-2">
    {#each targets as t (t.id)}
      <div class="card bg-base-200" data-target={t.name}>
        <div class="card-body gap-2">
          <div class="flex items-start justify-between gap-2">
            <h2 class="card-title">
              {#if t.kind === 'proxmox'}<Boxes size={20} class="text-primary" />{:else}<Server size={20} class="text-primary" />{/if}
              {t.name}
            </h2>
            <button class="btn btn-ghost btn-sm btn-square" aria-label="Удалить {t.name}" onclick={() => ask(t)}><Trash2 size={16} /></button>
          </div>
          <div class="text-sm opacity-70">{t.ssh_user}@{t.host}:{t.port} · {targetSummary(t)}</div>
          {#if t.nodes.length}
            <div class="flex flex-wrap gap-1">
              {#each t.nodes as n (n.name)}
                <span class="badge {n.online ? 'badge-success' : 'badge-warning'} badge-outline" title={n.host_key_fp ? `SSH: ${n.host_key_fp}` : ''}>{n.name}</span>
              {/each}
            </div>
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
