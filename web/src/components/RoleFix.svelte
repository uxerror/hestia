<script>
  import { api } from '../lib/api.js';
  import { TriangleAlert } from 'lucide-svelte';

  // Banner "the Hestia role is outdated" + the confirmation dialog with the plan.
  let { targetId } = $props();
  let plan = $state(null);
  let loading = $state(false);
  let applying = $state(false);
  let error = $state('');
  let dlg = $state();

  async function open() {
    error = '';
    plan = null;
    loading = true;
    dlg?.showModal();
    try {
      plan = await api.rolePlan(targetId);
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }
  async function apply() {
    applying = true;
    error = '';
    try {
      const r = await api.fixRole(targetId);
      dlg?.close();
      location.hash = '#/jobs/' + encodeURIComponent(r.job.id);
    } catch (e) {
      error = e.message;
    } finally {
      applying = false;
    }
  }
</script>

<div class="alert alert-warning text-sm" role="alert" data-testid="role-banner">
  <TriangleAlert size={18} />
  <span>Роль Hestia устарела: не хватает VM.GuestAgent.Audit — IP виртуальных машин не видны.</span>
  <button class="btn btn-sm" onclick={open}>Дополнить роль</button>
</div>

<dialog bind:this={dlg} class="modal">
  <div class="modal-box">
    <h3 class="font-bold text-lg mb-2">Дополнить роль Hestia</h3>
    {#if loading}
      <span class="loading loading-spinner"></span>
    {:else if plan && !plan.needed}
      <p>Роль уже в порядке — изменений не требуется. Обновите инвентарь.</p>
    {:else if plan}
      <p class="text-sm mb-2">Hestia выполнит на сервере Proxmox одну команду (по SSH ключом Hestia). Недостающие права: <b>{plan.missing.join(', ')}</b>.</p>
      <code class="block text-xs break-all bg-base-300 rounded p-2" data-testid="role-command">{plan.command}</code>
      <p class="text-xs opacity-70 mt-2">Существующие права роли сохраняются. Без подтверждения ничего не меняется.</p>
    {/if}
    {#if error}<div class="alert alert-error mt-3 text-sm" role="alert">{error}</div>{/if}
    <div class="modal-action">
      <button class="btn" onclick={() => dlg?.close()} disabled={applying}>Отмена</button>
      {#if plan?.needed}
        <button class="btn btn-primary" onclick={apply} disabled={applying} data-testid="role-apply">
          {#if applying}<span class="loading loading-spinner loading-sm"></span>{/if}
          Подтвердить и выполнить
        </button>
      {/if}
    </div>
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
