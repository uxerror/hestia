<script>
  // Scan settings on the map screen: subnets (automatic with the source, manual
  // ones can be added and removed), exclusions, the interval (read only).
  import { api } from '../lib/api.js';
  import { Plus, X, Save } from 'lucide-svelte';

  let { view, onsaved } = $props();

  let newSubnet = $state('');
  let exclude = $state('');
  let error = $state('');
  let saving = $state(false);
  let loadedFor = '';

  // Takes the stored exclusions whenever the server's copy changes.
  $effect(() => {
    const key = JSON.stringify(view.exclude || []);
    if (key !== loadedFor) {
      loadedFor = key;
      exclude = (view.exclude || []).join('\n');
    }
  });

  const SOURCE = { proxmox: 'Proxmox', ssh: 'SSH-сервер', manual: 'вручную' };

  function parseExclude(text) {
    return text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  async function save(extra) {
    saving = true;
    error = '';
    try {
      await api.networkSettings({ extra_subnets: extra, exclude: parseExclude(exclude) });
      newSubnet = '';
      await onsaved();
    } catch (e) {
      error = e.message;
    } finally {
      saving = false;
    }
  }

  const add = () => {
    const v = newSubnet.trim();
    if (v) save([...(view.extra_subnets || []), v]);
  };
  const remove = (cidr) => save((view.extra_subnets || []).filter((c) => c !== cidr));
</script>

<div class="flex flex-col gap-4 text-sm" data-testid="scan-settings">
  {#if error}<div class="alert alert-error" role="alert">{error}</div>{/if}

  <div>
    <h3 class="font-medium mb-1">Подсети</h3>
    <ul class="flex flex-col gap-1">
      {#each view.subnets as s (s.cidr)}
        <li class="flex flex-wrap items-center gap-2" data-testid="subnet-row">
          <span class="font-mono">{s.cidr}</span>
          <span class="badge badge-sm badge-ghost">{SOURCE[s.source] || s.source}</span>
          <span class="opacity-70">{s.label}</span>
          {#if s.error}<span class="text-error">{s.error}</span>{/if}
          {#if (view.extra_subnets || []).includes(s.cidr)}
            <button class="btn btn-ghost btn-xs btn-square" aria-label="Убрать подсеть {s.cidr}" onclick={() => remove(s.cidr)} disabled={saving}><X size={14} /></button>
          {/if}
        </li>
      {:else}
        <li class="opacity-70">Подсетей нет: подключите Proxmox или SSH-сервер, либо добавьте подсеть вручную.</li>
      {/each}
    </ul>
    <form class="flex gap-2 mt-2" onsubmit={(e) => { e.preventDefault(); add(); }}>
      <input class="input input-sm input-bordered w-48" placeholder="10.10.20.0/24" bind:value={newSubnet} aria-label="Новая подсеть" data-testid="new-subnet" />
      <button class="btn btn-sm" type="submit" disabled={saving || !newSubnet.trim()}><Plus size={14} /> Добавить</button>
    </form>
    <p class="opacity-60 text-xs mt-1">Сети за роутером (например, BMC) сканируются, только если добавлены здесь. Не шире /22.</p>
  </div>

  <div>
    <h3 class="font-medium mb-1">Исключения</h3>
    <textarea class="textarea textarea-bordered w-full max-w-md" rows="2" placeholder="адреса или подсети через пробел" bind:value={exclude} aria-label="Исключения"></textarea>
    <div><button class="btn btn-sm mt-1" onclick={() => save(view.extra_subnets || [])} disabled={saving}><Save size={14} /> Сохранить исключения</button></div>
  </div>

  <div class="opacity-70">Автоматически каждые {view.interval_hours} ч (первый запуск — через 5 минут после старта).</div>
</div>
