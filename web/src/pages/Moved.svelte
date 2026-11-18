<script>
  import { api } from '../lib/api.js';
  import { session } from '../lib/session.svelte.js';
  import { movedView } from '../lib/selfinstall.js';
  import { addressLine } from '../lib/dnsname.js';
  import { Flame, ExternalLink, RefreshCw } from 'lucide-svelte';

  let remote = $state(null);
  let checking = $state(false);
  const url = $derived(remote?.url || session.remote?.url || '');
  const view = $derived(movedView(checking ? null : remote));

  async function check() {
    checking = true;
    try {
      remote = await api.remote();
      if (remote.reachable) location.href = remote.url;
    } catch {
      remote = { url: session.remote?.url || '', reachable: false };
    } finally {
      checking = false;
    }
  }
  $effect(() => {
    check();
  });
</script>

<div class="min-h-screen flex items-center justify-center p-4">
  <div class="card bg-base-200 max-w-md w-full">
    <div class="card-body gap-3">
      <h1 class="card-title text-primary"><Flame size={22} /> Hestia</h1>
      <p data-testid="moved-text">Hestia работает на <a class="link font-mono" href={url}>{url}</a>.</p>
      {#if remote?.fallback_url}<p class="text-xs opacity-70" data-testid="moved-address">{addressLine(remote)}</p>{/if}
      <p class="text-sm opacity-70" data-testid="moved-state">{view.text}</p>
      <div class="flex gap-2">
        <a class="btn btn-primary" href={url} data-testid="moved-open"><ExternalLink size={16} /> Открыть</a>
        <button class="btn" onclick={check} disabled={checking}>
          {#if checking}<span class="loading loading-spinner loading-xs"></span>{:else}<RefreshCw size={16} />{/if}
          Повторить проверку
        </button>
      </div>
      <p class="text-xs opacity-60">Локальные данные этого ПК лежат в каталоге данных, в папке archive.</p>
    </div>
  </div>
</div>
