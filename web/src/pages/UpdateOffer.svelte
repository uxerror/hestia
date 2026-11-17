<script>
  import { api } from '../lib/api.js';
  import { parseOffer, fetchPayload, uploadPayload, isDirty, RELEASES_URL } from '../lib/update.js';
  import UpdateRun from '../components/UpdateRun.svelte';
  import { ArrowLeft, TriangleAlert, Download } from 'lucide-svelte';

  // Opened by the desktop app on the remote controller: the app is newer
  // (offer to update the controller from the app's own binary) or older.
  let { hash } = $props();
  const offer = $derived(parseOffer(hash));

  let current = $state('');
  let ok = $state(false); // can this controller be updated at all
  let reason = $state('');
  let loadError = $state('');
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let confirmNeeded = $state(''); // the warning to accept
  let run = $state(null);

  $effect(() => {
    api
      .update()
      .then((s) => {
        current = s.current;
        ok = s.location_ok;
        reason = s.reason || '';
      })
      .catch((e) => (loadError = e.message))
      .finally(() => (loading = false));
  });

  async function go(confirm = false) {
    busy = true;
    error = '';
    try {
      const { meta, blob } = await fetchPayload(offer);
      const up = await uploadPayload(meta.version, blob);
      if (meta.sha256 && up.sha256 !== meta.sha256) throw new Error('Контрольная сумма файла после загрузки не совпала. Попробуйте ещё раз.');
      try {
        const r = await api.startUpdate({ upload_id: up.upload_id, confirm });
        run = { job: r.job, expect: up.version };
      } catch (e) {
        if (e.status === 409 && !confirm) {
          confirmNeeded = e.message;
          return;
        }
        throw e;
      }
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<a href="#/targets" class="btn btn-ghost btn-sm mb-4"><ArrowLeft size={16} /> Системы</a>
<h1 class="text-2xl font-bold mb-3">Обновление контроллера</h1>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if loadError}
  <div class="alert alert-error" role="alert">{loadError}</div>
{:else if offer.kind === 'invalid'}
  <div class="alert alert-warning" role="alert" data-testid="offer-invalid">Ссылка на обновление неверна или устарела. Закройте окно и откройте приложение заново.</div>
{:else if offer.kind === 'older'}
  <div class="alert alert-warning" role="status" data-testid="offer-older">
    <TriangleAlert size={18} />
    <div>Приложение старше контроллера ({offer.version} &lt; {current}) — обновите приложение.
      <a class="link" href={RELEASES_URL} target="_blank" rel="noreferrer">Скачать новую версию</a></div>
  </div>
{:else if run}
  <UpdateRun job={run.job} expect={run.expect} />
{:else}
  <div class="card bg-base-200 max-w-xl" data-testid="offer">
    <div class="card-body gap-3">
      <p>Приложение новее контроллера: <b>{current}</b> → <b>{offer.version}</b>. Обновить контроллер?</p>
      <p class="text-sm opacity-70">Файл возьмётся из приложения, интернет не нужен. Если новая версия не запустится, вернутся прежний бинарник и база.</p>
      {#if isDirty(offer.version)}
        <div class="alert alert-warning text-sm" role="alert" data-testid="offer-dirty"><TriangleAlert size={18} /> Это сборка с незакоммиченными изменениями, а не релиз.</div>
      {/if}
      {#if !ok}<div class="alert alert-warning text-sm" role="alert">{reason}</div>{/if}
      {#if confirmNeeded}<div class="alert alert-warning text-sm" role="alert" data-testid="offer-confirm">{confirmNeeded} Продолжить?</div>{/if}
      {#if error}<div class="alert alert-error text-sm" role="alert">{error}</div>{/if}
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={() => go(!!confirmNeeded)} disabled={busy || !ok} data-testid="offer-go">
          {#if busy}<span class="loading loading-spinner loading-sm"></span>{:else}<Download size={16} />{/if}
          {confirmNeeded ? 'Да, обновить' : 'Обновить контроллер'}
        </button>
        <a class="btn btn-ghost" href="#/targets">Не сейчас</a>
      </div>
    </div>
  </div>
{/if}
