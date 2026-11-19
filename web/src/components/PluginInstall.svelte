<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { fmtBytes } from '../lib/format.js';
  import { uploadPackage, permissionList, trustInfo, fingerprintDisplay, capabilityText, canInstall, safeUrl, jobIdOf } from '../lib/plugins.js';
  import JobProgress from './JobProgress.svelte';
  import { TriangleAlert, ShieldCheck, Upload, Link, ExternalLink } from 'lucide-svelte';

  // Install a plugin from a file, a link or the catalog: source → preview
  // (permissions, author, trust) → install job. catalogId skips the source
  // step (install or update from the official catalog). onchanged() after the
  // job; onclose(changed).
  let { onchanged, onclose, catalogId = '' } = $props();

  let dlg = $state();
  let step = $state('source'); // source | preview | job
  let kind = $state('file'); // file | url
  let file = $state(null);
  let url = $state('');
  let busy = $state(false);
  let error = $state('');
  let uploadId = $state('');
  let preview = $state(null);
  let trusted = $state(false);
  let jobId = $state('');

  onMount(() => {
    dlg?.showModal();
    if (catalogId) fromCatalog();
  });

  async function fromCatalog() {
    busy = true;
    error = '';
    step = 'loading';
    try {
      const r = await api.fetchCatalogPackage(catalogId);
      uploadId = r.upload_id;
      preview = r.preview;
      trusted = false;
      step = 'preview';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function close() {
    dlg?.close();
  }

  const urlOk = $derived(!!safeUrl(url));
  const perms = $derived(permissionList(preview));
  const trust = $derived(trustInfo(preview?.author?.trust));
  const homepage = $derived(safeUrl(preview?.homepage));

  async function check() {
    busy = true;
    error = '';
    try {
      const r = kind === 'file' ? await uploadPackage(file) : await api.fetchPluginPackage(url.trim());
      uploadId = r.upload_id;
      preview = r.preview;
      trusted = false;
      step = 'preview';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  async function install() {
    busy = true;
    error = '';
    try {
      const r = await api.installPlugin(uploadId, preview.author?.trust === 'new' ? trusted : false);
      jobId = jobIdOf(r);
      step = 'job';
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

<dialog bind:this={dlg} class="modal" onclose={() => onclose?.(!!jobId)}>
  <div class="modal-box max-w-2xl" data-testid="plugin-install">
    <h3 class="font-bold text-lg mb-3">{preview?.update ? 'Обновление плагина' : 'Установка плагина'}</h3>

    {#if error}<div class="alert alert-error text-sm mb-3" role="alert" data-testid="install-error"><TriangleAlert size={16} /> {error}</div>{/if}

    {#if step === 'loading'}
      <div class="flex items-center gap-2 py-6 justify-center" data-testid="install-catalog-loading">
        {#if busy}<span class="loading loading-spinner"></span> Скачиваем и проверяем пакет из каталога…{/if}
      </div>
      {#if !busy}
        <div class="modal-action mt-0">
          <button type="button" class="btn" onclick={close}>Закрыть</button>
          <button type="button" class="btn btn-primary" onclick={fromCatalog}>Повторить</button>
        </div>
      {/if}
    {:else if step === 'source'}
      <form class="grid gap-3" onsubmit={(e) => (e.preventDefault(), check())}>
        <div role="tablist" class="tabs tabs-box tabs-sm self-start">
          <button type="button" role="tab" class="tab gap-1" class:tab-active={kind === 'file'} onclick={() => (kind = 'file')}><Upload size={14} /> Файл</button>
          <button type="button" role="tab" class="tab gap-1" class:tab-active={kind === 'url'} onclick={() => (kind = 'url')}><Link size={14} /> Ссылка</button>
        </div>
        {#if kind === 'file'}
          <label class="grid gap-1">
            <span class="label-text text-sm">Пакет плагина (.hpkg)</span>
            <input type="file" accept=".hpkg,application/gzip,application/x-gzip" class="file-input file-input-bordered file-input-sm w-full" onchange={(e) => (file = e.currentTarget.files?.[0] || null)} data-testid="install-file" />
          </label>
        {:else}
          <label class="grid gap-1">
            <span class="label-text text-sm">Ссылка на пакет (.hpkg)</span>
            <input class="input input-bordered input-sm w-full" placeholder="https://example.com/plugin-v0.1.0-linux-amd64.hpkg" bind:value={url} data-testid="install-url" />
            {#if url.trim() && !urlOk}<span class="text-error text-xs">Нужна ссылка http:// или https://</span>{/if}
          </label>
        {/if}
        <p class="text-xs opacity-70">Hestia проверит подпись пакета и покажет, что плагин сможет делать, до установки.</p>
        <div class="modal-action mt-0">
          <button type="button" class="btn" onclick={close}>Отмена</button>
          <button type="submit" class="btn btn-primary" disabled={busy || (kind === 'file' ? !file : !urlOk)} data-testid="install-check">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Проверить пакет
          </button>
        </div>
      </form>
    {:else if step === 'preview' && preview}
      <div class="grid gap-3 text-sm" data-testid="install-preview">
        <div>
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-semibold text-base">{preview.name}</span>
            {#if preview.update}
              <span class="badge badge-info" data-testid="install-update">{preview.update.from} → {preview.update.to}</span>
            {:else}
              <span class="badge badge-ghost">{preview.version}</span>
            {/if}
            <span class="font-mono text-xs opacity-60">{preview.id}</span>
          </div>
          {#if preview.description}<p class="mt-1 opacity-80">{preview.description}</p>{/if}
          {#if homepage}<a class="link text-xs inline-flex items-center gap-1" href={homepage} target="_blank" rel="noopener noreferrer">{homepage} <ExternalLink size={12} /></a>{/if}
        </div>

        <div class="flex flex-wrap items-center gap-2">
          <span>Автор: <b>{preview.author?.name || '—'}</b></span>
          <span class="badge badge-sm {trust.cls}" data-testid="install-trust">{trust.label}</span>
          {#if preview.author?.trust !== 'new'}<span class="font-mono text-xs opacity-60" title="Отпечаток ключа автора">{fingerprintDisplay(preview.author?.fingerprint)}</span>{/if}
        </div>

        <div>
          <div class="font-semibold mb-1">Плагин сможет:</div>
          {#if perms.length}
            <ul class="grid gap-1" data-testid="install-permissions">
              {#each perms as p (p.id)}
                <li class="flex items-center gap-2" class:text-warning={p.isNew}>
                  <ShieldCheck size={14} class="shrink-0" /> {p.label}
                  {#if p.isNew}<span class="badge badge-sm badge-warning" data-testid="perm-new">новое</span>{/if}
                </li>
              {/each}
            </ul>
          {:else}
            <span class="opacity-70">ничего сверх общения с Hestia</span>
          {/if}
        </div>

        {#if preview.provides?.length || preview.requires?.length}
          <div class="grid gap-1">
            {#if preview.provides?.length}<div>Предоставляет: {preview.provides.map(capabilityText).join(', ')}</div>{/if}
            {#if preview.requires?.length}<div>Требует: {preview.requires.map(capabilityText).join(', ')}</div>{/if}
          </div>
        {/if}

        <div class="text-xs opacity-70">
          Размер: {fmtBytes(preview.size)}
          {#if preview.sha256}· SHA-256: <span class="font-mono break-all">{preview.sha256}</span>{/if}
        </div>

        {#if preview.author?.trust === 'new'}
          <div class="alert alert-warning grid gap-2 text-sm" role="alert" data-testid="install-new-author">
            <div class="flex items-center gap-2 font-semibold"><TriangleAlert size={16} /> Сторонний автор</div>
            <div>Hestia ещё не устанавливала плагины этого автора. Ставьте, только если доверяете ему и получили пакет из надёжного источника.</div>
            <div>Автор: <b>{preview.author.name || '—'}</b></div>
            <div>Отпечаток ключа: <code class="font-mono text-xs break-all">{fingerprintDisplay(preview.author.fingerprint)}</code></div>
            <label class="label cursor-pointer justify-start gap-3">
              <input type="checkbox" class="checkbox checkbox-sm" bind:checked={trusted} data-testid="install-trust-ok" />
              <span class="label-text">Я доверяю этому автору</span>
            </label>
          </div>
        {/if}
      </div>
      <div class="modal-action">
        {#if !catalogId}
          <button class="btn mr-auto" onclick={() => ((step = 'source'), (preview = null), (error = ''))} disabled={busy}>Назад</button>
        {/if}
        <button class="btn" class:mr-auto={!!catalogId} onclick={close}>Отмена</button>
        <button class="btn btn-primary" onclick={install} disabled={busy || !canInstall(preview, trusted)} data-testid="install-go">
          {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} {preview.update ? 'Обновить' : 'Установить'}
        </button>
      </div>
    {:else}
      <JobProgress id={jobId} doneText={`Плагин ${preview?.name || ''} установлен.`} failText="Установка не удалась." onfinish={() => onchanged?.()} />
      <div class="modal-action">
        <button class="btn" onclick={close}>Закрыть</button>
      </div>
    {/if}
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
