<script>
  import { api } from '../lib/api.js';
  import { stateInfo, authorBadge, fingerprintDisplay, shortFingerprint, capabilityText, sourceLabel, unitInfo, jobIdOf, removeBlocked } from '../lib/plugins.js';
  import JobProgress from './JobProgress.svelte';
  import PluginInstall from './PluginInstall.svelte';
  import { Puzzle, Power, PowerOff, Trash2, TriangleAlert, ArrowUpCircle } from 'lucide-svelte';

  // Card of an installed plugin with «Отключить/Включить» and «Удалить».
  //  plugin — PluginView (with `unit` on the plugin page);
  //  link — the name links to the plugin page;
  //  onchanged(kind) — a job finished ('enable' | 'disable' | 'remove').
  let { plugin, link = true, onchanged } = $props();

  let iconFailed = $state(false);
  let busy = $state(false);
  let error = $state('');
  let confirmRemove = $state(false);
  let blocked = $state(null); // {message, instances} of a 409
  let job = $state(null); // {id, kind}
  let updating = $state(false); // the update dialog (from the catalog)

  const st = $derived(stateInfo(plugin.state));
  const author = $derived(authorBadge(plugin.author));
  const unit = $derived(unitInfo(plugin.unit));
  const href = $derived('#/plugins/' + encodeURIComponent(plugin.id));

  async function run(kind) {
    busy = true;
    error = '';
    blocked = null;
    try {
      const r = kind === 'enable' ? await api.enablePlugin(plugin.id) : kind === 'disable' ? await api.disablePlugin(plugin.id) : await api.removePlugin(plugin.id);
      job = { id: jobIdOf(r), kind };
    } catch (e) {
      const b = kind === 'remove' ? removeBlocked(e) : null;
      if (b) blocked = b;
      else error = e.message;
    } finally {
      busy = false;
      confirmRemove = false;
    }
  }

  function finished(j) {
    const kind = job?.kind;
    if (j.status === 'done') {
      setTimeout(() => {
        job = null;
        onchanged?.(kind);
      }, 800);
    } else onchanged?.(kind);
  }

  const doneText = { enable: 'Плагин включён.', disable: 'Плагин отключён.', remove: 'Плагин удалён.' };
</script>

<div class="card bg-base-200" data-testid="plugin-card">
  <div class="card-body p-4 gap-3">
    <div class="flex items-start gap-3">
      <div class="w-12 h-12 shrink-0 rounded bg-base-100 flex items-center justify-center overflow-hidden">
        {#if plugin.has_icon && !iconFailed}
          <img src={'/api/v1/plugins/' + encodeURIComponent(plugin.id) + '/icon'} alt="" class="w-10 h-10" onerror={() => (iconFailed = true)} />
        {:else}
          <Puzzle size={28} class="opacity-60" />
        {/if}
      </div>
      <div class="flex-1 min-w-0 grid gap-1">
        <div class="flex flex-wrap items-center gap-2">
          {#if link}
            <a class="font-semibold text-lg link link-hover" {href} data-testid="plugin-name">{plugin.name}</a>
          {:else}
            <h1 class="font-bold text-2xl" data-testid="plugin-name">{plugin.name}</h1>
          {/if}
          <span class="badge badge-ghost badge-sm">{plugin.version}</span>
          <span class="badge badge-sm {st.cls}" data-testid="plugin-state">{st.label}</span>
          {#if plugin.dev}<span class="badge badge-sm badge-warning" data-testid="plugin-dev">dev, без песочницы</span>{/if}
          {#if unit}<span class="badge badge-sm {unit.cls}" title={unit.error} data-testid="plugin-unit">{unit.label}</span>{/if}
        </div>
        {#if plugin.description}<p class="text-sm opacity-80">{plugin.description}</p>{/if}
        <div class="flex flex-wrap items-center gap-2 text-xs">
          <span>Автор: {plugin.author?.name || '—'}</span>
          <span class="badge badge-xs {author.cls}">{author.label}</span>
          {#if plugin.author?.fingerprint}
            <span class="font-mono opacity-60" title={fingerprintDisplay(plugin.author.fingerprint)}>{link ? shortFingerprint(plugin.author.fingerprint) : fingerprintDisplay(plugin.author.fingerprint)}</span>
          {/if}
        </div>
        <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs opacity-70">
          {#if plugin.provides?.length}<span>Предоставляет: {plugin.provides.map(capabilityText).join(', ')}</span>{/if}
          {#if plugin.requires?.length}<span>Требует: {plugin.requires.map(capabilityText).join(', ')}</span>{/if}
          <span data-testid="plugin-instances">Экземпляров: {plugin.instances ?? 0}</span>
          {#if !link && plugin.source}<span>Источник: {sourceLabel(plugin.source)}</span>{/if}
        </div>
        {#if unit?.error}<div class="text-xs text-error">{unit.error}</div>{/if}
      </div>
      {#if !plugin.dev && !job}
        <div class="flex flex-wrap gap-2 justify-end">
          {#if link}
            <a class="btn btn-sm btn-primary btn-outline" {href} data-testid="plugin-instances-open">Экземпляры ({plugin.instances ?? 0})</a>
          {/if}
          {#if plugin.update}
            <button class="btn btn-sm btn-info" onclick={() => (updating = true)} disabled={busy} title={plugin.update.new_permissions?.length ? 'Новые права: ' + plugin.update.new_permissions.join(', ') : ''} data-testid="plugin-update"><ArrowUpCircle size={14} /> Обновить до {plugin.update.to}</button>
          {/if}
          {#if plugin.enabled}
            <button class="btn btn-sm" onclick={() => run('disable')} disabled={busy} data-testid="plugin-disable"><PowerOff size={14} /> Отключить</button>
          {:else}
            <button class="btn btn-sm" onclick={() => run('enable')} disabled={busy} data-testid="plugin-enable"><Power size={14} /> Включить</button>
          {/if}
          {#if confirmRemove}
            <button class="btn btn-sm btn-error" onclick={() => run('remove')} disabled={busy} data-testid="plugin-remove-yes">Да, удалить</button>
            <button class="btn btn-sm btn-ghost" onclick={() => (confirmRemove = false)} disabled={busy}>Нет</button>
          {:else}
            <button class="btn btn-sm btn-ghost text-error" onclick={() => ((confirmRemove = true), (blocked = null))} disabled={busy} data-testid="plugin-remove"><Trash2 size={14} /> Удалить</button>
          {/if}
        </div>
      {/if}
    </div>

    {#if error}<div class="alert alert-error text-sm" role="alert"><TriangleAlert size={16} /> {error}</div>{/if}
    {#if blocked}
      <div class="alert alert-warning text-sm grid gap-1" role="alert" data-testid="plugin-remove-blocked">
        <div class="flex items-center gap-2"><TriangleAlert size={16} /> {blocked.message}</div>
        {#if blocked.instances.length}
          <div>Экземпляры плагина:</div>
          <ul class="list-disc ml-6">{#each blocked.instances as n (n)}<li>{n}</li>{/each}</ul>
        {/if}
        {#if link}<a class="link" {href}>Перейти к экземплярам</a>{/if}
      </div>
    {/if}
    {#if job}
      <JobProgress id={job.id} compact doneText={doneText[job.kind]} onfinish={finished} />
    {/if}
  </div>
</div>

{#if updating}
  <PluginInstall catalogId={plugin.id} onchanged={() => onchanged?.('update')} onclose={(changed) => ((updating = false), changed && onchanged?.('update'))} />
{/if}
