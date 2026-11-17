<script>
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { STEP_STATUS, isFinal } from '../lib/jobs.js';
  import { KINDS, emptyForm, validateConnectForm, buildProbeBody, flowReducer, initialFlow, fmtBytes } from '../lib/connect.js';
  import { ArrowLeft, ShieldCheck, TriangleAlert, CircleCheck } from 'lucide-svelte';

  let { kind } = $props();
  const meta = $derived(KINDS[kind]);

  let form = $state(emptyForm());
  let touched = $state(false);
  let name = $state('');
  let flow = $state(initialFlow);
  const dispatch = (action) => (flow = flowReducer(flow, action));

  const errors = $derived(validateConnectForm(form, kind));
  const shown = $derived(touched ? errors : {});
  const busy = $derived(flow.phase === 'probing' || flow.phase === 'starting');

  async function probe(e) {
    e.preventDefault();
    touched = true;
    if (Object.keys(errors).length) return;
    dispatch({ type: 'probing' });
    try {
      const r = await api.probeTarget(buildProbeBody(form, kind));
      // The server keeps the credentials for 10 minutes; drop them from the page.
      form.password = '';
      form.private_key = '';
      form.passphrase = '';
      touched = false;
      name = r.suggested_name || '';
      dispatch({ type: 'probed', probe: r });
    } catch (err) {
      dispatch({ type: 'probe_failed', error: err.message });
    }
  }

  let close = () => {};
  async function connect() {
    const p = flow.probe;
    dispatch({ type: 'starting' });
    try {
      const r = await api.createTarget({
        probe_id: p.probe_id,
        name: name.trim(),
        accept: { host_key_fp: p.host_key_fp, api_cert_fp: p.api_cert_fp || undefined },
      });
      dispatch({ type: 'started', job: r.job });
      watch(r.job.id);
    } catch (err) {
      dispatch({ type: 'start_failed', error: err.message, status: err.status });
    }
  }

  function watch(id) {
    close();
    close = subscribeJob(id, {
      onUpdate: (j) => dispatch({ type: 'job', job: j }),
      onError: () => api.job(id).then((r) => dispatch({ type: 'job', job: r.job })).catch(() => {}),
    });
  }
  $effect(() => () => close());

  const steps = $derived(flow.job?.steps || []);
  const f = $derived(flow.probe?.facts);
</script>

<a href="#/wizard" class="btn btn-ghost btn-sm mb-4"><ArrowLeft size={16} /> Назад</a>
<h1 class="text-2xl font-bold mb-1">{meta?.title}</h1>

{#if flow.phase === 'form' || flow.phase === 'probing'}
  <p class="opacity-70 mb-4">
    {#if kind === 'proxmox'}Укажите узел Proxmox и пользователя root. Пароль нужен только для первого входа и нигде не сохраняется.
    {:else}Укажите сервер и учётную запись. Пароль нужен только для первого входа и нигде не сохраняется.{/if}
  </p>
  <form class="card bg-base-200 max-w-xl" onsubmit={probe} novalidate>
    <div class="card-body gap-3">
      <div class="grid grid-cols-3 gap-3">
        <label class="form-control col-span-2">
          <span class="label-text mb-1">Адрес</span>
          <input class="input input-bordered w-full" class:input-error={shown.host} bind:value={form.host} placeholder="IP или имя" autocapitalize="off" spellcheck="false" disabled={busy} data-testid="host" />
          {#if shown.host}<span class="text-error text-sm mt-1">{shown.host}</span>{/if}
        </label>
        <label class="form-control">
          <span class="label-text mb-1">Порт SSH</span>
          <input class="input input-bordered w-full" class:input-error={shown.port} bind:value={form.port} inputmode="numeric" disabled={busy} />
          {#if shown.port}<span class="text-error text-sm mt-1">{shown.port}</span>{/if}
        </label>
      </div>
      <label class="form-control">
        <span class="label-text mb-1">Пользователь</span>
        <input class="input input-bordered w-full" class:input-error={shown.username} bind:value={form.username} autocapitalize="off" spellcheck="false" disabled={busy} />
        {#if shown.username}<span class="text-error text-sm mt-1">{shown.username}</span>{/if}
      </label>

      <div class="join">
        <input class="join-item btn btn-sm" type="radio" name="auth" value="password" aria-label="Пароль" bind:group={form.auth} disabled={busy} />
        <input class="join-item btn btn-sm" type="radio" name="auth" value="key" aria-label="Ключ" bind:group={form.auth} disabled={busy} />
      </div>

      {#if form.auth === 'password'}
        <label class="form-control">
          <span class="label-text mb-1">Пароль</span>
          <input type="password" class="input input-bordered w-full" class:input-error={shown.password} bind:value={form.password} autocomplete="off" disabled={busy} />
          {#if shown.password}<span class="text-error text-sm mt-1">{shown.password}</span>{/if}
        </label>
      {:else}
        <label class="form-control">
          <span class="label-text mb-1">Приватный ключ (текст)</span>
          <textarea class="textarea textarea-bordered w-full font-mono text-xs h-32" class:textarea-error={shown.private_key} bind:value={form.private_key} spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" disabled={busy}></textarea>
          {#if shown.private_key}<span class="text-error text-sm mt-1">{shown.private_key}</span>{/if}
        </label>
        <label class="form-control">
          <span class="label-text mb-1">Парольная фраза ключа (если есть)</span>
          <input type="password" class="input input-bordered w-full" bind:value={form.passphrase} autocomplete="off" disabled={busy} />
        </label>
      {/if}

      {#if flow.error}<div class="alert alert-error text-sm" role="alert">{flow.error}</div>{/if}
      <button class="btn btn-primary" type="submit" disabled={busy}>
        {#if flow.phase === 'probing'}<span class="loading loading-spinner loading-sm"></span>{/if}
        Проверить
      </button>
    </div>
  </form>
{:else}
  {@const p = flow.probe}
  <p class="opacity-70 mb-4">Проверка выполнена, на сервере пока ничего не изменено.</p>

  <div class="grid gap-4 lg:grid-cols-2 mb-4">
    <div class="card bg-base-200">
      <div class="card-body gap-2">
        <h2 class="card-title text-base">Что найдено</h2>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="opacity-70">Адрес</dt><dd>{p.host}:{p.port} ({p.username})</dd>
          {#if p.kind === 'proxmox'}
            <dt class="opacity-70">Proxmox VE</dt><dd>{p.version}</dd>
            <dt class="opacity-70">Кластер</dt><dd>{p.cluster || 'одиночный узел'}</dd>
            <dt class="opacity-70">Узлы</dt>
            <dd>
              {#each p.nodes as n (n.name)}
                <div>{n.name}{n.ip ? ` (${n.ip})` : ''} <span class="badge badge-sm {n.online ? 'badge-success' : 'badge-warning'}">{n.online ? 'в сети' : 'не в сети'}</span>
                  {#if n.host_key_fp}
                    <div class="font-mono text-xs opacity-70 break-all" data-testid="node-fp-{n.name}">SSH: {n.host_key_fp}</div>
                  {:else if n.online && p.nodes.length > 1}
                    <div class="text-xs text-warning" data-testid="node-fp-{n.name}">SSH-ключ узла в кластере не найден</div>
                  {/if}
                </div>
              {/each}
            </dd>
          {:else if f}
            <dt class="opacity-70">Система</dt><dd>{f.os || '—'}</dd>
            <dt class="opacity-70">Ядро</dt><dd>{f.kernel} {f.arch}</dd>
            <dt class="opacity-70">CPU</dt><dd>{f.cpus || '—'}</dd>
            <dt class="opacity-70">RAM</dt><dd>{fmtBytes(f.mem_total)}</dd>
            <dt class="opacity-70">Диски</dt>
            <dd>{#each f.disks as d (d.mount)}<div>{d.mount}: {fmtBytes(d.used)} из {fmtBytes(d.size)}</div>{:else}—{/each}</dd>
            <dt class="opacity-70">Docker</dt><dd>{f.docker ? 'установлен' : 'нет'}</dd>
            <dt class="opacity-70">Права</dt><dd>{f.uid === 0 ? 'root' : f.sudo ? 'не root, sudo без пароля есть' : 'не root, sudo без пароля нет'}</dd>
          {/if}
        </dl>
      </div>
    </div>

    <div class="card bg-base-200">
      <div class="card-body gap-2">
        <h2 class="card-title text-base"><ShieldCheck size={18} /> Отпечатки</h2>
        <p class="text-sm opacity-70">Сверьте, если сомневаетесь: сервер ли это. После подтверждения Hestia запомнит отпечатки и откажется подключаться, если они изменятся.</p>
        <div class="text-sm">SSH-ключ сервера</div>
        <code class="text-xs break-all bg-base-300 rounded p-2" data-testid="fp-ssh">{p.host_key_fp}</code>
        {#if p.api_cert_fp}
          <div class="text-sm">TLS-сертификат API (порт 8006)</div>
          <code class="text-xs break-all bg-base-300 rounded p-2" data-testid="fp-tls">{p.api_cert_fp}</code>
        {/if}
      </div>
    </div>
  </div>

  {#each p.warnings as w (w)}
    <div class="alert alert-warning mb-3 text-sm" role="alert"><TriangleAlert size={18} /> {w}</div>
  {/each}

  <div class="card bg-base-200 mb-4">
    <div class="card-body gap-2">
      <h2 class="card-title text-base">Что изменит Hestia</h2>
      <ol class="list-decimal ml-5 space-y-2 text-sm">
        {#each p.plan as item (item.id)}
          <li><span class="font-medium">{item.title}</span><div class="opacity-70">{item.detail}</div></li>
        {/each}
      </ol>
      <p class="text-xs opacity-60">Если на каком-то шаге случится ошибка, всё уже внесённое будет откатано.</p>
    </div>
  </div>

  {#if flow.phase === 'review' || flow.phase === 'starting'}
    <label class="form-control max-w-sm mb-3">
      <span class="label-text mb-1">Название в Hestia</span>
      <input class="input input-bordered w-full" bind:value={name} maxlength="64" disabled={busy} />
    </label>
    {#if flow.error}<div class="alert alert-error mb-3 text-sm" role="alert">{flow.error}</div>{/if}
    <div class="flex gap-2">
      <button class="btn btn-primary" onclick={connect} disabled={busy} data-testid="connect">
        {#if flow.phase === 'starting'}<span class="loading loading-spinner loading-sm"></span>{/if}
        Подключить
      </button>
      <button class="btn" onclick={() => dispatch({ type: 'edit' })} disabled={busy}>Изменить данные</button>
    </div>
  {:else}
    <h2 class="font-semibold mb-2">Подключение</h2>
    <ul class="steps steps-vertical mb-4">
      {#each steps as s (s.idx)}
        {@const ss = STEP_STATUS[s.status] || { label: s.status, cls: '' }}
        <li class="step" class:step-primary={s.status === 'done' || s.status === 'running'} class:step-error={s.status === 'failed'}>
          <div class="text-left">
            {s.title} <span class="badge badge-sm {ss.cls}">{ss.label}</span>
            {#if s.status === 'running'}<span class="loading loading-spinner loading-xs ml-1"></span>{/if}
            {#if s.error}<div class="text-error text-sm">{s.error}</div>{/if}
          </div>
        </li>
      {/each}
    </ul>
    {#if flow.phase === 'running'}
      <p class="text-sm opacity-70">Выполняется… <a class="link" href={'#/jobs/' + encodeURIComponent(flow.job.id)}>журнал задачи</a></p>
    {:else if flow.phase === 'done'}
      <div class="alert alert-success mb-3" role="alert"><CircleCheck size={18} /> Готово: цель подключена.</div>
      <a class="btn btn-primary" href="#/targets">К списку систем</a>
    {:else if flow.phase === 'failed'}
      <div class="alert alert-error mb-3" role="alert">{flow.error}</div>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={() => dispatch({ type: 'retry' })}>Повторить</button>
        <a class="btn" href={'#/jobs/' + encodeURIComponent(flow.job.id)}>Журнал</a>
        <button class="btn" onclick={() => dispatch({ type: 'edit' })}>Изменить данные</button>
      </div>
    {/if}
  {/if}
{/if}
