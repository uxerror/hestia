<script>
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { STEP_STATUS } from '../lib/jobs.js';
  import { startTransferWatch } from '../lib/session.svelte.js';
  import { targetSummary } from '../lib/connect.js';
  import {
    defaultTargetId, buildProbeRequest, installReducer, initialInstall, fieldValue, hasStaticIP, summarize, resultSummary,
    handoffHref, LXC_FIELDS,
  } from '../lib/selfinstall.js';
  import { ArrowLeft, TriangleAlert, CircleCheck, ChevronDown, ChevronUp } from 'lucide-svelte';

  let targets = $state([]);
  let targetId = $state(0);
  let loading = $state(true);
  let loadError = $state('');
  let flow = $state(initialInstall);
  let countdown = $state(0);
  const dispatch = (action) => (flow = installReducer(flow, action));

  $effect(() => {
    api
      .targets()
      .then((r) => {
        targets = r.targets || [];
        targetId = defaultTargetId(targets);
      })
      .catch((e) => (loadError = e.message))
      .finally(() => (loading = false));
  });

  const target = $derived(targets.find((t) => t.id === targetId));
  const busy = $derived(flow.phase === 'probing' || flow.phase === 'starting');

  async function check(again) {
    dispatch({ type: again ? 'reprobing' : 'probing' });
    try {
      dispatch({ type: 'probed', probe: await api.probeInstall(buildProbeRequest(targetId, again ? flow.dirty : {})) });
    } catch (e) {
      dispatch({ type: 'probe_failed', error: e.message });
    }
  }

  let close = () => {};
  async function install() {
    const p = flow.probe;
    dispatch({ type: 'starting' });
    try {
      const r = await api.startInstall(p.probe_id);
      dispatch({ type: 'started', job: r.job });
      watch(r.job.id);
    } catch (e) {
      dispatch({ type: 'start_failed', error: e.message, status: e.status });
    }
  }
  function watch(id) {
    close();
    close = subscribeJob(id, {
      onUpdate: (j) => {
        // the state copy starts at "Перенос состояния": show the banner at once
        if (j.steps?.some((s) => s.title === 'Перенос состояния' && s.status === 'running')) startTransferWatch();
        dispatch({ type: 'job', job: j });
      },
      // After the switch the local database is gone: the final event is all we get.
      onError: () => api.job(id).then((r) => dispatch({ type: 'job', job: r.job })).catch(() => {}),
    });
  }
  $effect(() => () => close());

  // Done: the window follows the one-time link to the new controller after 3 s.
  $effect(() => {
    if (flow.phase !== 'done' || !flow.result) return;
    countdown = 3;
    const t = setInterval(() => {
      countdown -= 1;
      if (countdown <= 0) {
        clearInterval(t);
        go();
      }
    }, 1000);
    return () => clearInterval(t);
  });
  function go() {
    const href = handoffHref(flow.result);
    if (href) location.href = href;
  }

  const LABELS = {
    node: 'Узел', vmid: 'VMID', hostname: 'Имя', storage: 'Хранилище диска', template_storage: 'Хранилище шаблонов', bridge: 'Мост',
    ip: 'Адрес', gateway: 'Шлюз', cores: 'Ядра', memory_mb: 'RAM, МБ', disk_gb: 'Диск, ГБ',
  };
  const steps = $derived(flow.job?.steps || []);
  const p = $derived(flow.probe);
</script>

<a href="#/targets" class="btn btn-ghost btn-sm mb-4"><ArrowLeft size={16} /> Системы</a>
<h1 class="text-2xl font-bold mb-1">Установить Hestia на сервер</h1>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if loadError}
  <div class="alert alert-error" role="alert">{loadError}</div>
{:else if targets.length === 0}
  <p class="opacity-70 py-6">Сначала подключите Proxmox или сервер. <a class="btn btn-primary btn-sm ml-2" href="#/wizard">Подключить</a></p>
{:else if !flow.probe}
  <p class="opacity-70 mb-4">Hestia переедет на выбранную систему и будет работать там постоянно. Сначала проверка: на системе ничего не меняется.</p>
  <div class="card bg-base-200 max-w-xl">
    <div class="card-body gap-3">
      <label class="form-control">
        <span class="label-text mb-1">Куда установить</span>
        <select class="select select-bordered w-full" bind:value={targetId} disabled={busy} data-testid="target-select">
          {#each targets as t (t.id)}
            <option value={t.id}>{t.name} — {t.kind === 'proxmox' ? 'Proxmox' : 'сервер'} ({targetSummary(t)})</option>
          {/each}
        </select>
      </label>
      {#if target}
        <p class="text-sm opacity-70">
          {#if target.kind === 'proxmox'}Будет создан непривилегированный LXC-контейнер (Debian 13) на узле Proxmox.
          {:else}Hestia встанет службой systemd прямо на сервер.{/if}
        </p>
      {/if}
      {#if flow.error}<div class="alert alert-error text-sm" role="alert">{flow.error}</div>{/if}
      <button class="btn btn-primary" onclick={() => check(false)} disabled={busy || !targetId} data-testid="check">
        {#if flow.phase === 'probing'}<span class="loading loading-spinner loading-sm"></span>{/if}
        Проверить
      </button>
    </div>
  </div>
{:else}
  {#if flow.phase === 'review' || flow.phase === 'probing' || flow.phase === 'starting'}
    <p class="opacity-70 mb-4">Проверка выполнена, на системе пока ничего не изменено.</p>
    <div class="card bg-base-200 mb-4">
      <div class="card-body gap-2">
        <h2 class="card-title text-base">Что получится</h2>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm" data-testid="summary">
          {#each summarize(p) as [k, v] (k)}<dt class="opacity-70">{k}</dt><dd>{v}</dd>{/each}
        </dl>
        <button class="btn btn-ghost btn-sm self-start" onclick={() => dispatch({ type: 'toggle_details' })} data-testid="details-toggle">
          {#if flow.details}<ChevronUp size={16} />{:else}<ChevronDown size={16} />{/if} Подробнее
        </button>
        {#if flow.details}
          <div class="grid gap-3 sm:grid-cols-2" data-testid="details">
            {#if p.kind === 'lxc'}
              {#each LXC_FIELDS as f (f)}
                {#if f === 'ip'}
                  <div class="form-control sm:col-span-2">
                    <span class="label-text mb-1">{LABELS.ip}</span>
                    <div class="join">
                      <input class="join-item btn btn-sm" type="radio" name="ipmode" aria-label="DHCP" checked={!hasStaticIP(p, flow.dirty)} onchange={() => dispatch({ type: 'edit_field', field: 'ip', value: 'dhcp' })} />
                      <input class="join-item btn btn-sm" type="radio" name="ipmode" aria-label="Статический" checked={hasStaticIP(p, flow.dirty)} onchange={() => dispatch({ type: 'edit_field', field: 'ip', value: p.params.ip !== 'dhcp' ? p.params.ip : '' })} />
                    </div>
                    {#if hasStaticIP(p, flow.dirty) || flow.dirty.ip === ''}
                      <input class="input input-bordered w-full mt-2" placeholder="192.168.1.20/24" value={fieldValue(p, flow.dirty, 'ip') === 'dhcp' ? '' : fieldValue(p, flow.dirty, 'ip')} oninput={(e) => dispatch({ type: 'edit_field', field: 'ip', value: e.currentTarget.value })} data-testid="field-ip" />
                    {/if}
                  </div>
                {:else if f === 'gateway'}
                  {#if hasStaticIP(p, flow.dirty) || flow.dirty.ip === ''}
                    <label class="form-control">
                      <span class="label-text mb-1">{LABELS.gateway}</span>
                      <input class="input input-bordered w-full" placeholder="по умолчанию — шлюз моста" value={fieldValue(p, flow.dirty, 'gateway')} oninput={(e) => dispatch({ type: 'edit_field', field: 'gateway', value: e.currentTarget.value })} data-testid="field-gateway" />
                    </label>
                  {/if}
                {:else if f === 'node' || f === 'storage' || f === 'template_storage' || f === 'bridge'}
                  {@const opts = f === 'node' ? p.choices.nodes : f === 'storage' ? p.choices.storages.map((s) => s.name) : f === 'template_storage' ? p.choices.template_storages : p.choices.bridges}
                  <label class="form-control">
                    <span class="label-text mb-1">{LABELS[f]}</span>
                    <select class="select select-bordered w-full" value={fieldValue(p, flow.dirty, f)} onchange={(e) => dispatch({ type: 'edit_field', field: f, value: e.currentTarget.value })} data-testid="field-{f}">
                      {#each opts as o (o)}<option value={o}>{o}</option>{/each}
                    </select>
                  </label>
                {:else}
                  <label class="form-control">
                    <span class="label-text mb-1">{LABELS[f]}</span>
                    <input class="input input-bordered w-full" value={fieldValue(p, flow.dirty, f)} oninput={(e) => dispatch({ type: 'edit_field', field: f, value: e.currentTarget.value })} data-testid="field-{f}" />
                  </label>
                {/if}
              {/each}
            {:else}
              <label class="form-control">
                <span class="label-text mb-1">Порт Hestia</span>
                <input class="input input-bordered w-full" inputmode="numeric" value={fieldValue(p, flow.dirty, 'port')} oninput={(e) => dispatch({ type: 'edit_field', field: 'port', value: e.currentTarget.value })} data-testid="field-port" />
              </label>
            {/if}
            <div class="sm:col-span-2">
              <button class="btn btn-sm" onclick={() => check(true)} disabled={busy} data-testid="recheck">Применить и проверить заново</button>
            </div>
          </div>
        {/if}
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
        <p class="text-xs opacity-60">Если на каком-то шаге до переключения случится ошибка, созданное этой установкой будет удалено, а Hestia на этом ПК останется как была.</p>
      </div>
    </div>
    {#if flow.error}<div class="alert alert-error mb-3 text-sm" role="alert">{flow.error}</div>{/if}
    <div class="flex gap-2">
      <button class="btn btn-primary" onclick={install} disabled={busy} data-testid="install">
        {#if flow.phase === 'starting'}<span class="loading loading-spinner loading-sm"></span>{/if}
        Установить
      </button>
      <button class="btn" onclick={() => dispatch({ type: 'back' })} disabled={busy}>Другая цель</button>
    </div>
  {:else}
    <h2 class="font-semibold mb-2">Установка</h2>
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
      <div class="alert alert-success mb-3" role="alert"><CircleCheck size={18} /> Готово: Hestia работает на сервере.</div>
      {#if flow.result}
        <div class="card bg-base-200 mb-4">
          <div class="card-body gap-2">
            <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm" data-testid="result">
              {#each resultSummary(flow.result) as [k, v] (k)}<dt class="opacity-70">{k}</dt><dd class="font-mono">{v}</dd>{/each}
            </dl>
            {#if flow.result.hint}<p class="text-sm" data-testid="dhcp-hint">{flow.result.hint}</p>{/if}
          </div>
        </div>
        <p class="text-sm opacity-70 mb-2">Переходим на новый адрес{countdown > 0 ? ` через ${countdown} с` : ''}…</p>
        <button class="btn btn-primary" onclick={go} data-testid="go-now">Перейти сейчас</button>
      {:else}
        <p class="text-sm opacity-70 mb-2">Адрес нового контроллера смотрите в журнале задачи.</p>
        <a class="btn" href={'#/jobs/' + encodeURIComponent(flow.job.id)}>Журнал</a>
      {/if}
    {:else if flow.phase === 'failed'}
      <div class="alert alert-error mb-3" role="alert">{flow.error}</div>
      <div class="flex gap-2">
        <button class="btn btn-primary" onclick={() => dispatch({ type: 'retry' })}>Повторить</button>
        <a class="btn" href={'#/jobs/' + encodeURIComponent(flow.job.id)}>Журнал</a>
        <button class="btn" onclick={() => dispatch({ type: 'back' })}>Другая цель</button>
      </div>
    {/if}
  {/if}
{/if}
