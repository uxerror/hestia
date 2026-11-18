<script>
  import { onMount, untrack } from 'svelte';
  import { api } from '../lib/api.js';
  import { subscribeJob } from '../lib/sse.js';
  import { STEP_STATUS, fmtTime } from '../lib/jobs.js';
  import { validateDomain, normalizeDomain, suggestedDomain, endpointChoices, planView, connectProblem } from '../lib/dnsname.js';
  import { TriangleAlert, CircleCheck, ExternalLink } from 'lucide-svelte';

  // Wizard "Имя в сети": 1 address (+certificate), 2 login, 3 name → plan, 4 apply.
  // start: 'setup' (from the beginning), 'connection' (change the connection),
  // 'name' (connected, choose the name), 'fix' / 'remove' (plan of the bound name).
  let { dns, start = 'setup', onclose } = $props();
  // The wizard works on the state it was opened with.
  const d0 = untrack(() => dns);

  let dlg = $state();
  let step = $state(1);
  let busy = $state(false);
  let error = $state('');

  // Step 1.
  const cand = d0?.candidates?.[0] ?? null;
  let choices = $derived(endpointChoices(cand));
  let url = $state(d0?.integration?.base_url || cand?.endpoints?.[0]?.url || '');
  let manual = $state(!cand && !d0?.integration);
  let probe = $state(null);
  let pin = $state(d0?.integration?.tls_pin || '');
  let trusted = $state(false);
  // Step 2.
  let username = $state(d0?.integration?.username || '');
  let password = $state('');
  let problem = $state(null);
  let connected = $state(null); // the answer of POST/PUT /dns/adguard
  // Step 3.
  let domain = $state(d0?.name?.domain || suggestedDomain(d0));
  let plan = $state(null);
  let replaceOk = $state(false);
  // Step 4.
  let job = $state(null);
  let jobFailed = $state(false);

  const editing = !!d0?.integration;
  const domainError = $derived(validateDomain(domain));
  const pv = $derived(planView(plan));

  onMount(() => {
    dlg?.showModal();
    if (start === 'name') step = 3;
    else if (start === 'fix') {
      step = 3;
      makePlan('update_ip');
    } else if (start === 'remove') {
      step = 3;
      makePlan('remove');
    } else if (start === 'connection' && d0?.integration) {
      doProbe();
    }
    return () => stopJob?.();
  });

  function close() {
    dlg?.close();
  }

  async function guard(fn) {
    busy = true;
    error = '';
    try {
      await fn();
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }

  function doProbe() {
    return guard(async () => {
      probe = null;
      trusted = false;
      probe = await api.probeAdguard(url.trim());
      if (probe.tls) pin = probe.tls.sha256;
      else pin = '';
    });
  }

  async function connect() {
    busy = true;
    error = '';
    problem = null;
    try {
      const body = { url: url.trim(), tls_pin: pin, username: username.trim(), password };
      connected = editing ? await api.updateAdguard(body) : await api.connectAdguard(body);
      password = '';
      if (connected.default_domain && !d0?.name) domain = connected.default_domain;
      step = 3;
    } catch (e) {
      problem = connectProblem(e);
      if (problem.kind === 'other') error = problem.message;
    } finally {
      busy = false;
    }
  }

  function trustNew() {
    pin = problem.fingerprint;
    problem = null;
    error = 'Новый отпечаток принят. Нажмите «Подключиться» ещё раз, чтобы подтвердить.';
  }

  function makePlan(action) {
    return guard(async () => {
      plan = null;
      replaceOk = false;
      if (action === 'add' || action === 'replace') {
        const v = validateDomain(domain);
        if (v) throw new Error(v);
      }
      plan = await api.dnsPlan(action, normalizeDomain(domain));
      if (plan.domain) domain = plan.domain;
    });
  }

  function apply() {
    return guard(async () => {
      const r = await api.dnsApply(plan.plan_id, plan.hash);
      step = 4;
      job = { status: 'queued', steps: [] };
      jobFailed = false;
      const close = subscribeJob(r.job_id, {
        onUpdate: (j) => {
          job = { ...j, id: r.job_id };
          jobFailed = j.status === 'failed' || j.status === 'cancelled';
        },
      });
      stopJob = close;
    });
  }
  let stopJob = null;

  const done = $derived(job?.status === 'done');
  const removing = $derived(plan?.action === 'remove');
</script>

<dialog bind:this={dlg} class="modal" onclose={() => onclose?.(done)}>
  <div class="modal-box max-w-xl" data-testid="dns-wizard">
    <h3 class="font-bold text-lg mb-3">{removing ? 'Убрать имя Hestia' : 'Имя Hestia в сети'}</h3>

    {#if error}<div class="alert alert-warning text-sm mb-3" role="alert">{error}</div>{/if}

    {#if step === 1}
      <div class="grid gap-3">
        {#if cand && !manual}
          <p class="text-sm">Найден AdGuard Home на <b>{cand.host}</b>. Как к нему подключиться?</p>
          <div class="grid gap-1">
            {#each choices as c (c.url)}
              <label class="label cursor-pointer justify-start gap-3">
                <input type="radio" class="radio radio-sm" name="ep" value={c.url} bind:group={url} onchange={() => (probe = null)} />
                <span class="label-text">{c.label} <span class="opacity-60 font-mono text-xs">{c.url}</span></span>
              </label>
            {/each}
          </div>
          <button class="link text-xs self-start" onclick={() => (manual = true)}>Указать адрес вручную</button>
        {:else}
          <label class="form-control">
            <span class="label-text text-sm mb-1">Адрес AdGuard Home</span>
            <input class="input input-bordered input-sm" placeholder="http://10.10.10.2:3000" bind:value={url} oninput={() => (probe = null)} data-testid="dns-url" />
          </label>
        {/if}

        {#if probe}
          {#if probe.tls}
            <div class="bg-base-200 rounded p-3 text-sm grid gap-1" data-testid="dns-cert">
              <div class="font-semibold">Это сертификат вашего AdGuard?</div>
              <div>Отпечаток SHA-256: <code class="font-mono text-xs break-all">{probe.tls.sha256}</code></div>
              <div>Кому выдан: {probe.tls.subject || '—'}</div>
              <div>Кем выдан: {probe.tls.issuer || '—'}</div>
              {#if probe.tls.san?.length}<div>Имена и адреса: {probe.tls.san.join(', ')}</div>{/if}
              <div>Действует до: {fmtTime(probe.tls.not_after)}</div>
              <label class="label cursor-pointer justify-start gap-3 mt-1">
                <input type="checkbox" class="checkbox checkbox-sm" bind:checked={trusted} data-testid="dns-trust" />
                <span class="label-text">Да, закрепить этот сертификат</span>
              </label>
            </div>
          {/if}
          {#if probe.warning}
            <div class="alert alert-warning text-sm" role="alert"><TriangleAlert size={16} /> {probe.warning}</div>
          {/if}
          {#if probe.location}<div class="text-xs opacity-70">AdGuard перенаправляет на {probe.location}</div>{/if}
        {/if}
      </div>
      <div class="modal-action">
        <button class="btn" onclick={close}>Отмена</button>
        {#if !probe}
          <button class="btn btn-primary" onclick={doProbe} disabled={busy || !url.trim()} data-testid="dns-probe">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Проверить адрес
          </button>
        {:else}
          <button class="btn btn-primary" onclick={() => (step = 2)} disabled={probe.tls && !trusted} data-testid="dns-next">Далее</button>
        {/if}
      </div>
    {:else if step === 2}
      <form class="grid gap-3" onsubmit={(e) => (e.preventDefault(), connect())}>
        <p class="text-sm">Логин и пароль администратора AdGuard. Hestia хранит их зашифрованно и использует только для записи своего имени.</p>
        <label class="form-control">
          <span class="label-text text-sm mb-1">Логин</span>
          <input class="input input-bordered input-sm" autocomplete="off" bind:value={username} data-testid="dns-user" />
        </label>
        <label class="form-control">
          <span class="label-text text-sm mb-1">Пароль{editing ? ' (пусто — оставить прежний)' : ''}</span>
          <input type="password" class="input input-bordered input-sm" autocomplete="new-password" bind:value={password} data-testid="dns-pass" />
        </label>
        {#if problem?.kind === 'auth'}
          <div class="alert alert-error text-sm" role="alert">{problem.message}</div>
        {:else if problem?.kind === 'cert'}
          <div class="alert alert-error text-sm grid gap-1" role="alert" data-testid="dns-cert-changed">
            <div>{problem.message}</div>
            <button type="button" class="btn btn-sm btn-outline justify-self-start" onclick={trustNew}>Доверять новому</button>
          </div>
        {/if}
        <div class="modal-action mt-0">
          <button type="button" class="btn" onclick={() => (step = 1)}>Назад</button>
          <button type="submit" class="btn btn-primary" disabled={busy || (!editing && !password)} data-testid="dns-connect">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Подключиться
          </button>
        </div>
      </form>
    {:else if step === 3}
      {#if connected}
        <div class="text-sm mb-3" data-testid="dns-connected">
          <CircleCheck size={16} class="inline text-success" /> AdGuard Home {connected.server.version} подключён.
          {#each connected.warnings as w (w)}<div class="alert alert-warning text-sm mt-2" role="alert"><TriangleAlert size={16} /> {w}</div>{/each}
        </div>
      {/if}
      {#if !removing && plan?.action !== 'update_ip'}
        <label class="form-control mb-3">
          <span class="label-text text-sm mb-1">Имя Hestia</span>
          <input class="input input-bordered input-sm font-mono" bind:value={domain} oninput={() => (plan = null)} data-testid="dns-domain" />
          {#if domainError && domain}<span class="text-error text-xs mt-1">{domainError}</span>{/if}
        </label>
      {/if}

      {#if plan}
        <div class="bg-base-200 rounded p-3 text-sm grid gap-2" data-testid="dns-plan">
          <div>
            {#if removing}Запись: <b class="font-mono">{plan.domain} → {plan.answer}</b>
            {:else}Имя <b class="font-mono">{plan.domain}</b> будет указывать на <b class="font-mono">{plan.answer}</b> (так Hestia видна из AdGuard).{/if}
          </div>
          {#if plan.actions?.length}
            <ol class="list-decimal ml-5 grid gap-1">
              {#each plan.actions as a (a.id)}<li>{a.title}{#if a.detail} <span class="font-mono text-xs opacity-70">{a.detail}</span>{/if}</li>{/each}
            </ol>
          {/if}
          {#each plan.conflicts as c (c.answer)}
            <div class="alert alert-warning text-sm" role="alert" data-testid="dns-conflict">
              <TriangleAlert size={16} />
              <span>Имя уже занято: {c.domain} → {c.answer}{#if c.owner} ({c.owner}){/if}.</span>
            </div>
          {/each}
          {#each plan.warnings as w (w)}<div class="alert alert-warning text-sm" role="alert"><TriangleAlert size={16} /> {w}</div>{/each}
        </div>
        {#if pv.needsReplace}
          <label class="label cursor-pointer justify-start gap-3 mt-2">
            <input type="checkbox" class="checkbox checkbox-sm" bind:checked={replaceOk} data-testid="dns-replace-ok" />
            <span class="label-text">Заменить чужую запись на адрес Hestia</span>
          </label>
        {/if}
      {/if}

      <div class="modal-action">
        <button class="btn" onclick={close}>Отмена</button>
        {#if !plan}
          <button class="btn btn-primary" onclick={() => makePlan('add')} disabled={busy || !!domainError} data-testid="dns-make-plan">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} Показать план
          </button>
        {:else if pv.needsReplace}
          <button class="btn btn-warning" onclick={() => makePlan('replace')} disabled={busy || !replaceOk} data-testid="dns-replace">Показать план замены</button>
        {:else}
          <button class="btn btn-primary" onclick={apply} disabled={busy || !pv.canApply} data-testid="dns-apply">
            {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if} {removing ? 'Убрать' : 'Применить'}
          </button>
        {/if}
      </div>
    {:else}
      <ul class="grid gap-1 text-sm mb-3" data-testid="dns-job">
        {#each job?.steps || [] as s (s.idx)}
          {@const st = STEP_STATUS[s.status] || { label: s.status, cls: '' }}
          <li class="flex items-center gap-2"><span class="badge badge-sm {st.cls}">{st.label}</span> {s.title}{#if s.error} <span class="text-error text-xs">{s.error}</span>{/if}</li>
        {/each}
      </ul>
      {#if done}
        <div class="alert alert-success text-sm" role="status" data-testid="dns-done">
          <CircleCheck size={18} />
          {removing ? 'Имя убрано.' : `Готово: Hestia открывается по имени ${plan.domain}.`}
        </div>
        <div class="modal-action">
          <button class="btn" onclick={close}>Закрыть</button>
          {#if !removing}<a class="btn btn-primary" href={'http://' + plan.domain} target="_blank" rel="noreferrer noopener"><ExternalLink size={16} /> Открыть http://{plan.domain}</a>{/if}
        </div>
      {:else if jobFailed}
        <div class="alert alert-error text-sm" role="alert" data-testid="dns-failed"><TriangleAlert size={18} /> {job.error || 'Не удалось. Изменения в AdGuard откатаны.'}</div>
        <div class="modal-action">
          {#if job.id}<a class="link text-sm mr-auto" href={'#/jobs/' + encodeURIComponent(job.id)} onclick={close}>Журнал задачи</a>{/if}
          <button class="btn" onclick={close}>Закрыть</button>
        </div>
      {:else}
        <div class="flex items-center gap-2 text-sm"><span class="loading loading-spinner loading-sm"></span> Выполняется…</div>
      {/if}
    {/if}
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
