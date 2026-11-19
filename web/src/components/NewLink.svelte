<script>
  import { untrack, onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { fieldsOf, presetsOf, initialValues, validate, toConfig } from '../lib/schemaform.js';
  import { candidateOptions, parseChoice, newLinkRequest, providerSide, providerPort, linkPlanError } from '../lib/linkpanel.js';
  import SchemaForm from './SchemaForm.svelte';
  import PlanRun from './PlanRun.svelte';
  import { TriangleAlert, X, ArrowRight } from 'lucide-svelte';

  // «Новая связь»: the sides, the form of the provider's link_schema, the plan and the job.
  //  graph — GET /graph; own — {instance, port, dir} the link starts from;
  //  peer — the second side when known (a drop on the map): {kind: 'port', instance, port} |
  //         {kind: 'device', ref, name?}; otherwise it is chosen from the list of candidates;
  //  onclose(); onchanged() — the job finished (refresh the map).
  let { graph, own, peer: peer0 = null, onclose, onchanged } = $props();
  const o0 = untrack(() => own);

  let choice = $state('');
  let options = $state(untrack(() => (peer0 ? [] : null))); // candidates as options (null while loading)
  let plugin = $state(null); // the provider's plugin (link_schema)
  let values = $state({});
  let errors = $state({});
  let busy = $state(false);
  let error = $state('');
  let plan = $state(null);
  let changed = false;

  const instOf = (id) => (graph?.instances || []).find((i) => i.id === id);
  const portOfInst = (id, dir, name) => (instOf(id)?.[dir] || []).find((p) => p.name === name);
  const ownInst = instOf(o0.instance);
  const ownPort = portOfInst(o0.instance, o0.dir, o0.port);
  const hostOf = (ref) => (graph?.hosts || []).find((h) => h.ref === ref);

  const peer = $derived(peer0 || (choice ? parseChoice(choice) : null));
  const side = $derived(providerSide(o0, peer));
  const fields = $derived(fieldsOf(providerPort(plugin, side?.port)?.link_schema));
  const presets = $derived(presetsOf(providerPort(plugin, side?.port)?.link_schema));

  onMount(() => {
    if (peer0) return;
    api
      .linkCandidates(o0.instance, o0.port, o0.dir)
      .then((c) => (options = candidateOptions(c)))
      .catch((e) => {
        options = [];
        error = e.message;
      });
  });

  // The form of the provider's link_schema comes with its plugin.
  $effect(() => {
    const s = side;
    plugin = null;
    if (!s) return;
    const pid = instOf(s.instance)?.plugin_id;
    if (!pid) return;
    let gone = false;
    api
      .plugin(pid)
      .then((p) => {
        if (gone) return;
        plugin = p;
        values = initialValues(fieldsOf(providerPort(p, s.port)?.link_schema), null);
      })
      .catch((e) => !gone && (error = e.message));
    return () => (gone = true);
  });


  const peerText = $derived.by(() => {
    if (!peer) return '';
    if (peer.kind === 'device') {
      const h = hostOf(peer.ref);
      return peer.name || (h ? `${h.names?.[0]?.name || h.ip} (${h.ip})` : peer.ref);
    }
    const i = instOf(peer.instance);
    const p = portOfInst(peer.instance, o0.dir === 'provides' ? 'requires' : 'provides', peer.port);
    return `${i?.name || 'экземпляр ' + peer.instance} · ${p?.label || peer.port}`;
  });
  const ownText = $derived(`${ownInst?.name || 'экземпляр ' + o0.instance} · ${ownPort?.label || o0.port}`);
  const kindText = $derived(peer?.kind === 'device' ? 'Сервис → устройство' : 'Сервис ↔ сервис');
  const leftLabel = $derived(o0.dir === 'provides' ? 'Поставщик' : 'Потребитель');
  const rightLabel = $derived(peer?.kind === 'device' ? 'Устройство' : o0.dir === 'provides' ? 'Потребитель' : 'Поставщик');

  async function makePlan() {
    error = '';
    const req = newLinkRequest(o0, peer, {});
    if (!req) {
      error = 'Выберите вторую сторону связи';
      return;
    }
    errors = validate(fields, values);
    if (Object.keys(errors).length) {
      error = 'Проверьте поля формы';
      return;
    }
    req.config = toConfig(fields, values);
    busy = true;
    try {
      plan = await api.planLink(req);
    } catch (e) {
      const pe = linkPlanError(e);
      if (pe.kind === 'fields') errors = pe.fields;
      error = pe.message;
    } finally {
      busy = false;
    }
  }

  function finished() {
    changed = true;
    onchanged?.();
  }
</script>

<div class="card bg-base-200 h-full" data-testid="new-link">
  <div class="card-body p-4 gap-3">
    <div class="flex items-start justify-between gap-2">
      <h2 class="font-bold text-lg">Новая связь</h2>
      <button class="btn btn-ghost btn-xs btn-circle" onclick={() => onclose?.(changed)} aria-label="Закрыть"><X size={16} /></button>
    </div>

    <div class="grid gap-1 text-sm" data-testid="link-sides">
      <div class="flex flex-wrap items-center gap-2">
        <span class="opacity-60 w-24 shrink-0">{leftLabel}</span><span class="font-medium break-words">{ownText}</span>
      </div>
      <div class="flex items-center gap-2 opacity-60"><ArrowRight size={14} class="rotate-90" /> {kindText}{ownPort?.type ? ' · ' + ownPort.type : ''}</div>
      <div class="flex flex-wrap items-center gap-2">
        <span class="opacity-60 w-24 shrink-0">{rightLabel}</span>
        {#if peer0}
          <span class="font-medium break-words" data-testid="link-peer">{peerText}</span>
        {:else if options === null}
          <span class="loading loading-spinner loading-xs"></span>
        {:else}
          <select class="select select-bordered select-sm flex-1 min-w-0" bind:value={choice} disabled={!!plan || busy} data-testid="link-choose">
            <option value="">— выберите —</option>
            {#each ['Сервисы', 'Устройства'] as g (g)}
              {#if options.some((x) => x.group === g)}
                <optgroup label={g}>
                  {#each options.filter((x) => x.group === g) as x (x.value)}
                    <option value={x.value} disabled={x.disabled} title={x.reason}>{x.label}{x.disabled ? ` — ${x.reason}` : ''}</option>
                  {/each}
                </optgroup>
              {/if}
            {/each}
          </select>
          {#if options.length === 0}<span class="text-xs opacity-70 w-full">Подходящих сторон нет.</span>{/if}
        {/if}
      </div>
    </div>

    {#if error}
      <div class="alert alert-warning text-sm" role="alert" data-testid="link-error"><TriangleAlert size={16} /> <span>{error}</span></div>
    {/if}

    {#if !plan}
      {#if peer && !plugin}
        <div class="flex items-center gap-2 text-sm opacity-70"><span class="loading loading-spinner loading-xs"></span> Загружаем настройки связи…</div>
      {:else if peer}
        {#if fields.length}<SchemaForm {fields} {presets} bind:values {errors} disabled={busy} />{/if}
      {/if}
      <div class="flex justify-end gap-2">
        <button class="btn btn-sm" onclick={() => onclose?.(changed)}>Отмена</button>
        <button class="btn btn-sm btn-primary" onclick={makePlan} disabled={busy || !peer || !plugin} data-testid="link-make-plan">
          {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if} Показать план
        </button>
      </div>
    {:else}
      <PlanRun {plan} doneText="Связь создана." onback={() => ((plan = null), (error = ''))} onreplan={() => ((plan = null), makePlan())} onfinish={finished} />
    {/if}
  </div>
</div>
