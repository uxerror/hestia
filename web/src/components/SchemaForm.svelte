<script>
  import { splitAdvanced, applyPreset, targetOptions, advancedNeedsOpen } from '../lib/schemaform.js';

  // A form built from a plugin schema. The logic lives in lib/schemaform.js;
  // this component only renders the controls.
  //  fields, presets — from manifest.schema;
  //  values — form values (bind:values), see initialValues();
  //  errors — {field: message} (client validation or the server's 422);
  //  targets — candidates of GET /plugins/targets (null while loading);
  //  secretsSet — names of secret fields that already have a stored value.
  let { fields = [], presets = [], values = $bindable({}), errors = {}, targets = null, secretsSet = [], disabled = false } = $props();

  const uid = $props.id();
  const parts = $derived(splitAdvanced(fields));
  let showAdvanced = $state(false);

  // An error in a hidden field opens «Подробнее».
  $effect(() => {
    if (advancedNeedsOpen(fields, errors)) showAdvanced = true;
  });

  function usePreset(p) {
    values = applyPreset(values, p, fields);
  }
</script>

{#snippet control(f)}
  {@const id = `${uid}-${f.name}`}
  {@const err = errors?.[f.name]}
  <div class="grid gap-1" data-testid={'field-' + f.name}>
    {#if f.type === 'bool'}
      <label class="label cursor-pointer justify-start gap-3" for={id}>
        <input {id} type="checkbox" class="toggle toggle-sm" bind:checked={values[f.name]} {disabled} />
        <span class="label-text text-sm">{f.label}{#if f.required}<span class="text-error"> *</span>{/if}</span>
      </label>
    {:else}
      <label class="label-text text-sm" for={id}>
        {f.label}{#if f.required}<span class="text-error"> *</span>{/if}
        {#if f.type === 'secret' && secretsSet.includes(f.name)}<span class="badge badge-sm badge-success ml-1">задан</span>{/if}
      </label>
      {#if f.type === 'text'}
        <textarea {id} class="textarea textarea-bordered textarea-sm w-full" class:textarea-error={err} rows="4" maxlength={f.max_len > 0 ? f.max_len : undefined} bind:value={values[f.name]} {disabled}></textarea>
      {:else if f.type === 'int'}
        <input {id} type="number" step="1" class="input input-bordered input-sm w-full" class:input-error={err} min={f.min} max={f.max} bind:value={values[f.name]} {disabled} />
      {:else if f.type === 'enum'}
        <select {id} class="select select-bordered select-sm w-full" class:select-error={err} bind:value={values[f.name]} {disabled}>
          {#if !f.required || !values[f.name]}<option value="">—</option>{/if}
          {#each f.options || [] as o (o.value)}<option value={o.value}>{o.label || o.value}</option>{/each}
        </select>
      {:else if f.type === 'secret'}
        <input
          {id}
          type="password"
          class="input input-bordered input-sm w-full"
          class:input-error={err}
          autocomplete="new-password"
          placeholder={secretsSet.includes(f.name) ? 'Оставьте пустым, чтобы не менять' : ''}
          bind:value={values[f.name]}
          {disabled}
        />
      {:else if f.type === 'target'}
        {@const opts = targetOptions(f, targets)}
        {#if targets === null}
          <div class="flex items-center gap-2 text-sm opacity-70"><span class="loading loading-spinner loading-xs"></span> Загружаем список серверов…</div>
        {:else}
          <select {id} class="select select-bordered select-sm w-full" class:select-error={err} bind:value={values[f.name]} {disabled}>
            <option value="">— выберите —</option>
            {#each opts as o (o.id)}
              <option value={o.id} disabled={o.disabled} title={o.reason}>{o.label}{o.disabled ? ` — ${o.reason}` : ''}</option>
            {/each}
          </select>
          {#if opts.length === 0}
            <span class="text-xs opacity-70">Нет серверов. Подключите сервер на экране <a class="link" href="#/wizard">«Подключение»</a>.</span>
          {:else if opts.every((o) => o.disabled)}
            <span class="text-xs text-warning">Нет подходящих серверов: {opts[0].reason}.</span>
          {/if}
        {/if}
      {:else}
        <input {id} type="text" class="input input-bordered input-sm w-full" class:input-error={err} maxlength={f.max_len > 0 ? f.max_len : undefined} bind:value={values[f.name]} {disabled} />
      {/if}
    {/if}
    {#if f.help}<span class="text-xs opacity-70">{f.help}</span>{/if}
    {#if err}<span class="text-error text-xs" data-testid={'error-' + f.name}>{err}</span>{/if}
  </div>
{/snippet}

<div class="grid gap-3" data-testid="schema-form">
  {#if presets.length}
    <div class="flex flex-wrap items-center gap-2" data-testid="presets">
      <span class="text-sm opacity-70">Набор настроек:</span>
      {#each presets as p (p.name)}
        <button type="button" class="btn btn-xs btn-outline" onclick={() => usePreset(p)} {disabled}>{p.label || p.name}</button>
      {/each}
    </div>
  {/if}

  {#each parts.basic as f (f.name)}{@render control(f)}{/each}

  {#if parts.advanced.length}
    <div class="collapse collapse-arrow bg-base-200" class:collapse-open={showAdvanced}>
      <button type="button" class="collapse-title text-sm font-medium min-h-0 py-2 text-left" onclick={() => (showAdvanced = !showAdvanced)} aria-expanded={showAdvanced}>Подробнее</button>
      {#if showAdvanced}
        <div class="collapse-content grid gap-3">
          {#each parts.advanced as f (f.name)}{@render control(f)}{/each}
        </div>
      {/if}
    </div>
  {/if}

  {#if fields.length === 0}<p class="text-sm opacity-70">У плагина нет настроек.</p>{/if}
</div>
