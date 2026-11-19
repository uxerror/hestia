<script>
  import { onMount } from 'svelte';
  import NewLink from './NewLink.svelte';
  import LinkPanel from './LinkPanel.svelte';

  // A dialog around the link panels for the plugin page: «Связать…» of an instance (choose
  // its port, then the second side from a list) or the removal of a link.
  //  graph — GET /graph; instanceId — the instance to link (mode 'new');
  //  link — a link of the graph (mode 'remove'); onchanged() — a job finished; onclose(changed).
  let { graph, mode = 'new', instanceId = 0, link = null, onchanged, onclose } = $props();

  let dlg = $state();
  let portValue = $state('');
  let changed = false;

  const inst = $derived((graph?.instances || []).find((i) => i.id === instanceId));
  const ports = $derived([
    ...(inst?.provides || []).map((p) => ({ value: `provides|${p.name}`, label: `Отдаёт: ${p.label || p.name} (${p.type})` })),
    ...(inst?.requires || []).map((p) => ({ value: `requires|${p.name}`, label: `Получает: ${p.label || p.name} (${p.type})` })),
  ]);
  $effect(() => {
    if (!portValue && ports.length === 1) portValue = ports[0].value;
  });
  const own = $derived.by(() => {
    const [dir, port] = portValue.split('|');
    return port ? { instance: instanceId, port, dir } : null;
  });

  onMount(() => dlg?.showModal());
  const close = () => dlg?.close();
</script>

<dialog bind:this={dlg} class="modal" onclose={() => onclose?.(changed)}>
  <div class="modal-box max-w-xl p-0" data-testid="link-dialog">
    {#if mode === 'remove' && link}
      <LinkPanel {link} autoRemove onclose={close} onchanged={() => ((changed = true), onchanged?.())} />
    {:else}
      {#if ports.length > 1}
        <div class="p-4 pb-0 grid gap-1">
          <label class="label-text text-sm" for="link-own-port">Порт «{inst?.name}», который нужно связать</label>
          <select id="link-own-port" class="select select-bordered select-sm w-full" bind:value={portValue} data-testid="link-own-port">
            <option value="">— выберите —</option>
            {#each ports as p (p.value)}<option value={p.value}>{p.label}</option>{/each}
          </select>
        </div>
      {:else if ports.length === 0}
        <div class="p-4 text-sm opacity-80" data-testid="link-no-ports">У экземпляра нет портов для связей.</div>
      {/if}
      {#if own}
        {#key portValue}
          <NewLink {graph} {own} onclose={close} onchanged={() => ((changed = true), onchanged?.())} />
        {/key}
      {:else if ports.length !== 1}
        <div class="modal-action p-4"><button class="btn btn-sm" onclick={close}>Закрыть</button></div>
      {/if}
    {/if}
  </div>
  <form method="dialog" class="modal-backdrop"><button>закрыть</button></form>
</dialog>
