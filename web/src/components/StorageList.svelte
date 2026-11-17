<script>
  import Meter from './Meter.svelte';
  import { fmtBytes, pct } from '../lib/format.js';
  import { storageTitle } from '../lib/inventory.js';

  let { storages = [] } = $props();
</script>

<div class="overflow-x-auto">
  <table class="table table-sm">
    <thead>
      <tr><th>Хранилище</th><th>Тип</th><th>Содержимое</th><th>Узлы</th><th class="w-72">Занято</th></tr>
    </thead>
    <tbody>
      {#each storages as s (s.name + '@' + s.nodes.join(','))}
        <tr class={s.active ? '' : 'opacity-50'} data-storage={s.name}>
          <td>
            {s.name}
            {#if s.shared}<span class="badge badge-sm badge-info ml-1" title={storageTitle(s)}>shared</span>{/if}
            {#if !s.active}<span class="badge badge-sm badge-warning ml-1">неактивно</span>{/if}
          </td>
          <td>{s.type}</td>
          <td class="text-xs">{s.content.join(', ')}</td>
          <td class="text-xs">{s.nodes.join(', ')}</td>
          <td>
            {#if s.total}
              <Meter label="" value={pct(s.used, s.total)} text="{fmtBytes(s.used)} / {fmtBytes(s.total)}" warn={80} danger={92} />
            {:else}—{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
