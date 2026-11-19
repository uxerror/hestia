<script>
  // The edge of a link on the map: solid for «сервис ↔ сервис», dashed for «сервис → устройство»,
  // the colour is the status of the link, the label is the type (the detail is the tooltip).
  import { BaseEdge, EdgeLabel, getBezierPath } from '@xyflow/svelte';
  import { getContext } from 'svelte';

  let { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, selected = false } = $props();

  // The label is HTML over the map: a click on it opens the panel of the link like a click on the line.
  const pick = getContext('maplink');
  const geom = $derived(getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition }));
  const color = $derived(data?.color || 'var(--color-neutral)');
  const style = $derived(`stroke:${color};stroke-width:${selected ? 3.5 : 2.5};${data?.dashed ? 'stroke-dasharray:7 5;' : ''}`);
</script>

<BaseEdge {id} path={geom[0]} {style} interactionWidth={24} />
<EdgeLabel x={geom[1]} y={geom[2]} selectEdgeOnClick>
  <span
    role="button"
    tabindex="0"
    onclick={() => pick?.(data?.link?.id)}
    onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && pick?.(data?.link?.id)}
    class="rounded px-1.5 py-0.5 text-[10px] leading-none bg-base-100 border cursor-pointer"
    style="border-color:{color}"
    title={data?.detail || ''}
    data-testid="link-label"
  >{data?.label || ''}</span>
</EdgeLabel>
