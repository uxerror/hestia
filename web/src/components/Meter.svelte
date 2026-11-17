<script>
  // A labelled progress bar. value is an integer percent (null = unknown).
  let { label, value = null, text = '', warn = 75, danger = 90 } = $props();
  const cls = $derived(value == null ? '' : value >= danger ? 'progress-error' : value >= warn ? 'progress-warning' : 'progress-success');
</script>

<div class="flex items-center gap-2 text-xs">
  <span class="w-14 shrink-0 opacity-70">{label}</span>
  <progress class="progress {cls} flex-1" value={value ?? 0} max="100" aria-label={label}></progress>
  <span class="w-28 shrink-0 text-right tabular-nums">{text}</span>
</div>
