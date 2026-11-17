<script>
  import { Server, HardDrive, Boxes } from 'lucide-svelte';
  const cards = [
    { kind: 'proxmox', title: 'Готовый Proxmox', text: 'Подключить уже установленный Proxmox VE.', icon: Boxes, href: '#/wizard/proxmox' },
    { kind: 'server', title: 'Отдельный сервер', text: 'Подключить сервер по SSH без Proxmox.', icon: Server, href: '#/wizard/server' },
    { kind: 'debian', title: 'Чистый Debian → Proxmox', text: 'Установить Proxmox VE на чистый Debian.', icon: HardDrive, disabled: true },
  ];
</script>

<h1 class="text-2xl font-bold mb-1">Что подключаем?</h1>
<p class="opacity-70 mb-6">Шаг 1. Выберите, с чего начать.</p>
<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
  {#each cards as c (c.kind)}
    {#if c.disabled}
      <div class="card bg-base-200 opacity-50 cursor-not-allowed grayscale" aria-disabled="true" data-card={c.kind}>
        <div class="card-body">
          <c.icon size={32} />
          <h2 class="card-title">{c.title} <span class="badge badge-neutral">скоро</span></h2>
          <p class="text-sm">{c.text}</p>
        </div>
      </div>
    {:else}
      <a href={c.href} class="card bg-base-200 hover:bg-base-300 hover:shadow transition" data-card={c.kind}>
        <div class="card-body">
          <c.icon size={32} class="text-primary" />
          <h2 class="card-title">{c.title}</h2>
          <p class="text-sm">{c.text}</p>
        </div>
      </a>
    {/if}
  {/each}
</div>
