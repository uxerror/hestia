<script>
  import { session, boot, logout, handoffLogin } from './lib/session.svelte.js';
  import { parseHash } from './lib/router.js';
  import SetupAdmin from './pages/SetupAdmin.svelte';
  import Login from './pages/Login.svelte';
  import Wizard from './pages/Wizard.svelte';
  import Stub from './pages/Stub.svelte';
  import Jobs from './pages/Jobs.svelte';
  import JobDetail from './pages/JobDetail.svelte';
  import Connect from './pages/Connect.svelte';
  import Targets from './pages/Targets.svelte';
  import Guests from './pages/Guests.svelte';
  import NetMap from './pages/Map.svelte';
  import Services from './pages/Services.svelte';
  import Install from './pages/Install.svelte';
  import Moved from './pages/Moved.svelte';
  import UpdateOffer from './pages/UpdateOffer.svelte';
  import Plugins from './pages/Plugins.svelte';
  import PluginPage from './pages/PluginPage.svelte';
  import { updateInfo, loadUpdateInfo } from './lib/updateinfo.svelte.js';
  import { badgeText } from './lib/update.js';
  import { Flame, LogOut, User, Puzzle } from 'lucide-svelte';

  let route = $state(parseHash(location.hash));
  let loggingOut = $state(false);

  $effect(() => {
    const r = parseHash(location.hash);
    if (r.name === 'handoff') {
      // The one-time token must not stay in the address bar or the history.
      history.replaceState(null, '', location.pathname + location.search + '#/targets');
      route = parseHash(location.hash);
      handoffLogin(r.token);
    } else {
      boot();
    }
    const h = () => (route = parseHash(location.hash));
    window.addEventListener('hashchange', h);
    return () => window.removeEventListener('hashchange', h);
  });

  // The "update available" badge: refreshed when the app opens and every 30 minutes.
  $effect(() => {
    if (session.phase !== 'app') return;
    loadUpdateInfo();
    const t = setInterval(loadUpdateInfo, 30 * 60 * 1000);
    return () => clearInterval(t);
  });
  const badge = $derived(badgeText(updateInfo.status));

  async function doLogout() {
    loggingOut = true;
    await logout();
    loggingOut = false;
  }
  const section = $derived(
    route.name === 'jobs' || route.name === 'job' ? 'jobs' : route.name === 'map' ? 'map' : route.name === 'services' ? 'services' : route.name === 'plugins' || route.name === 'plugin' ? 'plugins' : route.name === 'targets' || route.name === 'guests' || route.name === 'install' || route.name === 'update-offer' ? 'targets' : 'wizard',
  );
</script>

{#if session.phase === 'loading'}
  <div class="min-h-screen flex flex-col items-center justify-center gap-3">
    {#if session.error}
      <div class="alert alert-error max-w-sm" role="alert">{session.error}</div>
      <button class="btn" onclick={boot}>Повторить</button>
    {:else}
      <span class="loading loading-spinner loading-lg"></span>
    {/if}
  </div>
{:else if session.phase === 'moved'}
  <Moved />
{:else if session.phase === 'setup'}
  <SetupAdmin />
{:else if session.phase === 'login'}
  <Login />
{:else}
  <div class="min-h-screen flex flex-col">
    <div class="navbar bg-base-200 shadow-sm px-4">
      <div class="flex-1 gap-4">
        <a href="#/wizard" class="flex items-center gap-2 text-primary font-bold text-lg"><Flame size={22} /> Hestia</a>
        <ul class="menu menu-horizontal p-0">
          <li><a href="#/wizard" class:menu-active={section === 'wizard'}>Подключение</a></li>
          <li><a href="#/targets" class:menu-active={section === 'targets'}>Системы</a></li>
          <li><a href="#/map" class:menu-active={section === 'map'}>Карта сети</a></li>
          <li><a href="#/services" class:menu-active={section === 'services'}>Сервисы</a></li>
          <li><a href="#/plugins" class:menu-active={section === 'plugins'}><Puzzle size={16} /> Плагины</a></li>
          <li><a href="#/jobs" class:menu-active={section === 'jobs'}>Задачи</a></li>
        </ul>
      </div>
      <div class="flex-none flex items-center gap-2">
        {#if badge}<a href="#/targets" class="badge badge-info gap-1" data-testid="update-badge">{badge}</a>{/if}
        <span class="flex items-center gap-1 text-sm" data-testid="user"><User size={16} /> {session.user?.username}</span>
        <button class="btn btn-ghost btn-sm" onclick={doLogout} disabled={loggingOut}>
          {#if loggingOut}<span class="loading loading-spinner loading-xs"></span>{:else}<LogOut size={16} />{/if}
          Выйти
        </button>
      </div>
    </div>
    {#if session.transferring}
      <div class="alert alert-warning rounded-none justify-center text-sm" role="status" data-testid="transfer-banner">
        <span class="loading loading-spinner loading-xs"></span> Идёт перенос Hestia на сервер — изменения временно заблокированы.
      </div>
    {/if}
    <main class={route.name === 'map' ? 'flex-1 p-3 w-full' : 'flex-1 p-4 sm:p-6 max-w-6xl w-full mx-auto'}>
      {#if route.name === 'jobs'}<Jobs />
      {:else if route.name === 'job'}<JobDetail id={route.id} />
      {:else if route.name === 'targets'}<Targets />
      {:else if route.name === 'map'}<NetMap />
      {:else if route.name === 'services'}<Services />
      {:else if route.name === 'plugins'}<Plugins />
      {:else if route.name === 'plugin'}{#key route.id}<PluginPage id={route.id} />{/key}
      {:else if route.name === 'install'}<Install />
      {:else if route.name === 'update-offer'}{#key route.hash}<UpdateOffer hash={route.hash} />{/key}
      {:else if route.name === 'guests'}{#key route.id}<Guests id={route.id} node={route.node} />{/key}
      {:else if route.name === 'connect'}{#key route.kind}<Connect kind={route.kind} />{/key}
      {:else if route.name === 'next'}<Stub />
      {:else}<Wizard />{/if}
    </main>
  </div>
{/if}
