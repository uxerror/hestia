<script>
  import { validateUsername, validatePassword } from '../lib/validate.js';
  import { Flame } from 'lucide-svelte';

  let { title, hint, submitLabel, onsubmit, newPassword = false } = $props();
  let username = $state('');
  let password = $state('');
  let touched = $state(false);
  let busy = $state(false);
  let formError = $state('');

  const uErr = $derived(touched ? validateUsername(username) : '');
  const pErr = $derived(touched ? validatePassword(password) : '');

  async function submit(e) {
    e.preventDefault();
    touched = true;
    formError = '';
    if (validateUsername(username) || validatePassword(password)) return;
    busy = true;
    try {
      await onsubmit(username, password);
    } catch (err) {
      formError = err.message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="min-h-screen flex items-center justify-center p-4">
  <form class="card bg-base-200 shadow w-full max-w-sm" onsubmit={submit} novalidate>
    <div class="card-body gap-3">
      <div class="flex items-center gap-2 text-primary"><Flame size={28} /><span class="text-2xl font-bold">Hestia</span></div>
      <h1 class="card-title">{title}</h1>
      <p class="text-sm opacity-70">{hint}</p>

      <label class="form-control">
        <span class="label-text mb-1">Логин</span>
        <input class="input input-bordered w-full" class:input-error={uErr} bind:value={username}
          autocomplete="username" autocapitalize="off" spellcheck="false" disabled={busy} />
        {#if uErr}<span class="text-error text-sm mt-1">{uErr}</span>{/if}
      </label>

      <label class="form-control">
        <span class="label-text mb-1">Пароль</span>
        <input type="password" class="input input-bordered w-full" class:input-error={pErr} bind:value={password}
          autocomplete={newPassword ? 'new-password' : 'current-password'} disabled={busy} />
        {#if pErr}<span class="text-error text-sm mt-1">{pErr}</span>{/if}
      </label>

      {#if formError}<div class="alert alert-error text-sm" role="alert">{formError}</div>{/if}

      <button class="btn btn-primary" type="submit" disabled={busy}>
        {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
        {submitLabel}
      </button>
    </div>
  </form>
</div>
