<script>
  import AuthForm from './AuthForm.svelte';
  import { setupAdmin, boot } from '../lib/session.svelte.js';

  async function submit(u, p) {
    try {
      await setupAdmin(u, p);
    } catch (e) {
      if (e.status === 409) {
        await boot(); // admin already exists -> login screen
        return;
      }
      throw e;
    }
  }
</script>

<AuthForm title="Создание администратора" hint="Первый запуск: создайте учётную запись, с которой вы будете входить в Hestia."
  submitLabel="Создать и войти" newPassword onsubmit={submit} />
