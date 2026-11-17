<script>
  import AuthForm from './AuthForm.svelte';
  import { login } from '../lib/session.svelte.js';
</script>

<AuthForm title="Вход" hint="Введите логин и пароль администратора." submitLabel="Войти" onsubmit={login} />
