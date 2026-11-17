export const USERNAME_RE = /^[a-z0-9_.-]{2,32}$/;

export function validateUsername(v) {
  if (!v) return 'Введите логин';
  if (!USERNAME_RE.test(v)) return 'Логин: 2–32 символа, только a–z, 0–9, «_», «.», «-»';
  return '';
}

export function validatePassword(v) {
  if (!v) return 'Введите пароль';
  if (v.length < 8) return 'Пароль должен быть не короче 8 символов';
  return '';
}
