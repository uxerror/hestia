# 02a. Этап 0 — каркас

Цель: один бинарник `hestia` с режимами `serve` и `desktop`, встроенная SPA, SQLite, задачи
(jobs) с прогрессом по SSE, первый администратор и вход. Никакой работы с сетью/Proxmox.

## Сборка

- Go-модуль `hestia`, Go ≥ 1.26.
- Две сборки одного кода:
  - серверная: `CGO_ENABLED=0 go build ./cmd/hestia` — статический бинарник для LXC/серверов,
    без GTK/WebKit. Режим `desktop` в ней печатает «собрано без desktop» и выходит с кодом 2;
  - десктопная: `go build -tags desktop,gtk3 ./cmd/hestia` — Wails v3 (v3.1.0), cgo. Тег `gtk3`
    обязателен: по умолчанию Wails v3.1 берёт GTK4/webkitgtk-6.0, на Garuda стоит webkit2gtk-4.1.
  Весь код Wails — только в файлах с `//go:build desktop`.
- Фронтенд собирается до Go (`web/dist` встраивается через `web/embed.go`).

## Режимы

- `hestia serve [--listen :8080] [--data ./data]` — HTTP: `/api/v1/...` + SPA (fallback на
  index.html для не-API путей).
- `hestia desktop [--data ~/.local/share/hestia]` — окно Wails v3; AssetServer.Handler = тот же
  http.Handler, что у serve (API + SPA). TCP-порт не открывается. Фронтенд ходит на
  относительные `/api/v1/...` в обоих режимах.
- `hestia version`.

## Данные

`<data>/hestia.db` (SQLite, modernc.org/sqlite, WAL, foreign_keys), миграции по номерам в
таблице `schema_migrations`. Каталог данных 0700, файл БД 0600.

Таблицы этапа 0: `users(id, username UNIQUE, password_hash, created_at)`,
`sessions(token_hash PK, user_id, created_at, expires_at)`,
`jobs(id, kind, title, status, created_at, started_at, finished_at, error)`,
`job_steps(job_id, idx, title, status, started_at, finished_at, error)`,
`job_log(id, job_id, at, level, line)`.

## API (JSON, ошибки `{"error":"текст"}`)

Без входа:
- `GET  /api/v1/health` → `{"status":"ok","version":"..."}`
- `GET  /api/v1/setup` → `{"needs_admin":bool,"mode":"serve"|"desktop"}`
- `POST /api/v1/setup/admin {username,password}` → 201 + сессия (cookie) + `{"user":{id,username}}`;
  409, если админ уже есть (атомарно в БД: вставка только при пустой таблице users).
  Пароль ≥ 8 символов, логин `^[a-z0-9_.-]{2,32}$` → 400.
- `POST /api/v1/auth/login {username,password}` → 200 + cookie | 401.

С входом (cookie `hestia_session`, HttpOnly, SameSite=Strict; в БД хранится sha256 токена):
- `POST /api/v1/auth/logout` → 204
- `GET  /api/v1/auth/me` → `{"user":{id,username}}` | 401
- `GET  /api/v1/jobs` → `{"jobs":[Job]}` (последние 50)
- `GET  /api/v1/jobs/{id}` → `{"job":Job}` где Job = `{id,kind,title,status,created_at,
  started_at,finished_at,error,steps:[{idx,title,status,error}],log:[{at,level,line}]}`
- `GET  /api/v1/jobs/{id}/events` → SSE: события `step`, `log`, `status` (data = JSON),
  при подключении сначала снимок `snapshot` (data = Job). Закрывается после финального `status`.
- `POST /api/v1/jobs/demo` → 202 `{"job":Job}` — демонстрационная задача из 3 шагов по ~1 с
  (только чтобы проверить UI прогресса; удалим/спрячем позже).

Статусы: задачи `queued|running|done|failed|cancelled`, шага `pending|running|done|failed|skipped`.

## Jobs

`internal/jobs`: Runner запускает функцию задачи в горутине; API для кода задачи:
`Step(title, func(ctx) error)`, `Log(level, line)`. Всё пишется в БД и публикуется
подписчикам (hub). При старте процесса незавершённые задачи помечаются `failed`
("прервано перезапуском").

## Фронтенд

Svelte 5 + Vite + Tailwind 4 + DaisyUI 5 + lucide-svelte (база — как в Iris web/).
Экраны:
1. Создание администратора (если `needs_admin`).
2. Вход.
3. Мастер, шаг 1 «Что подключаем?»: три карточки — «Готовый Proxmox», «Отдельный сервер»
   (обе пока ведут на заглушку «на следующем этапе»), «Чистый Debian → Proxmox» — серая,
   неактивная, бейдж «скоро».
4. Экран «Задачи»: список + карточка задачи с шагами и логом в реальном времени (SSE);
   кнопка «Демо-задача».
Тема DaisyUI светлая/тёмная по системе. Тексты интерфейса — русский.
