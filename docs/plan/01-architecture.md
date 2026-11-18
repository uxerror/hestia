# 01. Архитектура

## Компоненты

```
 ┌──────────── ПК пользователя (Linux) ─────────────┐
 │ Hestia Desktop                                    │
 │  ├─ окно (webview) ── тот же Svelte UI           │
 │  ├─ встроенный контроллер (bootstrap-режим)       │
 │  └─ (позже) агент ПК: mount, CA trust, репо       │
 └───────────────┬───────────────────────────────────┘
                 │ HTTP(S) / JSON API
 ┌───────────────▼──────────── сервер ───────────────┐
 │ Hestia Controller (LXC на Proxmox или systemd)    │
 │  ├─ REST API + веб-панель (embed web/dist)        │
 │  ├─ SQLite: цели, секреты, инвентарь, задачи      │
 │  ├─ транспорт: Proxmox API │ SSH key │ SSH pass   │
 │  ├─ discovery: узлы, гости, скан сети, отпечатки  │
 │  └─ плагины (позже): dns, ca, samba, gitea, ...   │
 └───────────────────────────────────────────────────┘
```

Один Go-бинарник `hestia`, режимы:
- `hestia desktop` — окно + встроенный контроллер на localhost (bootstrap);
- `hestia serve` — контроллер + веб-панель (на сервере);
- `hestia agent` — (позже) агент на ПК/цели.

### Desktop

Wails v3 с тем же Svelte-фронтендом. Запасной вариант, если упрёмся, — `hestia serve`
на localhost + браузер.

До самоустановки фронтенд ходит во встроенный контроллер. После — в удалённый
(`http://<IP>` или `http://hestia.home`); локальное состояние переносится и локальный
контроллер больше не используется.

### Controller

- HTTP API `/api/v1/...`, SSE для прогресса долгих задач (установка, скан).
- Долгие операции — задачи (jobs) с шагами и логом; UI показывает прогресс, повтор шага.
- Хранилище — SQLite (modernc, без cgo — как в hestia-backend).
- Секреты (пароли, ключи, токены) — в БД, шифрование мастер-ключом из файла с правами 600
  рядом с БД. Пароли после перевода на ключ/токен не хранятся.
- Аутентификация панели: первый вход создаёт администратора (атомарно в БД, как в Iris).

## Транспорт («как выполнить действие на цели»)

Интерфейс `Target`: `Exec(cmd)`, `Put(path, data, mode)`, `Get(path)`, `Facts()`.
Реализации:
- **Proxmox API** — узел через API-токен (`/api2/json`): ресурсы, хранилища, гости, создание
  LXC; исполнение внутри гостя — `pct exec` / `qm guest exec` (через SSH на узел, т.к. в API
  нет pct exec).
- **SSH key** — ключ Hestia (ed25519, генерируется при первом запуске).
- **SSH password** — только первый вход: положить ключ Hestia в `authorized_keys`, дальше key.

Для Proxmox при первом входе (root/пароль или ключ): создать пользователя `hestia@pve`,
роль с минимально нужными правами, API-токен; положить SSH-ключ Hestia на узлы для exec.

## Discovery (только чтение)

Источники (то, что мы вручную делали в аудите ../../../../README.md):
- Proxmox API: узлы (CPU, RAM, uptime), хранилища (размер/занято), гости (VMID, имя, статус,
  ресурсы, IP через guest agent / LXC config), кластер/кворум;
- скан подсети: ARP/ping-sweep, TCP connect по набору портов, баннеры HTTP/TLS/SSH, mDNS;
- отпечатки сервисов (fingerprints): правило «порт + проба + признак» → тип сервиса
  (AdGuard, Nginx Proxy Manager, Gitea, Samba, Iris, Proxmox, PBS, Synology, MikroTik...).

Результат — инвентарь: хосты, гости, сервисы, связи (гость → узел, сервис → хост,
DNS-имя → IP). Из него строится карта сети.

## Плагины

Плагин = отдельный процесс (RPC, SDK на Go), манифест (provides/requires, схема полей, пресеты,
права), подпись автора. Разделы: `schema`, `presets`, `install`, `adopt`, `audit`, `client`,
`health`, реализация связей. UI строит формы по `schema` — новый плагин не требует кода во
фронтенде. Подробно — 04-ecosystem.md.

Интеграции с найденными сервисами (как AdGuard на этапе 1) остаются; полная работа — через плагин.

## Структура репозитория (план)

```
cmd/hestia/            точка входа, режимы desktop/serve/agent
internal/api/          роутер, middleware, обработчики, SSE
internal/store/        SQLite, миграции
internal/secrets/      шифрование секретов
internal/jobs/         задачи с шагами и логом
internal/target/       транспорт: proxmox, ssh
internal/proxmox/      клиент Proxmox API
internal/discovery/    скан, отпечатки, инвентарь
internal/selfinstall/  развёртывание контроллера на цели, перенос состояния
internal/integrations/adguard/
internal/desktop/      окно (Wails/webview)
web/                   Svelte 5 + Vite + Tailwind 4 + DaisyUI 5
docs/plan/
```
