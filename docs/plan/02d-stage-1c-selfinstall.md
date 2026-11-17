# 02d. Этап 1c — самоустановка контроллера

Цель: из «Систем» одной кнопкой перенести Hestia с ПК (bootstrap) на подключённую цель —
в непривилегированный LXC на Proxmox или systemd-сервисом на отдельный сервер. Состояние
(SQLite + мастер-ключ) переносится, ПК дальше работает клиентом удалённого контроллера.
Всё, что создаётся на цели, показывается планом до подтверждения и откатывается при ошибке.

## Решения (2026-11-18, с пользователем)

- Узел по умолчанию — online-узел с наибольшей долей свободной RAM (в нашей сети это pve1).
- VMID — отдельный диапазон служебных гостей Hestia: первый свободный, начиная с **900**
  (по `/cluster/resources`, включая шаблоны). Поле редактируемо.
- IP — **DHCP** по умолчанию. В конце показывается MAC и полученный IP с подсказкой
  «закрепите адрес в DHCP роутера (MikroTik: IP → DHCP Server → Leases → Make Static)».
  Настройка MikroTik самой Hestia — позже (плагин роутера, см. 03-roadmap). Статический IP —
  поле в «Подробнее» (адрес/маска + шлюз; по умолчанию шлюз моста), перед созданием — проверка,
  что адрес не отвечает (`ping -c1 -W1` с узла) и не занят гостями из инвентаря.
- Ресурсы: 1 vCPU, 512 МБ RAM, 512 МБ swap, диск 4 ГБ; хранилище корня — `local-lvm`, если
  есть и поддерживает `rootdir`, иначе rootdir-хранилище с наибольшим свободным местом.
- Шаблон: последний `debian-13-standard_*_amd64` из `aplinfo` узла; если его нет в
  vztmpl-хранилище (по умолчанию `local`) — скачать.
- Создание и управление LXC — **через API-токен** `hestia@pve!hestia` (роли хватает: `VM.Allocate`
  разрешает `features: nesting=1` для непривилегированного CT, проверено по PVE 9.2 `LXC.pm`).
  Команды внутри CT — `pct exec` по SSH на узел ключом Hestia (пиннутый host key узла).
- Файлы в CT передаются **через stdin** `pct exec <vmid> -- sh -c 'cat > …'` (без временных файлов
  на узле); целостность — сверка `sha256sum` внутри CT.
- Бинарник для цели — статический linux/amd64 (`CGO_ENABLED=0`). Desktop-сборка несёт его внутри
  (`internal/selfinstall/payload/`, embed; Makefile кладёт туда `build/bin/hestia` перед сборкой
  desktop). Серверная сборка использует собственный `os.Executable()`. Нет бинарника → понятная
  ошибка «эта сборка не содержит серверного бинарника». Архитектура цели не amd64 → ошибка в проверке.
- Порт 80, HTTP. Сервис от пользователя `hestia` (`AmbientCapabilities=CAP_NET_BIND_SERVICE`).
- Desktop после переноса — клиент: при старте читает `<data>/remote.json` и открывает окно сразу на
  удалённый адрес; локальный контроллер не запускается.

## Proxmox: проверка (`POST /api/v1/selfinstall/probe`, только чтение)

Вход: `{target_id, node?, vmid?, hostname?, storage?, template_storage?, bridge?, ip?:"dhcp"|"a.b.c.d/nn",
gateway?, cores?, memory_mb?, disk_gb?}` — пустые поля заполняются значениями по умолчанию.
Проверки: узел online; `uname -m` на узле = `x86_64`; VMID свободен (`/cluster/resources`); хранилище
поддерживает `rootdir`, активно и свободно ≥ диска; мост существует на узле (`/nodes/{n}/network`);
шаблон (есть/скачать, имя и размер из aplinfo); статический IP свободен. Ответ: `{probe_id, kind:"lxc",
params:{...итоговые значения...}, defaults:{...}, choices:{nodes[], storages[], bridges[]}, warnings[],
plan:[{id,title,detail}]}`. Сессия проверки — в памяти, TTL 10 мин, как в 1b.

## Proxmox: план (задача `selfinstall`)

1. **Шаблон** — скачать `POST /nodes/{n}/aplinfo {storage, template}`, дождаться UPID
   (`GET /nodes/{n}/tasks/{upid}/status`, лог задачи в лог job). Откат: удалить том, только если скачали мы.
2. **Создать CT** — `POST /nodes/{n}/lxc`: `vmid, hostname=hestia, ostemplate, rootfs=<storage>:<disk>,
   cores, memory, swap, net0=name=eth0,bridge=<bridge>,ip=dhcp|<ip>[,gw=<gw>],firewall=0,
   unprivileged=1, features=nesting=1, onboot=1, start=0, description="Hestia controller", tags=hestia`.
   Откат: остановить (если запущен) и `DELETE /nodes/{n}/lxc/{vmid}?purge=1&destroy-unreferenced-disks=1`.
3. **Запустить** — `POST …/status/start`, дождаться UPID; затем IP через `/nodes/{n}/lxc/{vmid}/interfaces`
   (eth0, IPv4, до 90 с). MAC — из конфига `net0` (`GET …/config`).
4. **Уникальность** — в CT: `/etc/machine-id` — 32 hex и не совпадает с машинным id узла; SSH host
   keys существуют. Нет/пусто → `systemd-machine-id-setup`; нет ключей → `ssh-keygen -A`. Записать
   отпечаток ed25519 host key CT в лог (ошибку шаблона 135 не повторяем).
5. **Пользователь и бинарник** — `useradd --system --home-dir /var/lib/hestia --shell /usr/sbin/nologin
   hestia` (если нет), `/var/lib/hestia` 0700 hestia:hestia; бинарник → `/usr/local/bin/hestia` 0755
   root:root, сверка sha256; `hestia version` в CT совпадает с версией контроллера.
6. **Юнит** — `/etc/systemd/system/hestia.service` (см. ниже), `systemctl daemon-reload`, `enable`
   (без старта).
7. **Перенос состояния** — (с этого шага локальный контроллер в режиме переноса, см. ниже)
   снимок БД `VACUUM INTO` во временный файл в `<data>`; в копии: текущая задача `selfinstall`
   помечена выполненной (шаг «Состояние перенесено»), добавлен одноразовый handoff-токен,
   записан `settings.controller_location`. Копия + `master.key` → `/var/lib/hestia/` (0600
   hestia:hestia), сверка sha256, временный файл удалить.
8. **Старт и проверка** — `systemctl start hestia`; с контроллера-источника `GET http://<ip>/api/v1/health`
   до 30 с, `instance_id` в ответе должен совпасть с локальным (значит, поднялась перенесённая БД).
   Недоступен с ПК (маршрут/фаервол) → ошибка с IP и откат.
9. **Переключение** — записать `<data>/remote.json`, перенести `hestia.db*` и `master.key` в
   `<data>/archive/<UTC-время>/` (0700, ключ 0600). Точка невозврата: шаги 1–8 откатываются, 9 — нет
   (ошибка здесь — сообщение пользователю, CT остаётся рабочим).

Откат при ошибке на шагах 1–8 — в обратном порядке, только созданное этим запуском; локальное
состояние не трогается, режим переноса снимается. В лог задачи не попадают содержимое БД,
мастер-ключ, токены.

### Юнит

```
[Unit]
Description=Hestia HomeLAN controller
After=network-online.target
Wants=network-online.target

[Service]
User=hestia
Group=hestia
ExecStart=/usr/local/bin/hestia serve --listen :80 --data /var/lib/hestia
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/hestia
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Отдельный сервер (systemd на хосте)

Цель `kind=ssh`, нужен root или `sudo -n` (иначе проверка — ошибка «нужен root или sudo без пароля»).
Проверка: `uname -m`=x86_64, есть systemd (`systemctl --version`), порт свободен
(`ss -ltnH 'sport = :<port>'`; по умолчанию 80, занят → предложить 8080), `/usr/local/bin/hestia` и
`/etc/systemd/system/hestia.service` отсутствуют (иначе — ошибка «Hestia уже установлена», без
перезаписи). План — шаги 5–9 выше на самом хосте (через `sudo -n` при не-root), порт в `ExecStart`
и в адресе. Откат: `systemctl disable --now hestia`, удалить юнит, бинарник, `/var/lib/hestia`,
пользователя (только если создан нами).

## Режим переноса и «перемещён»

- Режим переноса (шаги 7–8): все не-GET запросы к API, кроме `/api/v1/auth/*` и самой задачи,
  отвечают 503 `{"error":"идёт перенос Hestia на сервер"}`; UI показывает баннер.
- Режим «перемещён» (есть `remote.json`; при старте `serve`/`desktop` проверяется до открытия БД):
  БД не открывается; отдаются только `GET /api/v1/health` (`{status:"moved", remote}`),
  `GET /api/v1/remote` (`{url, instance_id, reachable}` — проверка health удалённого, 3 с) и SPA,
  которая показывает экран «Hestia работает на <url>» с кнопками «Открыть» и «Повторить проверку».
- Desktop при `remote.json`: Go проверяет health удалённого (3 с) → доступен: окно сразу на
  `remote.url`; нет — окно на локальный loopback с экраном «перемещён» (повтор → `location` на удалённый).
- `remote.json`: `{url, instance_id, kind:"lxc"|"ssh", target_id, node?, vmid?, host?, mac?, ip,
  moved_at}`. Возврат на локальный контроллер — вне этапа (вручную: удалить `remote.json`, вернуть
  файлы из `archive/`); путь описать в README.

## Handoff (вход на новом контроллере без повторного ввода пароля)

- В копии БД: таблица `handoff_tokens(hash TEXT PRIMARY KEY, user_id, expires_at)`, хеш sha256 от
  32 случайных байт, TTL 10 мин, одноразовый.
- После успеха задачи (событие задачи несёт `result:{url, handoff_url, ip, mac, vmid?}`) UI
  показывает экран готовности и сам переходит на `handoff_url` = `<url>/#/handoff/<token>` через 3 с
  (кнопка «Перейти сейчас»). Маршрут SPA `#/handoff/<token>` → `POST /api/v1/auth/handoff {token}` →
  cookie сессии, токен удаляется → «Системы». Неверный/истёкший токен → экран входа.
- `result` с токеном хранится только в памяти (в БД задачи — без токена); задача после перезапуска
  его не отдаёт.

## Модель данных

Миграция: `settings(key TEXT PRIMARY KEY, value TEXT)` (если ещё нет) с ключами `instance_id`
(uuid, создаётся при первом старте, переносится вместе с БД) и `controller_location` (JSON как
`remote.json` без url-зависимых полей); таблица `handoff_tokens`. `GET /api/v1/health` дополнить
`instance_id` (без входа — это не секрет).

## API (с входом)

- `GET  /api/v1/selfinstall` → `{state:"local"|"installed", location?}` — показывать ли карточку.
- `POST /api/v1/selfinstall/probe` → ответ проверки (выше) | 400/422 с понятной ошибкой.
- `POST /api/v1/selfinstall {probe_id}` → 202 `{job}`; 410 — проверка истекла, 409 — уже идёт.
- `POST /api/v1/auth/handoff {token}` (без входа) → 204 + cookie | 401.

## Интерфейс

- «Системы»: пока `state=local` — карточка «Hestia сейчас работает на этом ПК. Установите её на
  сервер, чтобы она работала постоянно» + кнопка «Установить на сервер». Нет подключённых целей —
  кнопка ведёт в мастер подключения.
- Экран установки (`#/install`): выбор цели (по умолчанию первая Proxmox) → «Проверить» →
  итог: узел, VMID, IP-режим, ресурсы, шаблон (скачать/есть), предупреждения, план. «Подробнее»
  раскрывает редактируемые поля (узел, VMID, хранилище, мост, статический IP, ресурсы, порт для
  сервера) с повторной проверкой. Кнопка «Установить» → прогресс задачи → готово: адрес, MAC,
  подсказка про резервацию DHCP, авто-переход на handoff.
- Карточка «Отдельный сервер» — та же форма без Proxmox-полей.

## Тесты

- Фейковый Proxmox API (httptest TLS): aplinfo, storage content, lxc create/start/stop/delete,
  tasks status (UPID running→stopped OK / ошибка), interfaces (IP появляется не сразу), config с MAC;
  проверка заголовка токена и тел запросов (unprivileged=1, nesting=1, onboot=1, net0, rootfs).
- In-process SSH-сервер-узел с фейковым `pct exec`: файловая система CT в памяти (запись через stdin,
  sha256sum, useradd, systemctl, machine-id пустой/дубль → regenerate).
- Сценарии: успешная установка (шаблон есть / скачивается); ошибка на старте CT → откат удаляет CT,
  шаблон, скачанный этим запуском; health не отвечает → откат + локальное состояние цело и режим
  переноса снят; `instance_id` не совпал → ошибка; VMID 900–902 заняты → 903; занятый статический IP →
  ошибка проверки; узел не x86_64; повторная установка при `state=installed` → 409.
- Отдельный сервер: root и sudo-пользователь; порт 80 занят → 8080 в defaults; уже установлено → ошибка;
  откат удаляет только созданное.
- Режим переноса: POST во время шагов 7–8 → 503. Режим «перемещён»: БД не открывается, health/remote/SPA.
- Перенос: снимок открывается как валидная БД, задача в копии выполнена, handoff-токен работает
  один раз и истекает; master.key 0600; `archive/` создан; в логах задачи нет секретов.
- Payload: desktop-сборка без бинарника в `payload/` собирается, установка падает с понятной ошибкой.
- Фронтенд: reducer результата проверки и параметров «Подробнее», маршрут handoff, баннер переноса.
- Никаких обращений к реальной сети 10.10.10.0/24 из тестов и при разработке. Живой прогон —
  только ревьюером, после показа плана пользователю.
