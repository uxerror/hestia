# 02h. Этап 2a-1 — каркас плагинов, SDK, развёртывание Docker

Цель: Hestia умеет ставить, запускать, обновлять и удалять плагины — отдельные процессы в песочнице
systemd. Плагин общается с Hestia по JSON-RPC, получает доступ к целям, секретам и развёртыванию
только через API Hestia и только в пределах выданных прав. Есть SDK на Go, каталог официальных
плагинов, установка стороннего плагина по URL или файлом, страница «Плагины» с формами по схеме и
демо-плагин `hestia-hello`, который ставит контейнер whoami через Docker compose.

Граф связей и составные узлы — этап 2a-2 (здесь только хранение `provides`/`requires` из
манифеста). HestiaCA и HTTPS — 2a-3. Общая модель — 04-ecosystem.md.

## Решения (2026-11-19, с пользователем)

- Протокол: **свой JSON-RPC 2.0** поверх потокового соединения, двусторонний (плагин вызывает API
  Hestia), версия протокола в рукопожатии. Без новых зависимостей.
- Изоляция: **песочница systemd для всех плагинов**, включая официальные: юнит
  `hestia-plugin@<id>.service` с `DynamicUser=yes`, без доступа к `/var/lib/hestia`; ключ Hestia и
  `master.key` плагин не видит.
- Каталог: **монорепо** `uxerror/hestia` — SDK (`sdk/`) и официальные плагины (`plugins/<id>/`);
  каталог — подписанный `index.json` в релизе GitHub; сторонние — по URL или файлом.
- Подпись официальных плагинов — **отдельный ключ** `~/.config/hestia/plugins.key` (пользователь
  генерирует сам, как release.key). Ключ стороннего автора закрепляется при первой установке
  (показывается отпечаток), обновления — только тем же ключом.
- В этап входит **API развёртывания Docker compose** (с установкой Docker по плану) и демо-плагин
  `hestia-hello` (контейнер whoami).

## Решения (технические, ревьюер)

- Go-модуль переименовывается `hestia` → `github.com/uxerror/hestia` (иначе SDK нельзя
  импортировать извне). Механическая замена импортов отдельным первым коммитом батча.
- SDK — пакет `github.com/uxerror/hestia/sdk` (вне `internal/`), без зависимостей кроме stdlib.
  Протокол описан в `docs/plugins/protocol.md` (публичная документация для авторов) — плагин на
  другом языке пишется по ней.
- Плагины работают **только на контроллере-сервере** (`serve` на LXC/сервере). В desktop-режиме до
  самоустановки страница «Плагины» показывает «Плагины доступны после переноса Hestia на сервер».
- Режим разработчика: `hestia serve --plugin-dev <путь-к-бинарнику>` запускает плагин дочерним
  процессом по stdio **без песочницы**, в UI с плашкой «dev, без песочницы». Используется в тестах
  и E2E, и авторами плагинов. Флаг не сохраняется в БД.

## Протокол (v1)

Транспорт — поток байтов, сообщения JSON-RPC 2.0, каждое — одна строка JSON + `\n` (NDJSON;
максимальная длина строки 8 МБ, больше — ошибка соединения). Обе стороны могут слать запросы,
ответы и уведомления; id запросов у каждой стороны свои.

- **Продакшен:** контроллер слушает unix-сокет `/run/hestia/plugins.sock` (сокет 0666). Каталог
  создаёт `/etc/tmpfiles.d/hestia.conf` (`d /run/hestia 0755 hestia hestia -`) — его пишет шаг
  установки первого плагина (`systemd-tmpfiles --create`) и selfinstall для новых установок; юнит
  `hestia.service` не меняется (уже работающему CT не нужен «первый прыжок»). Нет каталога —
  контроллер сокет не открывает, плагины «не установлены». Юнит плагина получает путь в `HESTIA_SOCKET` и токен через
  systemd credentials (`LoadCredential=token:/var/lib/hestia-plugins/<id>/token`, файл root 0600) —
  плагин читает `$CREDENTIALS_DIRECTORY/token`. Первое сообщение плагина — `hello`.
- **dev:** stdin/stdout дочернего процесса; токен — в переменной `HESTIA_PLUGIN_TOKEN`.
- Рукопожатие: плагин → `hello {protocol: 1, id, version, token}`; Hestia сверяет токен (константное
  время), id и версию с установленными; ответ `{protocol: 1, hestia_version, instances: [...]}`.
  Неподдерживаемый протокол → ошибка с поддерживаемым диапазоном, соединение закрывается. Повторное
  подключение того же плагина вытесняет старое.
- Токен: 32 байта случайных, хранится в БД как sha256; новый — при каждой установке/обновлении.
- Таймауты: вызов Hestia → плагин 30 с по умолчанию (`apply` — без общего таймаута, отмена через
  `$/cancel {id}`); heartbeat `ping` раз в 30 с, 3 пропуска → плагин «не отвечает».

### Методы, которые реализует плагин (Hestia → плагин)

| Метод | Назначение |
|---|---|
| `manifest` | вернуть манифест (сверяется с установленным) |
| `instance.validate {config}` | ошибки по полям `[{field, msg}]` |
| `instance.plan {instance, config, action}` | `action`: `create`/`update`/`remove`; ответ — `{actions: [{title, detail, risk: info/change/danger}], warnings, data}` |
| `instance.apply {job_id, instance, config, action, plan}` | выполнить подтверждённый план (шаги и лог — через `job.*`) |
| `instance.status {instance}` | `{state: ok/degraded/down/unknown, detail, endpoints: [{name, url}]}` |

`data` из плана — непрозрачный JSON плагина, Hestia хранит его вместе с хешем плана и передаёт в
`apply` без изменений.

### Методы Hestia (плагин → Hestia)

Каждый вызов проверяется по правам плагина и по грантам экземпляра. Отказ — ошибка `-32001
permission denied` с указанием права.

| Метод | Право | Что делает |
|---|---|---|
| `job.step {job_id, title}` / `job.step_done {job_id, error?}` | — | шаги задачи (UI/SSE как у остальных jobs) |
| `job.log {job_id, level, line}` | — | лог задачи; Hestia маскирует известные секреты экземпляра |
| `secret.put {instance, name, value}` / `secret.get` / `secret.delete` | — | секреты в пространстве `plugin:<id>:<instance>:<name>`, шифрование как у остальных |
| `target.list` | `targets.read` | цели, выданные экземпляру: id, тип, имя, адрес, ОС, root/sudo |
| `target.exec {instance, target, cmd, stdin?, timeout_s?}` | `targets.exec` | команда от root на выданной цели (через существующий транспорт: SSH/sudo, `pct exec`); результат `{code, stdout, stderr}` (каждый ≤ 4 МБ) |
| `target.put_file {instance, target, path, data_b64, mode}` | `targets.exec` | файл на цели |
| `deploy.plan {instance, target, project, compose, files}` | `deploy.docker` | что нужно сделать на цели (см. «Развёртывание») |
| `deploy.up {job_id, instance, target, project, compose, files}` | `deploy.docker` | применить |
| `deploy.down {job_id, instance, target, project, volumes: bool}` | `deploy.docker` | остановить и удалить проект |
| `deploy.status {instance, target, project}` | `deploy.docker` | `docker compose ps` в JSON |
| `inventory.get` | `inventory.read` | хосты, сервисы, гости (как `GET /api/v1/network` + `/inventory`) |
| `log {level, line}` | — | системный лог плагина (journal Hestia с префиксом id) |

Гранты: экземпляр получает цели, выбранные пользователем в форме (поле типа `target`). Вызов к
цели, не выданной экземпляру, — отказ, даже если право у плагина есть.

## Пакет плагина

Файл `<id>-<version>-linux-amd64.hpkg` = tar.gz:

```
manifest.json
plugin            # исполняемый, статический (CGO_ENABLED=0 для Go)
icon.svg          # необязательно, ≤ 64 КБ, санитизируется (без script/foreign/on*)
README.md         # необязательно
SHA256SUMS        # sha256 всех файлов выше
SHA256SUMS.sig    # ed25519 подпись SHA256SUMS ключом автора (base64)
```

Ограничения при распаковке: ≤ 64 МБ в сумме, только обычные файлы из списка выше, без путей с
`/`, `..`, ссылок. Любое несоответствие — пакет отклонён целиком.

### manifest.json

```json
{
  "protocol": 1,
  "id": "hestia-hello",
  "name": "Hestia Hello",
  "version": "v0.1.0",
  "description": "Демонстрационный сервис whoami в Docker",
  "homepage": "https://github.com/uxerror/hestia",
  "author": {"name": "uxerror", "key": "<ed25519 pub, base64>"},
  "min_hestia": "v0.2.0",
  "permissions": ["targets.read", "deploy.docker"],
  "provides": [{"type": "http.service"}],
  "requires": [],
  "multi_instance": true,
  "schema": {
    "fields": [
      {"name": "target", "type": "target", "label": "Где запустить", "required": true,
       "filter": {"docker_capable": true}},
      {"name": "port", "type": "int", "label": "Порт", "default": 8080, "min": 1, "max": 65535},
      {"name": "message", "type": "string", "label": "Приветствие", "default": "Привет от Hestia",
       "max_len": 200}
    ],
    "presets": [{"name": "default", "label": "По умолчанию", "values": {}}]
  }
}
```

- `id`: `^[a-z][a-z0-9-]{1,39}$`; префикс `hestia-` зарезервирован за официальным ключом.
- Типы полей формы: `string`, `text`, `int`, `bool`, `enum` (`options: [{value, label}]`),
  `secret` (значение уходит в secrets, в конфиге — ссылка), `target` (выбор цели, становится
  грантом). Атрибуты: `label`, `help`, `default`, `required`, `advanced` (скрыто под «Подробнее»),
  `min/max/max_len/pattern`.
- Права (закрытый список v1): `targets.read`, `targets.exec`, `deploy.docker`, `inventory.read`,
  `net.outbound`. Неизвестное право — пакет отклонён.
- `provides`/`requires`: `[{type, name?}]`, `type` — `^[a-z][a-z0-9.-]+$`. В 2a-1 только хранятся и
  показываются.

### Подпись и доверие

- Официальные: `author.key` совпадает с вшитым `internal/plugins/official.pub` → «Официальный
  плагин Hestia», ставится после показа прав без предупреждения.
- Сторонние: подпись проверяется ключом из манифеста. Первая установка от этого ключа — экран
  «Сторонний автор» с отпечатком ключа (SHA-256, hex, группами), именем автора и правами; после
  подтверждения ключ закрепляется (`plugin_authors`). Обновление плагина — только тем же ключом,
  другой ключ — отказ «Ключ автора изменился» без кнопки обхода (удалить и поставить заново).
- Пакет без подписи или с неверной подписью не ставится никогда.

## Каталог

- Официальный каталог: релиз GitHub с постоянным тегом `plugins-catalog` в `uxerror/hestia`,
  ассеты `index.json` + `index.json.sig` (подпись plugins.key) + сами `.hpkg` (имена с версией —
  старые версии остаются).
- `index.json`: `{"generated": "<RFC3339>", "plugins": [{"id", "name", "version", "description",
  "min_hestia", "url", "sha256", "size", "permissions", "provides", "requires"}]}`.
- Контроллер проверяет каталог раз в сутки (вместе с проверкой обновлений) и по кнопке; неверная
  подпись — каталог не показывается, ошибка в UI. Скачанный пакет сверяется с `sha256` из каталога
  и затем проверяется сам (подпись в пакете).
- Сторонний плагин: «Установить по ссылке» (https, ≤ 64 МБ, редиректы GitHub разрешены) или
  загрузка файла.
- Обновления плагинов: для официальных — по каталогу; для сторонних, поставленных по URL — нет
  автопроверки в 2a-1 (кнопка «Обновить из файла/ссылки»). Даунгрейд запрещён.

### Инструменты (cmd/hestia-release)

- `go run ./cmd/hestia-release keygen --out ~/.config/hestia/plugins.key --pub
  internal/plugins/official.pub` — существующая команда (флаги уже есть). Ключ генерирует пользователь; до этого `official.pub` пуст и
  официальные пакеты ставятся как сторонние (тесты подменяют переменную, как с release.pub).
- `hestia-release plugin-pack --dir build/plugins/<id> --key <file> --out dist/plugins/` — собрать и
  подписать `.hpkg` (для сторонних авторов то же самое со своим ключом; `plugin-keygen` = `keygen`).
- `hestia-release plugin-verify <file.hpkg>`.
- `hestia-release catalog-add --index dist/plugins/index.json --key ~/.config/hestia/plugins.key
  <file.hpkg>...` — добавить/обновить записи и переподписать index.
- Makefile: `make plugin ID=hestia-hello VERSION=v0.1.0` (сборка + пакет), `make plugin-publish
  ID=... VERSION=...` (тег `plugin/<id>/<version>` на HEAD, загрузка `.hpkg`, `index.json`,
  `index.json.sig` в релиз `plugins-catalog` с `--clobber`). Публикация — только по слову
  пользователя.

## Песочница и жизненный цикл на контроллере

Root-действия на собственной машине контроллера — через существующий путь
`selfinstall.OpenShell(location)` (pct exec с узла или root/sudo по SSH), как обновление.

Раскладка:

```
/var/lib/hestia-plugins/<id>/<version>/plugin   root:root 0755 (весь каталог только для чтения)
/var/lib/hestia-plugins/<id>/token              root:root 0600
/var/lib/hestia-plugins/<id>/current -> <version>
/etc/systemd/system/hestia-plugin@.service      шаблон, ставится при первом плагине
```

Шаблон юнита (значения — исходные; батч проверяет, что каждое работает в непривилегированном LXC
Debian 13, и снимает только то, что не работает, отметив в «Отклонениях»):

```ini
[Unit]
Description=Hestia plugin %i
PartOf=hestia.service
After=hestia.service

[Service]
ExecStart=/var/lib/hestia-plugins/%i/current/plugin
Environment=HESTIA_SOCKET=/run/hestia/plugins.sock
LoadCredential=token:/var/lib/hestia-plugins/%i/token
DynamicUser=yes
StateDirectory=hestia-plugin/%i
ProtectSystem=strict
ProtectHome=yes
InaccessiblePaths=/var/lib/hestia /etc/hestia
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=256M
TasksMax=64
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=5

[Install]
WantedBy=hestia.service
```

- Без права `net.outbound`: добавить `RestrictAddressFamilies=AF_UNIX` (только сокет Hestia).
  Связь с целями у таких плагинов — только через `target.*`/`deploy.*`.
- Состояние плагина (`StateDirectory`) — его собственное, удаляется при удалении плагина.
- Супервизия: Hestia знает состояние по соединению (`connected/disconnected`) и `systemctl
  is-active` (через root-путь — только по запросу страницы, не по таймеру). Падение плагина не
  влияет на контроллер; его задачи `apply` в момент обрыва → `failed` «Плагин перезапустился».
- Абстракция `Supervisor` с реализациями `systemd` (продакшен) и `child` (dev/тесты), одинаковый
  RPC-слой поверх `io.ReadWriteCloser`.

### Установка (задача `plugin-install`)

План (показывается до подтверждения): id, версия, автор (официальный / сторонний + отпечаток),
права, `provides`/`requires`, размер; для обновления — «было → стало» и новые права
(подсвечены). Шаги:

1. проверить пакет (уже проверен при загрузке; повторная проверка sha256 файла из временного каталога);
2. положить файлы в `<id>/<version>/`, токен, шаблон юнита и tmpfiles (если нет), `daemon-reload`;
3. переключить `current`, `systemctl enable --now hestia-plugin@<id>` (обновление — `restart`);
4. дождаться `hello` (20 с) и сверить `manifest` из процесса с манифестом пакета;
5. при обновлении — `instance.status` всех экземпляров.

Откат: при ошибке на шагах 2–5 — вернуть `current` на прежнюю версию (или удалить установку
целиком для новой) и перезапустить; новая версия удаляется. Хранится одна предыдущая версия.

### Отключение / удаление

- «Отключить» — `systemctl disable --now`, экземпляры остаются, статус «плагин отключён».
- «Удалить» — только если нет экземпляров (иначе список и «сначала удалите экземпляры»; удаление
  экземпляра = его `remove`-план, т. е. сервисы на целях убирает сам плагин). Удаляются юнит-ссылка,
  `/var/lib/hestia-plugins/<id>`, StateDirectory, секреты `plugin:<id>:*`. Закреплённый ключ автора
  остаётся (видно в «Авторах», можно забыть вручную, если от него нет плагинов).

## Экземпляры

- Экземпляр = конфигурация плагина: `id`, `plugin_id`, `name` (по умолчанию `<name плагина> N`),
  `config` (JSON без секретов), гранты целей, `status`, `detail`, `endpoints`, `checked_at`.
- Создание/изменение/удаление — всегда `plan` → экран плана (действия с цветом риска,
  предупреждения) → «Применить» → задача `plugin-apply` (jobs + SSE; шаги и лог из плагина).
  План с хешем (`sha256` канонического JSON plan+config); при применении Hestia заново запрашивает
  план и сравнивает хеш — расхождение → «Состояние изменилось, проверьте план ещё раз» (как 02g).
- Статус: `instance.status` при открытии страницы плагина и раз в 5 мин для включённых плагинов
  (без root-пути, только RPC).

## Развёртывание Docker compose (API Hestia для плагинов)

Цели развёртывания в 2a-1: SSH-сервер с root/sudo и **существующий LXC** на подключённом Proxmox
(команды через `pct exec` с узла). Новая LXC/VM под сервис — в следующем этапе (отметить в
roadmap). `docker_capable` в `target.list`/фильтре формы — Debian/Ubuntu с root/sudo (Docker может
ещё не стоять — его поставит план).

`deploy.plan` возвращает действия:

- **Docker отсутствует:** «Установить Docker: `apt-get install -y docker.io docker-compose`
  (Debian/Ubuntu, пакеты дистрибутива)». Другая ОС — ошибка «Поставьте Docker вручную» с
  командой. Если нет `docker compose` v2 — то же, ставим `docker-compose` (v2 в Debian 13).
- **LXC без `nesting=1`/`keyctl=1`:** «Включить nesting и keyctl для CT <vmid> (Proxmox API,
  нужен перезапуск контейнера)», risk `danger`, отдельная галка подтверждения. Для привилегированного
  LXC keyctl не нужен.
- Проект: `/opt/hestia/<instance>-<project>/compose.yaml` + `files` (имена без `/`, ≤ 1 МБ каждый,
  0640 root); «создать» / «изменить (diff размеров/хешей)» / «без изменений».
- Порты: если опубликованный порт занят не этим проектом (`ss -ltnH`) — предупреждение-конфликт.

`deploy.up`: шаги — установка Docker (если в плане) → features LXC + перезапуск (если в плане,
после подтверждения галкой) → запись файлов → `docker compose -p hestia-<instance>-<project> up -d
--remove-orphans` → `ps` до `running` (60 с). Откат при ошибке: если проект был — вернуть прежние
файлы и `up -d`; если новый — `down`. Docker и features LXC обратно не снимаются (в логе — что
осталось).

Hestia проверяет compose перед записью: запрещены `privileged: true`, `network_mode: host`,
`pid: host`, `cap_add`, `devices`, bind-маунты вне `/opt/hestia/<instance>-<project>/` и именованных
томов — для всех плагинов (явные исключения — будущим правом `deploy.docker.privileged`, не в 2a-1).
Метки `hestia.plugin=<id>`, `hestia.instance=<id>` добавляет Hestia.

## hestia-hello (plugins/hestia-hello)

- Схема как в примере манифеста; одна цель, порт, приветствие.
- Plan: `deploy.plan` с compose из одного сервиса `traefik/whoami:v1.10` (порт `<port>:80`,
  `command: ["--name", <message>]`); плюс действие «Проверить http://<адрес цели>:<port>».
- Apply: `deploy.up`, затем GET `http://<адрес>:<port>/` до 200 (20 с) — нужен `net.outbound`;
  без него проверка через `target.exec curl`. Выбрать один путь и указать права в манифесте
  соответственно (рекомендация: `target.exec`-путь не нужен, взять `net.outbound`).
- Status: GET → ok/down, endpoint `http://<адрес>:<port>`.
- Remove: `deploy.down` (`volumes: true`).
- Служит образцом для авторов: README в `plugins/hestia-hello/` — как собрать, подписать, поставить.

## SDK (sdk/)

```go
type Plugin interface {
    Validate(ctx, cfg Config) []FieldError
    Plan(ctx, req PlanRequest) (Plan, error)
    Apply(ctx, req ApplyRequest, job *Job) error
    Status(ctx, inst Instance) (Status, error)
}
func Serve(manifest []byte, p Plugin)   // разбирает окружение (сокет+credentials или stdio), рукопожатие, цикл
// Клиент API Hestia: sdk.Host — Targets, Exec, PutFile, Secrets, Deploy*, Inventory, Log; Job.Step/Log
```

- `manifest.json` вшивается в бинарник плагина (`//go:embed`) — `manifest` отвечает им же.
- `sdk/rpc` — переиспользуемый JSON-RPC слой; контроллер использует тот же код.
- `sdk/sdktest` — фейковый хост для юнит-тестов плагинов (записывает вызовы, отвечает заданными
  результатами).

## Данные (миграция)

```sql
CREATE TABLE plugin_authors (key TEXT PRIMARY KEY, name TEXT NOT NULL, official INTEGER NOT NULL,
  pinned_at TEXT NOT NULL);
CREATE TABLE plugins (id TEXT PRIMARY KEY, version TEXT NOT NULL, prev_version TEXT NOT NULL DEFAULT '',
  author_key TEXT NOT NULL REFERENCES plugin_authors(key), manifest TEXT NOT NULL,
  source TEXT NOT NULL,            -- catalog / url:<...> / file / dev
  enabled INTEGER NOT NULL DEFAULT 1, token_hash TEXT NOT NULL, installed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL);
CREATE TABLE plugin_instances (id INTEGER PRIMARY KEY, plugin_id TEXT NOT NULL REFERENCES plugins(id),
  name TEXT NOT NULL, config TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unknown',
  detail TEXT NOT NULL DEFAULT '', endpoints TEXT NOT NULL DEFAULT '[]', checked_at TEXT,
  created_at TEXT NOT NULL, UNIQUE(plugin_id, name));
CREATE TABLE plugin_grants (instance_id INTEGER NOT NULL REFERENCES plugin_instances(id) ON DELETE CASCADE,
  target_kind TEXT NOT NULL, target_ref TEXT NOT NULL,   -- ssh:<target_id> / lxc:<target_id>:<node>:<vmid>
  PRIMARY KEY (instance_id, target_kind, target_ref));
CREATE TABLE plugin_catalog (id INTEGER PRIMARY KEY CHECK (id = 1), fetched_at TEXT, index_json TEXT,
  error TEXT NOT NULL DEFAULT '');
```

## API

```
GET    /api/v1/plugins                      установленные + состояние соединения + доступные обновления
GET    /api/v1/plugins/catalog              каталог (кеш) ; POST /plugins/catalog/refresh
POST   /api/v1/plugins/packages             загрузка файла (multipart) → {upload_id, preview}
POST   /api/v1/plugins/packages/fetch       {url} → {upload_id, preview}
POST   /api/v1/plugins/packages/catalog     {id} → {upload_id, preview}
         preview: manifest, автор (official/pinned/new + отпечаток), права, для обновления — diff прав
POST   /api/v1/plugins/install              {upload_id, trust_author: bool} → job
POST   /api/v1/plugins/{id}/enable|disable  → job (root-путь)
DELETE /api/v1/plugins/{id}                 → job
GET    /api/v1/plugins/{id}/instances
POST   /api/v1/plugins/{id}/instances/plan  {name, config} → {plan_id, plan, hash}
POST   /api/v1/plugins/instances/{iid}/plan {action: update|remove, config?}
POST   /api/v1/plugins/plans/{plan_id}/apply {hash, confirm_danger: bool} → job
GET    /api/v1/plugins/instances/{iid}      (+ status=refresh)
GET    /api/v1/plugins/authors ; DELETE /api/v1/plugins/authors/{key} (если нет плагинов)
GET    /api/v1/plugins/targets              кандидаты для поля `target` (SSH-серверы + LXC из инвентаря, docker_capable)
```

Временные загрузки — в `/var/lib/hestia/tmp/plugins/`, живут 1 час, чистятся при старте. Планы
хранятся в памяти 15 мин.

## UI

- Меню: «Плагины» (иконка puzzle). Вкладки: **Установленные**, **Каталог**, «Установить из
  файла/ссылки» (кнопка в шапке).
- Карточка плагина: иконка, имя, версия, автор (бейдж «Официальный» / «Сторонний» + отпечаток),
  состояние (работает / не отвечает / отключён / dev), `provides`, число экземпляров, кнопки
  «Обновить до vX», «Отключить», «Удалить».
- Экран установки: права списком человеческим языком («Выполнять команды от root на выбранных
  серверах», «Разворачивать Docker-контейнеры», «Сетевые подключения напрямую», «Читать карту
  сети»), для стороннего — жёлтый блок с отпечатком и галкой «Я доверяю этому автору».
- Страница плагина: README (markdown → текст, без HTML), экземпляры (статус, endpoints-ссылки),
  «Создать» → форма по схеме (пресеты сверху, `advanced` под «Подробнее», поле `target` —
  выпадающий список с подсказкой, почему цель недоступна) → план → задача.
- Компонент формы по схеме — общий (`web/src/components/SchemaForm.svelte`), тесты на все типы
  полей и валидацию.

## Тесты

- RPC: корректные/битые сообщения, длинная строка, двусторонние вызовы, отмена, обрыв во время
  `apply`, heartbeat.
- Пакет: подпись ок/неверна/нет; лишний файл, путь с `..`, симлинк, превышение размера; неизвестное
  право; `hestia-` префикс со сторонним ключом; смена ключа автора при обновлении; даунгрейд.
- Права: вызов без права, вызов к не выданной цели, секреты чужого экземпляра/плагина.
- Compose-валидация: каждый запрещённый ключ; bind-маунт вне каталога.
- deploy: фейковая цель (как `fakehost_test.go`): Docker нет → план установки; LXC без nesting →
  danger-действие; up → ok; ошибка `up` → откат к прежним файлам / `down` для нового.
- Install/rollback с фейковым ControllerShell: ошибка на каждом шаге 2–5 → прежняя версия на месте.
- E2E (dev-режим): `serve --plugin-dev build/plugins/hestia-hello/plugin` → создать экземпляр на
  фейковой SSH-цели (тестовый SSH-сервер из sshx-тестов) → план → apply → status.
- `sdk/sdktest` покрывает hestia-hello юнит-тестами.

## Живая проверка (с разрешения пользователя, после ревью)

1. Пользователь генерирует `plugins.key`, публичный ключ коммитится; релиз Hestia `v0.2.0`;
   обновление CT 900 кнопкой.
2. `make plugin-publish ID=hestia-hello VERSION=v0.1.0` (по слову пользователя).
3. В панели: Каталог → hestia-hello → установка. Проверки (только чтение): `pct exec 900 --
   systemctl status hestia-plugin@hestia-hello`, `systemd-analyze security hestia-plugin@hestia-hello`,
   плагин не читает `/var/lib/hestia` (`systemd-run -p DynamicUser=yes ... cat` с теми же
   свойствами → Permission denied).
4. Экземпляр hestia-hello на цели, выбранной пользователем (рекомендация — одноразовый LXC,
   который пользователь создаст или разрешит создать), whoami отвечает, удаление экземпляра убирает
   контейнер.

## Батчи

- **2a-1a:** переименование модуля; `sdk/rpc`, `sdk`, `sdk/sdktest`; пакет/подпись/инструменты
  `hestia-release`; миграция; менеджер плагинов (Supervisor child + systemd, установка/откат,
  права, гранты, секреты, `target.*`); API и UI (страница, установка из файла/ссылки, SchemaForm,
  экземпляры с планом); hestia-hello **без** развёртывания (plan/apply через `target.exec`
  `echo`/`cat` — только для проверки каркаса); `docs/plugins/protocol.md`.
- **2a-1b:** `deploy.*` (Docker, features LXC, валидация compose, откат); каталог (`index.json`,
  проверка, вкладка «Каталог», обновления официальных); hestia-hello на whoami; Makefile
  `plugin`/`plugin-publish`; README для авторов.

## Отклонения (по факту реализации 2a-1a)

- **Сокет и `hestia.service`.** У юнита контроллера `ProtectSystem=strict` и `ReadWritePaths=/var/lib/hestia`:
  `/run` для него только для чтения, и созданный tmpfiles каталог `/run/hestia` не помогает — сокет не
  открыть без изменения юнита. Поэтому: selfinstall для новых установок пишет
  `ReadWritePaths=/var/lib/hestia -/run/hestia` (и tmpfiles, как в спеке); установка плагина кладёт
  drop-in `/etc/systemd/system/hestia.service.d/10-plugins.conf` (`ReadWritePaths=-/run/hestia`). Если
  работающий контроллер (установлен до плагинов, CT 900) всё же не может открыть сокет, задача
  установки откатывается с сообщением «контроллер перезапустится один раз — повторите установку» и
  планирует `systemd-run --on-active=5 … systemctl restart hestia.service`. Это и есть «первый прыжок»,
  которого спека хотела избежать: без перезапуска процесса namespace не поменять.
- **Шаблон юнита плагина:** `StartLimitIntervalSec`/`StartLimitBurst` перенесены в `[Unit]` (их место в
  современном systemd); `InaccessiblePaths=-/var/lib/hestia -/etc/hestia` — с `-`, иначе юнит не
  стартует, если `/etc/hestia` нет (его нет). Сеть без `net.outbound` режет drop-in
  `hestia-plugin@<id>.service.d/10-hestia.conf` со сбросом (`RestrictAddressFamilies=` +
  `RestrictAddressFamilies=AF_UNIX`), т. к. списки семейств в systemd объединяются.
- **Экземпляр создаётся черновиком при плане `create`** (`status='draft'`): у него сразу есть id (плагин
  планирует с настоящим id, например путь `/tmp/hestia-hello-<id>`) и гранты целей из формы.
  Черновики не видны в API, удаляются с истечением плана (15 мин), при старте, при новом плане с тем
  же именем и при неудачном `apply` создания.
- **Гранты при изменении:** пока идёт план или `apply` для `update`, экземпляру доступны и старые, и
  новые цели; после успеха в БД остаются только новые.
- **Секреты формы:** в `config` — ссылка `{"secret": "<поле>"}`, значение пишется в secrets
  (`plugin:<id>:<экземпляр>:<поле>`) в начале задачи `apply`; при ошибке возвращается прежнее.
  Пустое поле при изменении — «оставить прежнее».
- **`target.exec`:** вывод обрезается до 1 МБ на поток (общий лимит `sshx`), а не 4 МБ. Команда —
  `sh -c` от root (`sudo -n` для SSH не от root, `pct exec` с узла для LXC); `timeout_s` 60 по
  умолчанию, максимум 3600.
- **БД:** в `plugins` добавлены `readme` и `icon` (очищенный SVG); время — INTEGER (мс), как во всей
  базе. Плагин `--plugin-dev` записывается в `plugins` с `source='dev'` и псевдоавтором `dev` (у
  экземпляров должен быть родитель); сам флаг не хранится. dev-плагин не включается/отключается через
  API, а пакет с тем же id блокирует dev-режим для него.
- **API:** добавлены `GET /plugins/{id}` (манифест, README, `?unit=1` — `systemctl is-active` через
  root-путь) и `GET /plugins/{id}/icon` (с CSP `sandbox`). Пути `/plugins/instances/{iid}` и
  `/plugins/{id}/instances` (и их `/plan`) конфликтуют в mux Go и разбираются одним обработчиком;
  поэтому id `authors`, `catalog`, `install`, `instances`, `packages`, `plans`, `targets` запрещены.
  Каталог — 501, `deploy.*` в RPC — `-32601` «будет в следующем обновлении».
- **Версии плагинов** — строго `vX.Y.Z`. **`plugin-pack`** требует, чтобы `author.key` в
  `manifest.json` совпадал с ключом подписи (манифест вшит в бинарник и при установке сверяется с
  пакетом); у `hestia-hello` ключ пуст, пока пользователь не создаст `plugins.key`. Флаг `--src` —
  откуда брать `manifest.json`/`icon.svg`/`README.md` (по умолчанию `plugins/<имя --dir>`).
- **Кандидаты целей:** SSH не от root считается «через sudo» (проверяется при выполнении);
  `docker_capable` у SSH — Debian/Ubuntu по инвентарю, у LXC — всегда (ОС проверит план 2a-1b);
  остановленный LXC недоступен.
- **hestia-hello 2a-1a:** поля `target` и `message`, `provides: demo.hello`, права `targets.read`,
  `targets.exec`; файл `/tmp/hestia-hello-<id>`.
- **Состояние «не отвечает»** — `unresponsive` после трёх пропущенных `ping`; задачи плагина
  (`plugin-*`) на один плагин не идут параллельно.
