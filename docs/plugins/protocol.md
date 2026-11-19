# Протокол плагинов Hestia (v1)

Документ для авторов плагинов. Плагин — отдельная программа, которую Hestia запускает в песочнице
systemd и с которой общается по JSON-RPC 2.0. На Go проще всего писать на SDK
(`github.com/uxerror/hestia/sdk`, пример — `plugins/hestia-hello`), но плагин на любом языке
пишется по этому описанию.

## Транспорт

- Поток байтов, в обе стороны — сообщения JSON-RPC 2.0, **одно сообщение — одна строка JSON,
  оканчивающаяся `\n`** (NDJSON). Перевод строки внутри JSON допускается только экранированным
  (`\n` в строках), как его и выдают обычные JSON-кодировщики.
- Максимальная длина строки — **8 МБ** (без `\n`). Более длинная строка — ошибка соединения: его
  закрывают.
- Обе стороны шлют запросы, ответы и уведомления. Идентификаторы запросов у каждой стороны свои
  (числа или строки); ответ несёт `id` запроса.
- Отмена: уведомление `$/cancel {"id": <id запроса>}`. Обработчик отменённого запроса должен
  прекратить работу; ответ на него — ошибка `-32800`.
- Heartbeat: Hestia раз в 30 с шлёт запрос `ping` (без параметров), ответ — `{}`. Три пропуска
  подряд — плагин помечается «не отвечает». SDK отвечает на `ping` сам.
- Таймаут вызова Hestia → плагин — 30 с; `instance.apply` — без общего таймаута (отмена — через
  `$/cancel`, когда пользователь отменяет задачу).
- Битая строка (не JSON, не `"jsonrpc":"2.0"`) получает ответ с ошибкой `-32700` и `"id": null`,
  соединение остаётся.

### Как плагин подключается

| Режим | Как найти Hestia | Токен |
|---|---|---|
| Продакшен (юнит `hestia-plugin@<id>.service`) | unix-сокет из `$HESTIA_SOCKET` (`/run/hestia/plugins.sock`) | файл `$CREDENTIALS_DIRECTORY/token` (systemd credentials) |
| Разработка (`hestia serve --plugin-dev <бинарник>`) | stdin/stdout процесса | переменная `HESTIA_PLUGIN_TOKEN` |

Сокет может появиться чуть позже процесса — пробуйте подключиться несколько раз (SDK ждёт до 30 с).
После обрыва соединения плагин должен завершиться (в продакшене с ненулевым кодом — systemd
перезапустит его через 5 с).

## Рукопожатие

Первое сообщение плагина — запрос `hello`:

```json
{"jsonrpc":"2.0","id":1,"method":"hello","params":{"protocol":1,"id":"hestia-hello","version":"v0.1.0","token":"<токен>"}}
```

Hestia сверяет токен (хранит только его sha256, сравнение за постоянное время), `id` и `version` с
установленным плагином. Ответ:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocol":1,"hestia_version":"v0.2.0","instances":[{"id":5,"name":"Hestia Hello 1","config":{"target":"ssh:1","message":"Привет"}}]}}
```

- Неподдерживаемый `protocol` → ошибка `-32002` с `data: {"min":1,"max":1}`, соединение закрывается.
- Неверный токен/id/версия → ошибка `-32002`, соединение закрывается.
- Любой другой запрос до `hello` → ошибка `-32002`. Без `hello` за 20 с соединение закрывается.
- Повторное подключение того же плагина вытесняет старое соединение.
- В режиме разработки Hestia после `hello` спрашивает `manifest` и берёт права из него (подпись не
  проверяется — плагин помечен «dev, без песочницы»). Флаг `--plugin-dev` можно повторять: каждый
  бинарник — отдельный плагин.
- `links` (необязательно) — активные связи экземпляров плагина:
  `[{link, kind, role, instance, port, peer?, device?, binding?}]` (`binding` — только у роли
  `consumer`, секреты в нём — ссылками). Потребитель может восстановить свои подключения без своего
  состояния.

## Методы плагина (Hestia → плагин)

| Метод | Параметры | Ответ |
|---|---|---|
| `manifest` | `{}` | манифест (тот же `manifest.json`, что в пакете; при установке сверяется побайтно после канонизации JSON) |
| `instance.validate` | `{config}` | `[{field, msg}]` — пустой массив, если всё верно |
| `instance.plan` | `{instance, config, action}` | `{actions: [{title, detail, risk}], warnings: [...], data}` |
| `instance.apply` | `{job_id, instance, config, action, plan}` | `{}` или ошибка |
| `instance.status` | `{instance}` | `{state, detail, endpoints: [{name, url}]}` |
| `link.plan` | `{link, kind, role, action, instance, port, type, peer?, device?, config}` | план своей стороны связи |
| `link.apply` | то же + `job_id`, `plan`, `binding?` | `{binding}` (поставщик) или `{}` |
| `link.remove` | то же + `job_id`, `plan` | `{}` |
| `link.status` | `{link, kind, role, instance, port, type, peer?, device?, config, binding?}` | `{state, detail}` |
| `link.refresh` | `{link, kind, role, instance, port, type, …}` | `{binding}` (поставщик) |

- `instance` — `{id, name, config}` (текущее состояние экземпляра). У создаваемого экземпляра `id`
  уже есть: Hestia заводит черновик до первого плана.
- `action` — `create` / `update` / `remove`. Для `update` в `instance.config` — старая конфигурация,
  в `config` — новая.
- `risk` — `info` (ничего не меняет), `change`, `danger` (пользователь подтверждает отдельной галкой).
- `data` — любой JSON плагина: Hestia хранит его с планом и передаёт в `apply` в `plan.data` без
  изменений. Hestia считает хеш плана (sha256 канонического JSON `{plan, config}`) и перед
  применением **запрашивает план заново**; если хеш изменился — пользователь видит «Состояние
  изменилось, проверьте план ещё раз». Поэтому план должен быть детерминированным: без времени,
  случайных чисел и т. п.
- `state` — `ok` / `degraded` / `down` / `unknown`. `endpoints` — только ссылки `http(s)://`,
  остальные Hestia отбрасывает. Статус спрашивается при открытии страницы плагина и раз в 5 минут.
- Ошибка метода — обычная ошибка JSON-RPC; её `message` увидит пользователь (по-русски, коротко).
- В `instance.plan`/`instance.apply` составного плана (см. «Связи») приходит `links: [{port, peer}]` —
  поставщики, которые подключат к новому экземпляру сразу после создания (данные — позже, в
  `link.apply`).
- `link.*` необязательны: плагин без них отвечает `-32601`, и его порты нельзя связать («плагин не
  поддерживает связи»). В Go — интерфейс `sdk.Linker`.

### Конфигурация

Значения полей формы по схеме манифеста. Особые типы:

- `target` — строка-ссылка на цель: `ssh:<id>` (SSH-сервер) или `lxc:<id>:<узел>:<vmid>` (контейнер
  Proxmox). Выбор цели в форме — это **грант**: экземпляр получает доступ только к ней.
- `secret` — в конфигурации лежит ссылка `{"secret": "<имя поля>"}`, значение читается через
  `secret.get {instance, name: "<имя поля>"}`. Значения секретов никогда не попадают в конфигурацию,
  журнал задач и ответы API.

## Методы Hestia (плагин → Hestia)

Каждый вызов проверяется: есть ли у плагина право из манифеста **и** принадлежит ли экземпляр этому
плагину, выдана ли ему цель. Отказ — ошибка `-32001` с текстом `permission denied: …` и `data`
(`{"permission": "targets.exec"}` или `{"instance": 5, "target": "ssh:2"}`).

| Метод | Право | Параметры → ответ |
|---|---|---|
| `job.step` | — | `{job_id, title}` — начать шаг задачи (предыдущий закрывается как выполненный) |
| `job.step_done` | — | `{job_id, error?}` — закрыть текущий шаг (с `error` — ошибкой) |
| `job.log` | — | `{job_id, level: info/warn/error, line}` — строка журнала; известные секреты экземпляра заменяются на `***` |
| `secret.put` | — | `{instance, name, value}` — сохранить секрет (шифруется, ≤ 64 КБ) |
| `secret.get` | — | `{instance, name}` → `{value, exists}`; `name` вида `link:<id>:<поле>` — секрет связи (см. «Связи») |
| `secret.delete` | — | `{instance, name}` |
| `target.list` | `targets.read` | `{instance}` → `[{id, kind, name, address, os, root, sudo, docker_capable}]` — цели, выданные экземпляру |
| `target.exec` | `targets.exec` | `{instance, target, cmd, stdin?, timeout_s?}` → `{code, stdout, stderr}` |
| `target.put_file` | `targets.exec` | `{instance, target, path, data_b64, mode: "0644"}` |
| `inventory.get` | `inventory.read` | `{}` → `{targets: [...], network: {...}}` (как `GET /api/v1/inventory` и `/network`) |
| `log` | — | `{level, line}` — системный журнал Hestia с префиксом id плагина |
| `deploy.plan` | `deploy.docker` | `{instance, target, project, compose, files?}` → план развёртывания (ничего не меняет) |
| `deploy.up` | `deploy.docker` | `{job_id, instance, target, project, compose, files?}` → `{project, docker, exists, containers}` |
| `deploy.down` | `deploy.docker` | `{job_id, instance, target, project, volumes}` |
| `deploy.status` | `deploy.docker` | `{instance, target, project}` → `{project, docker, exists, containers}` |

- `job.*` принимаются только для задачи `instance.apply`, которую Hestia сейчас выполняет у этого
  плагина. `deploy.up`/`deploy.down` — тоже: `job_id` должен быть задачей применения **этого
  экземпляра**, иначе `-32001`. Подробно — раздел «Развёртывание Docker compose».
- Имя секрета — `[A-Za-z0-9_.-]{1,64}`; секреты лежат в пространстве `plugin:<id>:<экземпляр>:<имя>` и
  удаляются вместе с экземпляром и плагином.
- `target.exec`: команда выполняется `sh -c` от root на цели (SSH под root или `sudo -n`, контейнер —
  `pct exec` с узла). `timeout_s` по умолчанию 60, максимум 3600. Ненулевой код выхода — не ошибка
  вызова, смотрите `code`. Вывод обрезается до 1 МБ на поток; `stdin` ≤ 4 МБ, команда ≤ 64 КБ.
- `target.put_file`: путь абсолютный, без `..` и `//`; файл ≤ 4 МБ, создаётся с `umask 077`, затем
  `chmod mode`.
- Во время плана и применения изменения (`update`) плагину доступны и старая, и новая цель; после
  успешного применения остаётся только новая.

### Коды ошибок

| Код | Значение |
|---|---|
| `-32700` | сообщение не разбирается |
| `-32601` | метод не поддерживается |
| `-32602` | неверные параметры |
| `-32603` | внутренняя ошибка (сообщение — для пользователя) |
| `-32001` | нет права или гранта (`permission denied: …`) |
| `-32002` | протокол/рукопожатие |
| `-32003` | слишком много одновременных запросов (64) |
| `-32800` | запрос отменён (`$/cancel`) |

## Права

| Право | Что даёт | Как видит пользователь |
|---|---|---|
| `targets.read` | `target.list` | «Видеть выбранные серверы (имя, адрес, ОС)» |
| `targets.exec` | `target.exec`, `target.put_file` | «Выполнять команды от root на выбранных серверах» |
| `deploy.docker` | `deploy.*` | «Разворачивать Docker-контейнеры» |
| `inventory.read` | `inventory.get` | «Читать карту сети» |
| `net.outbound` | сетевые сокеты в песочнице | «Сетевые подключения напрямую» |
| `links.client` | связи «сервис → устройство»: работа на устройстве пользователя во время `link.*` этой связи (вместе с `targets.exec`) | «Настраивать подключение на выбранных устройствах» |

Без `net.outbound` песочница разрешает только unix-сокеты: всё общение с целями — через Hestia.

## Развёртывание Docker compose (`deploy.*`)

Hestia разворачивает compose-проект плагина на выданной цели: SSH-сервер с root/sudo или
существующий контейнер LXC на подключённом Proxmox (команды — через `pct exec` с узла). Плагину не
нужно право `targets.exec`: всё, что делается на цели, делает и проверяет Hestia.

**Проект.** `project` — `^[a-z0-9][a-z0-9_-]{0,39}$`. На цели это каталог
`/opt/hestia/<экземпляр>-<project>/` (0750, файлы 0640, владелец root) и compose-проект
`hestia-<экземпляр>-<project>`. В каталоге: `compose.yaml` (то, что прислал плагин, после проверки и с
метками), файлы из `files` и служебные `.hestia-files` (список файлов Hestia) и `.hestia-prev`
(резервная копия на время `up`). Подкаталоги (данные контейнеров, например `./data`) Hestia не
трогает, кроме `deploy.down`, который удаляет каталог целиком.

**`compose` — JSON-объект**, а не текст YAML: Docker compose читает JSON как YAML, а Hestia проверяет
структуру без парсера YAML. Пример:

```json
{"services": {"whoami": {"image": "traefik/whoami:v1.10", "command": ["--name", "Привет"],
  "ports": ["8080:80"], "restart": "unless-stopped", "volumes": ["./data:/data"]}}}
```

**`files`** — `[{name, data_b64}]`, до 32 файлов, каждый ≤ 1 МБ, всё вместе ≤ 4 МБ. Имя —
`[A-Za-z0-9._-]{1,100}` без `/`; `compose.yaml` и имена на `.hestia` заняты. `.env` разрешён (compose
подставит переменные), но Hestia всегда вызывает compose с `-p` и `-f compose.yaml`, так что
`COMPOSE_FILE` и `COMPOSE_PROJECT_NAME` из `.env` ни на что не влияют.

**Что Hestia запрещает в compose** (ошибка `-32602` с путём к полю, например
`compose: services.app.privileged: привилегированный режим запрещён`):

- `privileged: true` (и в `build`, `post_start`/`pre_stop`), `cap_add`, `devices`,
  `device_cgroup_rules`, `gpus`, `deploy.resources.reservations.devices`, `security_opt`,
  `userns_mode`, `uts`, `cgroup_parent`, `cgroup` кроме `private`, `volumes_from`,
  `use_api_socket`, `provider`;
- `network_mode` кроме `bridge`/`none`/`service:<имя>`; `pid` кроме `service:<имя>`; `ipc` кроме
  `private`/`shareable`/`none`/`service:<имя>`; сети с именем или драйвером `host`;
- bind-маунты вне каталога проекта — в коротком (`/etc:/x`, `../x:/x`, `~/x:/x`) и длинном
  (`{type: bind, source: …}`) синтаксисе; тома с `driver_opts` или драйвером не `local`; типы томов
  кроме `bind`/`volume`/`tmpfs`;
- пути вне каталога проекта в `env_file`, `build.context`, `secrets.*.file`, `configs.*.file`;
  `build.additional_contexts`, `build.entitlements`, `build.network: host`;
- `include` и `extends.file` (внешние файлы Hestia не проверяет; `extends: {service: …}` можно);
- подстановки `$…` в томах, путях, портах и `*_mode` (иначе путь подменяется переменной).

Метки `hestia.plugin=<id>` и `hestia.instance=<экземпляр>` Hestia ставит каждому сервису сама
(ваши метки `hestia.*` заменяются), поле `name` верхнего уровня убирается.

**`deploy.plan`** проверяет цель и отвечает:

```json
{"project": "hestia-5-whoami", "dir": "/opt/hestia/5-whoami", "exists": false, "changed": true,
 "install_docker": false, "enable_features": false,
 "files": [{"name": "compose.yaml", "action": "create", "size": 362, "old_size": 0}],
 "actions": [{"title": "Создать проект hestia-5-whoami в /opt/hestia/5-whoami", "detail": "compose.yaml: новый, 362 Б", "risk": "change"},
             {"title": "Запустить: docker compose -p hestia-5-whoami up -d --remove-orphans", "detail": "сервисы: whoami", "risk": "change"}],
 "warnings": []}
```

Положите `actions` и `warnings` в свой план как есть — так пользователь увидит, что сделает Hestia.
Возможные действия:

- **Docker не установлен** (или нет `docker compose` v2) на Debian/Ubuntu — «Установить Docker:
  `apt-get install -y docker.io docker-compose`» (на Ubuntu пакет compose — `docker-compose-v2`).
  На другой ОС `deploy.plan` — ошибка с командой `curl -fsSL https://get.docker.com | sh` (поставить
  вручную и составить план заново).
- **Контейнер LXC без `nesting=1`** (и без `keyctl=1`, если он непривилегированный) — действие
  `risk: danger` «Включить nesting и keyctl для CT <vmid> (Proxmox, нужен перезапуск контейнера)».
  Конфигурацию CT Hestia читает через API Proxmox. Пользователь подтверждает такое действие отдельной
  галкой; без неё `deploy.up` откажет, не меняя ничего.
- **Файлы**: создать / изменить (размеры «было → стало») / без изменений / удалить лишние.
- **Порты**: если опубликованный порт на цели уже слушает не этот проект (`ss -ltnH`) — предупреждение.

План детерминирован (сортировка файлов и портов), поэтому хеш плана экземпляра не «плавает».

**`deploy.up`** выполняется внутри `instance.apply` и сам добавляет шаги в задачу (не оборачивайте
вызов в `job.step` — Hestia закроет ваш шаг): проверка цели → включение features LXC и перезапуск CT
(если нужно и подтверждено) → установка Docker (если нужно) → запись файлов → `docker compose -p …
-f compose.yaml up -d --remove-orphans` → ожидание, пока все сервисы в состоянии `running` (60 с).
При ошибке после записи файлов — откат: у существующего проекта возвращаются прежние файлы и
выполняется `up -d`, новый проект — `down -v` и удаление каталога. Docker и features LXC обратно не
снимаются (в журнале задачи — что осталось). Ответ — как у `deploy.status`. В SDK вызов без общего
таймаута (`Host.DeployUp`).

**`deploy.down`** — `docker compose down --remove-orphans` (с `volumes: true` — ещё и `-v`, именованные
тома проекта удаляются) и удаление каталога проекта; тоже шаги задачи.

**`deploy.status`** — `{project, docker, exists, containers: [{name, service, state, status, health,
exit_code, ports: [{url, target_port, published_port, protocol}]}]}` (по `docker compose ps -a`).

## Связи

Связь соединяет порт `provides` одного экземпляра с портом `requires` другого (**service**) или порт
`provides` с устройством пользователя (**device**: поставщик сам настраивает клиентскую сторону —
запись в hosts, монтирование, доверие к CA). Типы портов и данные (`binding`) — в
[`types.md`](types.md).

### Порты в манифесте

```json
"provides": [{"name": "web", "type": "http.service", "label": "Веб-страница", "client": true, "multi": true,
              "link_schema": {"fields": [{"name": "hostname", "type": "string", "label": "Имя", "default": "hello.home"}]}}],
"requires": [{"name": "target", "type": "http.service", "label": "Что проверять", "optional": false, "multi": false}]
```

- `name` — `^[a-z][a-z0-9_]{0,31}$`, уникален в своём списке; без `name` (манифесты 02h) — `type` с
  заменой `.`/`-` на `_`.
- `type` — официальный тип из `types.md` или свой `<id плагина>.<имя>`. Неизвестный официальный тип
  или чужой префикс — пакет отклоняется. Совместимость — точное совпадение `type`.
- `provides.multi` (по умолчанию `true`) — много потребителей; `requires.multi` (по умолчанию
  `false`) — несколько поставщиков; `requires.optional` (по умолчанию `false`).
- `provides.client` — поставщик умеет связь с устройством; требует права `links.client`.
- `provides.link_schema` — форма связи (как `schema.fields`, без `target`, `secret` и пресетов);
  значения приходят в `config` вызовов `link.*`.

### Жизненный цикл

Создание и удаление — план → подтверждение → задача `plugin-link` (как у экземпляров: хеш, 15 мин,
перепроверка планов обеих сторон перед применением). В `link.*` приходят: `link` — id связи,
`kind` (`service`/`device`), `role` (`provider`/`consumer`/`client`), `instance` — свой экземпляр,
`port`, `type`, `peer` — другая сторона (`{plugin, instance, name, port}` — единственное, что плагин
узнаёт о чужих экземплярах), `device` — устройство (`{id, kind, name, address, …}` как в
`target.list`), `action` (`create`/`remove`; при повторном применении после refresh — `update`).

**service:**

1. `link.plan` у поставщика (`role: provider`) и у потребителя (`role: consumer`) — действия обеих
   сторон в одном плане.
2. `link.apply` у поставщика → `{binding}`. Hestia проверяет binding по типу (ошибка — связь не
   создаётся), значения полей-секретов кладёт в секреты связи `link:<id>:<поле>`, а в binding ставит
   ссылки `{"secret": "link:<id>:<поле>"}`. Затем `link.apply` у потребителя с этим binding. Ошибка
   потребителя → `link.remove` у поставщика (откат), запись удаляется.
3. Удаление: `link.remove` у потребителя, затем у поставщика, секреты связи удаляются. Если сторона
   ответила ошибкой — связь `orphaned` (видна, можно удалить только запись).

**device:**

1. `link.plan` у поставщика с `role: client`, `device`, `config`.
2. `link.apply` — поставщик работает на устройстве через `target.exec`/`target.put_file`. Может
   вернуть binding (тот же тип порта) — Hestia сохранит его и по нему заметит изменения.
3. `link.remove` у поставщика, затем доступ к устройству снимается.

**Статус:** `link.status` у сторон связи при открытии карты (не чаще раза в минуту) и раз в 5 минут;
итог — худший из `ok/degraded/down/unknown`.

**Изменение экземпляра-поставщика:** после успешного `instance.apply` (`update`) Hestia вызывает
`link.refresh` по каждой его связи; если binding изменился — `link.apply` (`action: update`) у
потребителя или (device) у поставщика на устройстве. Ошибка не отменяет изменение экземпляра, связь
помечается `degraded`. **Удаление экземпляра** со связями — один план: сначала связи, потом экземпляр.

### Составной план

`POST /api/v1/plugins/compose/plan` — новый экземпляр с зависимостями: для каждого `requires` —
существующий поставщик или новый экземпляр (вложенно, глубина ≤ 3, тот же плагин в цепочке —
ошибка). Шаги: новые поставщики (сначала самые глубокие) → экземпляр → связи; общий хеш; задача
`plugin-compose`; при ошибке уже выполненные шаги откатываются в обратном порядке (`link.remove`,
удаление экземпляра через `instance.plan`/`instance.apply` с `action: remove`).

### Доступ

- Устройство связи `device` — грант экземпляра-поставщика с пометкой `via_link`: `target.exec`,
  `target.put_file`, `deploy.*` к нему проходят **только во время вызова `link.*` этой связи** и
  пока связь существует (плюс права `targets.exec`/`deploy.docker`). В `target.list` оно не
  попадает, своей целью экземпляра не становится.
- `secret.get` секрета `link:<id>:<поле>` — только экземпляру-потребителю этой связи и только пока
  связь активна. `secret.put`/`secret.delete` для `link:*` запрещены всем: поставщик передаёт
  секреты только в binding (`link.apply`/`link.refresh`).
- Значения секретов связи маскируются в журнале задачи и не попадают в БД открытым текстом и в API.

## Манифест и пакет

`manifest.json` вшивается в бинарник (`//go:embed`) и кладётся в пакет. Поля — см.
`docs/plan/02h-stage-2a1-plugins.md` («manifest.json») и тип `sdk.Manifest`. Коротко:

- `id` — `^[a-z][a-z0-9-]{1,39}$`; префикс `hestia-` — только для официального ключа; `version` —
  `vX.Y.Z`; `author.key` — ваш публичный ed25519-ключ (base64), им подписан пакет.
- `schema.fields[]`: `name` (`^[a-z][a-z0-9_]{0,39}$`), `type` (`string`, `text`, `int`, `bool`,
  `enum` с `options`, `secret`, `target` с необязательным `filter: {"docker_capable": true}`),
  `label`, `help`, `default`, `required`, `advanced`, `min`/`max`, `max_len`, `pattern` (регулярное
  выражение RE2 на всё значение). `schema.presets[]` — `{name, label, values}` (без `secret`/`target`).
- Пакет `<id>-<version>-linux-amd64.hpkg` — tar.gz из `manifest.json`, `plugin` (статический
  linux/amd64), необязательных `icon.svg` (≤ 64 КБ, очищается от скриптов) и `README.md`, плюс
  `SHA256SUMS` и `SHA256SUMS.sig` (base64-подпись `SHA256SUMS` ключом автора). Больше ничего: ни
  каталогов, ни ссылок; всё вместе ≤ 64 МБ.

Сборка и подпись:

```sh
go run ./cmd/hestia-release plugin-keygen --out ~/.config/my-plugins.key --pub my.pub   # один раз
# впишите содержимое my.pub в author.key манифеста, затем
CGO_ENABLED=0 go build -o build/plugins/my-plugin/plugin ./plugins/my-plugin
go run ./cmd/hestia-release plugin-pack --key ~/.config/my-plugins.key --dir build/plugins/my-plugin --out dist/plugins
go run ./cmd/hestia-release plugin-verify dist/plugins/my-plugin-v0.1.0-linux-amd64.hpkg
```

Первая установка стороннего плагина показывает отпечаток ключа (SHA-256) и закрепляет ключ;
обновления принимаются только с тем же ключом и только с большей версией.

`plugin-pack --version vX.Y.Z` дополнительно сверяет версию в `manifest.json` (так делает
`make plugin`). Ключ — только у вас: не кладите его в репозиторий; потеряли ключ — пользователям
придётся удалить плагин и поставить заново с новым ключом.

## Каталог и подпись

- **Официальный каталог** — релиз GitHub с постоянным тегом `plugins-catalog` в `uxerror/hestia`
  (pre-release, чтобы не мешать проверке обновлений Hestia): `index.json`, `index.json.sig` и пакеты
  `.hpkg` (старые версии остаются). Hestia проверяет его раз в сутки и по кнопке «Проверить сейчас».
- `index.json`:
  `{"generated": "<RFC3339>", "plugins": [{"id", "name", "version", "description", "min_hestia",
  "url", "sha256", "size", "permissions", "provides", "requires"}]}`; одна запись на `id`.
- `index.json.sig` — base64 подписи ed25519 **всего файла** `index.json` официальным ключом плагинов
  (`internal/plugins/official.pub`). Неверная подпись — каталог не показывается совсем, в интерфейсе
  ошибка. Сетевая ошибка — остаётся последний проверенный каталог и предупреждение.
- Установка из каталога: Hestia скачивает `url`, сверяет `size` и `sha256` с каталогом, затем
  проверяет пакет как любой другой (подпись `SHA256SUMS` ключом автора) и требует, чтобы он был
  подписан официальным ключом и совпадал по `id` и `version` с записью. Обновления официальных
  плагинов видны в списке плагинов («Обновить до vX»); понизить версию нельзя.
- `hestia-release catalog-add --index dist/plugins/index.json --key <ключ> <пакет.hpkg>...`
  добавляет или заменяет записи (понижение версии — ошибка), сортирует по `id` и пишет рядом
  `index.json.sig`. `make plugin-publish ID=<id> VERSION=<v>` делает это для официальных плагинов.
- **Сторонние авторы** в официальный каталог не попадают: распространяйте `.hpkg` ссылкой
  (`https://`, ≤ 64 МБ, редиректы GitHub разрешены) или файлом. Удобно — релизом GitHub своего
  репозитория. Доверие — по закреплённому ключу автора (см. выше); автопроверки обновлений для
  сторонних плагинов пока нет — пользователь ставит новую версию той же кнопкой.

## Песочница

Юнит `hestia-plugin@<id>.service`: `DynamicUser=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, пустой `CapabilityBoundingSet`, нет доступа к
`/var/lib/hestia` и `/etc/hestia`, `MemoryMax=256M`, `TasksMax=64`. Своё состояние плагин держит в
`$STATE_DIRECTORY` (`/var/lib/hestia-plugin/<id>`), оно удаляется вместе с плагином; файлы
создаются с `UMask=0077`. Сетевые сокеты — только с правом `net.outbound`. Шаблон юнита и
drop-in'ы Hestia обновляет при установке или обновлении любого плагина, если их содержимое
отличается от текущей версии (с `systemctl daemon-reload`).

## Пример сессии

`→` — от плагина к Hestia, `←` — от Hestia к плагину (каждая строка — отдельное сообщение). Пример —
плагин, работающий через `target.exec`/`target.put_file` (так был устроен `hestia-hello` v0.1.0;
v0.2.0 делает то же через `deploy.plan`/`deploy.up`, см. `plugins/hestia-hello`).

```
→ {"jsonrpc":"2.0","id":1,"method":"hello","params":{"protocol":1,"id":"hestia-hello","version":"v0.1.0","token":"6f1c…"}}
← {"jsonrpc":"2.0","id":1,"result":{"protocol":1,"hestia_version":"v0.2.0","instances":[]}}
← {"jsonrpc":"2.0","id":1,"method":"instance.validate","params":{"config":{"target":"ssh:1","message":"Привет"}}}
→ {"jsonrpc":"2.0","id":1,"result":[]}
← {"jsonrpc":"2.0","id":2,"method":"instance.plan","params":{"instance":{"id":5,"name":"Hestia Hello 1","config":{"target":"ssh:1","message":"Привет"}},"config":{"target":"ssh:1","message":"Привет"},"action":"create"}}
→ {"jsonrpc":"2.0","id":2,"method":"target.exec","params":{"instance":5,"target":"ssh:1","cmd":"cat /tmp/hestia-hello-5 2>/dev/null || exit 3","timeout_s":30}}
← {"jsonrpc":"2.0","id":2,"result":{"code":3,"stdout":"","stderr":""}}
→ {"jsonrpc":"2.0","id":3,"method":"target.list","params":{"instance":5}}
← {"jsonrpc":"2.0","id":3,"result":[{"id":"ssh:1","kind":"ssh","name":"web","address":"10.10.10.21","os":"Debian GNU/Linux 13 (trixie)","root":true,"sudo":false,"docker_capable":true}]}
→ {"jsonrpc":"2.0","id":2,"result":{"actions":[{"title":"Записать приветствие в /tmp/hestia-hello-5","detail":"на web","risk":"change"}],"warnings":[],"data":{"path":"/tmp/hestia-hello-5","target":"ssh:1","write":true}}}
← {"jsonrpc":"2.0","id":3,"method":"ping"}
→ {"jsonrpc":"2.0","id":3,"result":{}}
   … пользователь нажал «Применить»: Hestia запрашивает план ещё раз (тот же хеш) и запускает задачу …
← {"jsonrpc":"2.0","id":5,"method":"instance.apply","params":{"job_id":"a1b2c3d4e5f60718","instance":{"id":5,"name":"Hestia Hello 1","config":{"target":"ssh:1","message":"Привет"}},"config":{"target":"ssh:1","message":"Привет"},"action":"create","plan":{"actions":[…],"warnings":[],"data":{"path":"/tmp/hestia-hello-5","target":"ssh:1","write":true}}}}
→ {"jsonrpc":"2.0","id":6,"method":"job.step","params":{"job_id":"a1b2c3d4e5f60718","title":"Запись приветствия"}}
← {"jsonrpc":"2.0","id":6,"result":{}}
→ {"jsonrpc":"2.0","id":7,"method":"target.put_file","params":{"instance":5,"target":"ssh:1","path":"/tmp/hestia-hello-5","data_b64":"0J/RgNC40LLQtdGCCg==","mode":"0644"}}
← {"jsonrpc":"2.0","id":7,"result":{}}
→ {"jsonrpc":"2.0","id":8,"method":"job.step_done","params":{"job_id":"a1b2c3d4e5f60718"}}
← {"jsonrpc":"2.0","id":8,"result":{}}
→ {"jsonrpc":"2.0","id":9,"method":"job.log","params":{"job_id":"a1b2c3d4e5f60718","level":"info","line":"/tmp/hestia-hello-5: Привет"}}
← {"jsonrpc":"2.0","id":9,"result":{}}
→ {"jsonrpc":"2.0","id":5,"result":{}}
← {"jsonrpc":"2.0","id":6,"method":"instance.status","params":{"instance":{"id":5,"name":"Hestia Hello 1","config":{"target":"ssh:1","message":"Привет"}}}}
→ (target.exec cat …) 
→ {"jsonrpc":"2.0","id":6,"result":{"state":"ok","detail":"Привет","endpoints":[]}}
```

Обратите внимание: у Hestia и у плагина свои счётчики `id` — `id: 2` от Hestia и `id: 2` от
плагина не связаны; ответ относится к запросу той стороны, которой он адресован.

Попытка выйти за грант:

```
→ {"jsonrpc":"2.0","id":10,"method":"target.exec","params":{"instance":5,"target":"ssh:2","cmd":"id"}}
← {"jsonrpc":"2.0","id":10,"error":{"code":-32001,"message":"permission denied: цель ssh:2 не выдана экземпляру 5","data":{"instance":5,"target":"ssh:2"}}}
```

## Совместимость

Версия протокола — целое число в `hello`. Новые методы и поля добавляются без смены версии
(неизвестные поля игнорируйте); несовместимые изменения — новая версия протокола, Hestia в ответе на
неподдерживаемую сообщает диапазон `{min, max}`.
