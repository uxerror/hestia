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
  проверяется — плагин помечен «dev, без песочницы»).

## Методы плагина (Hestia → плагин)

| Метод | Параметры | Ответ |
|---|---|---|
| `manifest` | `{}` | манифест (тот же `manifest.json`, что в пакете; при установке сверяется побайтно после канонизации JSON) |
| `instance.validate` | `{config}` | `[{field, msg}]` — пустой массив, если всё верно |
| `instance.plan` | `{instance, config, action}` | `{actions: [{title, detail, risk}], warnings: [...], data}` |
| `instance.apply` | `{job_id, instance, config, action, plan}` | `{}` или ошибка |
| `instance.status` | `{instance}` | `{state, detail, endpoints: [{name, url}]}` |

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
| `secret.get` | — | `{instance, name}` → `{value, exists}` |
| `secret.delete` | — | `{instance, name}` |
| `target.list` | `targets.read` | `{instance}` → `[{id, kind, name, address, os, root, sudo, docker_capable}]` — цели, выданные экземпляру |
| `target.exec` | `targets.exec` | `{instance, target, cmd, stdin?, timeout_s?}` → `{code, stdout, stderr}` |
| `target.put_file` | `targets.exec` | `{instance, target, path, data_b64, mode: "0644"}` |
| `inventory.get` | `inventory.read` | `{}` → `{targets: [...], network: {...}}` (как `GET /api/v1/inventory` и `/network`) |
| `log` | — | `{level, line}` — системный журнал Hestia с префиксом id плагина |
| `deploy.*` | `deploy.docker` | следующий этап (сейчас — ошибка `-32601`) |

- `job.*` принимаются только для задачи `instance.apply`, которую Hestia сейчас выполняет у этого
  плагина.
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
| `deploy.docker` | `deploy.*` (следующий этап) | «Разворачивать Docker-контейнеры» |
| `inventory.read` | `inventory.get` | «Читать карту сети» |
| `net.outbound` | сетевые сокеты в песочнице | «Сетевые подключения напрямую» |

Без `net.outbound` песочница разрешает только unix-сокеты: всё общение с целями — через Hestia.

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

## Песочница

Юнит `hestia-plugin@<id>.service`: `DynamicUser=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, пустой `CapabilityBoundingSet`, нет доступа к
`/var/lib/hestia` и `/etc/hestia`, `MemoryMax=256M`, `TasksMax=64`. Своё состояние плагин держит в
`$STATE_DIRECTORY` (`/var/lib/hestia-plugin/<id>`), оно удаляется вместе с плагином. Сетевые
сокеты — только с правом `net.outbound`.

## Пример сессии

`→` — от плагина к Hestia, `←` — от Hestia к плагину (каждая строка — отдельное сообщение).

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
