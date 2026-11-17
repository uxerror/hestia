# 02c. Этап 1e-1 — «Системы»: инвентарь подключённых целей

Цель: после подключения видно всё про каждую систему: узлы, железо, загрузку, хранилища, гостей
(VM и LXC) с IP. Только чтение. Сканирование сети, отпечатки сервисов и карта — этап 1e-2.
Самоустановка (1c) — после этого этапа.

## Источник данных

Proxmox — только API с токеном Hestia (`PVEAPIToken=hestia@pve!hestia=…`, пиннинг TLS как в 1b):
- `GET /cluster/resources` — одним запросом узлы, хранилища, VM, LXC: cpu/maxcpu, mem/maxmem,
  disk/maxdisk, status, uptime, node, name, vmid, tags, template;
- `GET /cluster/status` — имя кластера, кворум, узлы и их IP;
- `GET /nodes/{node}/status` — модель CPU (cpuinfo: model, sockets, cores, cpus), loadavg,
  kernel, pveversion, rootfs, memory, swap;
- `GET /nodes/{node}/storage` — хранилища узла (тип, content, active, shared, used/total);
- IP гостей: LXC — `GET /nodes/{node}/lxc/{vmid}/interfaces`; QEMU (только запущенные) —
  `GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`. Ошибка агента
  («VM … is not running», агент не установлен/не запущен, 500) — не ошибка инвентаря:
  у гостя `ip_source: "none"` и причина. Запросы IP — параллельно, не больше 8 одновременно,
  таймаут 5 с на запрос.
- Привилегия: для агента нужна `VM.GuestAgent.Audit` (есть в PVE 9). Добавить её в список
  привилегий роли Hestia в коде подключения (1b). Для уже подключённой цели, если API отвечает
  403 на агент, — в инвентаре баннер «Роль Hestia устарела: не хватает VM.GuestAgent.Audit» с
  кнопкой «Дополнить роль» → план (одна команда `pveum role modify Hestia --privs …`) →
  подтверждение → job по SSH ключом Hestia с пиннингом. Без подтверждения ничего не меняем.

Отдельный SSH-сервер — те же факты, что в проверке 1b (ОС, ядро, CPU, RAM, диски, docker),
собираются заново ключом Hestia.

## Хранение и обновление

- Снимок инвентаря цели — таблица `inventory(target_id PK, collected_at, data JSON, error)`.
- Сбор — job «Обновление инвентаря» (видна в задачах), запускается: сразу после подключения
  цели (в конце job подключения или отдельной job), по кнопке «Обновить», и фоном раз в 60 с,
  пока хоть один клиент держит открытым SSE `/api/v1/inventory/events` (без клиентов — не
  опрашиваем). Одновременно не больше одной сборки на цель.
- API: `GET /api/v1/inventory` (все цели: последний снимок + возраст), `GET
  /api/v1/inventory/{target_id}`, `POST /api/v1/inventory/{target_id}/refresh` → 202 `{job}`,
  `GET /api/v1/inventory/events` (SSE: `snapshot` при обновлении цели).
- Нормализованная модель (Go-структуры, JSON snake_case): Target → Nodes[] (name, ip, online,
  cpu_model, sockets, cores, threads, cpu_usage, load1/5/15, mem_used/total, swap,
  rootfs_used/total, uptime, kernel, pve_version) → Storages[] (name, type, content[], shared,
  active, used, total, nodes[]) → Guests[] (vmid, type qemu|lxc, name, node, status, template,
  tags[], cpus, cpu_usage, mem_used/total, disk_used/total, uptime, ips[], ip_source, ip_error).
  Shared-хранилища (shared=1) показывать один раз на кластер, не по разу на узел.

## Интерфейс

- «Системы» (главный экран после мастера): карточка на цель. У Proxmox: имя кластера, кворум,
  версия; внутри — карточки узлов: модель CPU, потоков, загрузка (progress), RAM (progress),
  rootfs, uptime, гости «запущено/всего». Ниже — хранилища кластера (занято/всего, тип,
  shared-бейдж). Для SSH-сервера — одна карточка с теми же полями.
- Клик по узлу → таблица гостей: VMID, имя, тип (VM/LXC), статус (бейдж), CPU, RAM, диск, IP,
  теги, «шаблон». Фильтры: узел, тип, статус; поиск по имени/IP/VMID; сортировка по колонкам.
  Показывать и остановленные (серым).
- Время сбора («обновлено 20 с назад»), кнопка «Обновить», ошибки сбора — alert на карточке.
- Размеры — в двоичных единицах (ГиБ/ТиБ), проценты — целые.

## Тесты

- Фикстуры с живого кластера (без секретов): `internal/proxmox/testdata/real-pve9-api/`
  (cluster_resources, cluster_status, node_status_*, node_storage_*, lxc_ifaces_110,
  lxc_config_110, qemu109_agent_ifaces, qemu113_agent_ifaces, qemu109_config,
  qemu_stopped_agent_err.txt — текст ошибки pvesh, в API это HTTP 500 с этим сообщением).
  Важно: это вывод `pvesh --output-format json` — тела ответов API это то же, обёрнутое в
  `{"data": …}`; фейковый API должен оборачивать.
- httptest TLS-сервер, раздающий фикстуры: нормализация (3 узла, 34 qemu + 6 lxc, shared-
  хранилища один раз, IP у LXC 110 и у QEMU 109), ошибка агента → ip_source none,
  403 на агент → флаг «нужна VM.GuestAgent.Audit», таймаут одного гостя не валит сборку.
- Планировщик: не опрашивает без подписчиков, одна сборка на цель одновременно.
- Фронтенд: форматирование размеров/процентов, фильтр/сортировка гостей.

## Отклонения (по факту реализации)

- **Привилегия гостевого агента зависит от версии Proxmox.** `VM.GuestAgent.Audit` есть только в PVE 9+;
  на PVE 8 `pveum role add/modify` с неизвестной привилегией падает. Поэтому `proxmox.Privileges` — базовый
  набор, а `proxmox.PrivilegesFor(version)` добавляет `VM.GuestAgent.Audit` (версия ≥ 9 или неизвестна) либо
  `VM.Monitor` (версия < 9: так агент закрыт в PVE 8 — из знания о PVE, на живом PVE 8 не проверялось).
  `CmdRoleCreate`/`CmdRoleModify` стали функциями от версии; план подключения показывает набор для версии.
- **Дополнение роли** — отдельные эндпоинты `GET/POST /api/v1/inventory/{id}/role-fix`: GET читает роль по SSH
  ключом Hestia (только чтение) и возвращает `{needed, version, missing, command}`; POST требует
  `{"confirm": true}` и запускает job «Дополнение роли Hestia» (одна команда `pveum role modify`, права роли,
  которых нет в нашем списке, сохраняются). Баннер показывается по флагу `needs_guest_agent_audit` в снимке
  (любой 403 на запросе к агенту).
- **Хранилища.** Берутся из `GET /nodes/{node}/storage` каждого узла в сети (для узлов не в сети — из
  `/cluster/resources`). Shared — одна запись на кластер со списком узлов; локальные (`local`, `local-lvm`) —
  по записи на узел. Поле `Storage.Nodes` — список узлов, которые видят хранилище.
- **Снимок.** Помимо плана добавлены: `kind`, `clustered`, `quorate`, `version`, `needs_guest_agent_audit`,
  `warnings[]`; у узла — `os`, `docker` (для SSH-сервера), `cpu_usage` (доля 0..1; у SSH-сервера оценка
  load1/потоков). Версия PVE узла: `pve_version` без префикса `pve-manager/`. Проценты считает фронтенд.
- **Ошибки сбора.** Таблица `inventory` (миграция 4): при неудачной сборке прошлый снимок и `collected_at`
  сохраняются, пишется `error`; у цели без снимка `collected_at` пуст. Сбор падает только если не отвечает
  `/cluster/resources` (или токен/TLS-пиннинг отвергнуты); остальное — `warnings` и `ip_error` у гостя.
- **Одна сборка на цель.** Повторный `POST …/refresh` во время сбора не создаёт вторую job: возвращает 202 с
  уже идущей.
- **IP гостей.** Только у запущенных не-шаблонов. Отбрасываются loopback, link-local и интерфейсы
  `veth*`, `docker*`, `br-*`, `virbr*`, `cni*`, `flannel*`; IPv4 идут раньше IPv6. Остановленный гость:
  `ip_source: "none"`, `ip_error: "гость остановлен"`; шаблон — «шаблон».
- **События SSE** `/api/v1/inventory/events`: событие `snapshot` с записью цели публикуется при начале и при
  конце сборки (`collecting`); при подключении текущее состояние не шлётся — клиент берёт его через
  `GET /api/v1/inventory`. Подписка первого клиента сразу будит планировщик; цели со снимком моложе
  полуинтервала (30 с) пропускаются.
- **Старт сбора после подключения** — хук `onboard.Service.AfterChange` (после сохранения цели и после
  дополнения роли), отдельная job «Обновление инвентаря».
- **Интерфейс.** «Системы» (`#/targets`) показывает карточки целей с узлами и хранилищами; клик по узлу —
  `#/targets/<id>/<узел>` (таблица гостей с фильтрами и сортировкой; `#/targets/<id>` — все узлы). Колонка
  «Узел» добавлена в таблицу гостей, «шаблон» — отдельная колонка с бейджем. Диск QEMU-гостя PVE не
  отдаёт в `disk` (всегда 0) — показывается только размер.
