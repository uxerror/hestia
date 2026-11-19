# Hestia Hello

Демонстрационный плагин Hestia и образец для авторов плагинов. Ставит веб-сервис
[whoami](https://github.com/traefik/whoami) (`traefik/whoami:v1.10`) в Docker на выбранном сервере
или контейнере Proxmox и проверяет, что он отвечает по HTTP. Приветствие из формы whoami
показывает в ответе (`Name: …`).

- Поля формы: `target` — где запустить (Debian/Ubuntu; Docker Hestia поставит сама, если его нет),
  `port` — порт на цели (8080), `message` — приветствие.
- Права: `targets.read` (адрес цели для проверки), `deploy.docker` (развёртывание через Hestia),
  `net.outbound` (сам плагин делает GET к whoami), `targets.exec` и `links.client` (запись в
  `/etc/hosts` устройства по связи).
- Предоставляет порт `web` (`http.service`, «Веб-страница»):
  - связь с сервисом (например, [Hestia Probe](../hestia-probe/README.md)) — отдаёт binding
    `{url, host, port, scheme}` (адрес цели и порт whoami);
  - связь с устройством (`client: true`) — строка `<IP цели> <имя> # hestia-link-<id>` в `/etc/hosts`
    устройства; имя — поле формы связи `hostname` (по умолчанию `hello.home`). Файл правится
    атомарно (временная копия с теми же правами + `mv`), строка заменяется и удаляется по маркеру;
    статус — строка на месте и `getent hosts <имя>` даёт адрес цели;
  - `link.refresh` после изменения экземпляра (другой порт или цель) — новый binding; Hestia сама
    применит его у потребителя и на устройстве.

- Требует (необязательно) порт `tls` (`tls.cert`, «HTTPS») — демо выпуска сертификата по CSR
  (v0.4.0): в плане связи — предпросмотр `{ips: [<IP цели>], dns: [tls_name?]}`; `link.prepare`
  создаёт ключ ECDSA P-256 в `$STATE_DIRECTORY/tls-<связь>.key.pending` (0600) и отдаёт CSR;
  `link.apply` поднимает второй сервис `whoami-tls` на `tls_port` (8443) с `--cert/--key` из файлов
  проекта (0640 root) — ключ переносится в `tls-<связь>.key` только после успешного `deploy.up`;
  `link.remove` возвращает compose без `whoami-tls` и удаляет ключи. Поля `tls_port`, `tls_name` —
  в «Дополнительно».

## Как устроен

- `manifest.json` — манифест; вшит в бинарник (`//go:embed`) и кладётся в пакет.
- `main.go` — `sdk.Serve(manifest, &hello{})`.
- `hello.go`:
  - `Plan` — `deploy.plan` с compose-файлом из одного сервиса (JSON-объект: Hestia принимает
    compose в JSON) плюс действие «Проверить http://<адрес>:<порт>/»; действия Hestia (установить
    Docker, включить nesting/keyctl в LXC, создать/изменить проект) попадают в план как есть;
  - `Apply` — `deploy.up` (Hestia сама пишет шаги задачи и откатывает проект при ошибке), затем
    GET до ответа 200 за 20 с; при смене цели — сначала `deploy.down` на старой;
  - `Status` — GET: `ok` / `degraded` (не 200) / `down` (нет ответа), ссылка на сервис;
  - удаление экземпляра — `deploy.down` с `volumes: true`.
- `links.go` — `sdk.Linker`: `LinkPlan`/`LinkApply`/`LinkRemove`/`LinkStatus`/`LinkRefresh`.
- `hello_test.go`, `links_test.go` — юнит-тесты на `sdk/sdktest` (фейковая Hestia: `OnDeployPlan`,
  `OnDeployUp`, `OnExec`, `LinkApply`, …; «устройство» — временный каталог и белый список утилит).

Протокол и правила для compose-файла — `docs/plugins/protocol.md`.

## Запуск в режиме разработки

```sh
CGO_ENABLED=0 go build -o build/plugins/hestia-hello/plugin ./plugins/hestia-hello
go run ./cmd/hestia serve --listen 127.0.0.1:8080 --data /tmp/hestia-dev --plugin-dev build/plugins/hestia-hello/plugin
```

Плагин запускается дочерним процессом без песочницы и подписи (в интерфейсе — плашка «dev»).
Цель для экземпляра — сервер, подключённый к Hestia (SSH с root/sudo) или контейнер Proxmox.

## Свой плагин на основе этого

1. Скопируйте `plugins/hestia-hello` в свой репозиторий, поменяйте `id` (префикс `hestia-` —
   только для официальных плагинов), `name`, `version`, `author.name`.
2. Создайте свой ключ подписи (один раз; храните только у себя):

   ```sh
   go run github.com/uxerror/hestia/cmd/hestia-release@latest plugin-keygen \
     --out ~/.config/my-plugins.key --pub my-plugins.pub
   ```

   Впишите содержимое `my-plugins.pub` в `author.key` манифеста (манифест вшит в бинарник, поэтому
   ключ — до сборки).
3. Соберите статический бинарник и пакет:

   ```sh
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o build/plugins/my-plugin/plugin .
   hestia-release plugin-pack --key ~/.config/my-plugins.key --dir build/plugins/my-plugin \
     --src . --out dist --version v0.1.0
   hestia-release plugin-verify dist/my-plugin-v0.1.0-linux-amd64.hpkg
   ```

4. Поставьте: «Плагины → Установить из файла/ссылки» (файл `.hpkg` или ссылка `https://…`, например на
   релиз GitHub). При первой установке Hestia покажет отпечаток вашего ключа и права плагина;
   обновления принимаются только с тем же ключом и с большей версией.

## Официальная сборка (для сопровождающего)

```sh
make plugin ID=hestia-hello VERSION=v0.4.0          # build/plugins/hestia-hello/plugin + dist/plugins/*.hpkg
make plugin-publish ID=hestia-hello VERSION=v0.4.0  # тег plugin/hestia-hello/v0.4.0, каталог plugins-catalog
```

`make plugin` подписывает ключом `~/.config/hestia/plugins.key` (`PLUGIN_KEY=…` — другой) и сверяет
`VERSION` с манифестом. `make plugin-publish` требует чистое дерево и `gh auth login`; публикуется
только по решению сопровождающего.
