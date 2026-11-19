# Hestia Hello

Демонстрационный плагин Hestia и образец для авторов плагинов. В этой версии он проверяет каркас
плагинов: записывает приветствие в файл `/tmp/hestia-hello-<номер экземпляра>` на выбранном сервере
(через `target.put_file`), читает его обратно (`target.exec cat`) для плана и статуса и удаляет при
удалении экземпляра. Версия с контейнером whoami в Docker — следующий этап.

Права: `targets.read` (имя выбранного сервера в плане), `targets.exec` (запись и чтение файла).

## Как устроен

- `manifest.json` — манифест; вшит в бинарник (`//go:embed`) и кладётся в пакет.
- `main.go` — `sdk.Serve(manifest, &hello{})`.
- `hello.go` — `Validate`, `Plan` (что сделает: записать / перезаписать / без изменений / удалить),
  `Apply` (шаги задачи через `job.Run`), `Status` (`ok` / `degraded` / `down`).
- `hello_test.go` — юнит-тесты на `sdk/sdktest` (фейковая Hestia).

## Запуск в режиме разработки

```sh
CGO_ENABLED=0 go build -o build/plugins/hestia-hello/plugin ./plugins/hestia-hello
go run ./cmd/hestia serve --listen 127.0.0.1:8080 --data /tmp/hestia-dev --plugin-dev build/plugins/hestia-hello/plugin
```

Плагин запускается дочерним процессом без песочницы и подписи (в интерфейсе — плашка «dev»).

## Пакет

```sh
go run ./cmd/hestia-release plugin-keygen --out ~/.config/hestia/plugins.key   # один раз; ключ — только у вас
# впишите публичный ключ (internal/plugins/official.pub) в author.key манифеста и пересоберите
CGO_ENABLED=0 go build -o build/plugins/hestia-hello/plugin ./plugins/hestia-hello
go run ./cmd/hestia-release plugin-pack --dir build/plugins/hestia-hello --out dist/plugins
go run ./cmd/hestia-release plugin-verify dist/plugins/hestia-hello-v0.1.0-linux-amd64.hpkg
```

Готовый `.hpkg` ставится в «Плагины → Установить из файла/ссылки». Протокол — `docs/plugins/protocol.md`.
