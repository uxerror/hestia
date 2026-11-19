# Hestia Probe

Демонстрационный плагин связей Hestia. Проверка HTTP-сервиса: экземпляр требует поставщика
`http.service` (например, [Hestia Hello](../hestia-hello/README.md)), раз в `interval_s` секунд делает
GET по его адресу и показывает ответ в статусе: `ok` — «200, 12 мс, Name: Привет от Hestia» (первая
строка тела `Name:`), `degraded` — другой код ответа, `down` — сервис не отвечает. Без связи —
`degraded` «Не подключён к сервису».

- Поля формы: `interval_s` — интервал проверки (30…3600 с, по умолчанию 60).
- Права: только `net.outbound` (сам плагин делает GET). Целей и Docker нет: работает в своей песочнице
  на контроллере; план создания — «Создать проверку», действий на серверах нет.
- Требует `target` (`http.service`, обязательный, один поставщик). При создании Hestia предлагает
  выбрать существующий экземпляр Hello или создать новый — одним составным планом.

## Как устроен

- `manifest.json` — манифест (вшит в бинарник).
- `probe.go`:
  - `Plan`/`Apply` — только конфигурация (интервал); в плане создания — строка о будущей связи
    (`PlanRequest.links`);
  - `LinkApply` (роль `consumer`) — запоминает binding (`url`) в `$STATE_DIRECTORY/links.json` и
    запускает опрос; `LinkRemove` — останавливает; `LinkStatus` — результат последней проверки;
  - после перезапуска связи восстанавливаются из `welcome.links` (Hestia передаёт активные связи
    при подключении), так что файл состояния — только кеш;
  - роль `provider`/`client` и `link.refresh` не поддерживаются (ошибка).
- `probe_test.go` — тесты на `sdk/sdktest` (`LinkApply`, `LinkStatus`, `NewWith` с welcome).

## Запуск в режиме разработки

```sh
CGO_ENABLED=0 go build -o build/plugins/hestia-hello/plugin ./plugins/hestia-hello
CGO_ENABLED=0 go build -o build/plugins/hestia-probe/plugin ./plugins/hestia-probe
go run ./cmd/hestia serve --listen 127.0.0.1:8080 --data /tmp/hestia-dev \
  --plugin-dev build/plugins/hestia-hello/plugin --plugin-dev build/plugins/hestia-probe/plugin
```

Составной план «probe + новый hello»: `POST /api/v1/plugins/compose/plan` с
`{"root": {"plugin_id": "hestia-probe", "config": {}}, "deps": [{"port": "target",
"new": {"plugin_id": "hestia-hello", "config": {"target": "ssh:1"}}}]}`, затем
`POST /api/v1/plugins/plans/<plan_id>/apply` с `{"hash": "…"}`. Протокол связей —
`docs/plugins/protocol.md`, типы — `docs/plugins/types.md`.

Пакет: `make plugin ID=hestia-probe VERSION=v0.1.0`.
