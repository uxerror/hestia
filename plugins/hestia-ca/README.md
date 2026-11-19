# HestiaCA

Свой корневой CA Hestia. Ключ CA живёт **только** в томе `ca-data` контейнера `ca-server` на
выбранной цели (0600, uid 65532) — никогда в базе Hestia, в данных плагина или в связях. Плагин (в
песочнице на контроллере) говорит с ca-server по TLS с закреплённым ключом API и токеном экземпляра
(секрет Hestia; в контейнер передаётся только sha256 токена).

- **Корень:** ECDSA P-256, 10 лет (`root_years`), `MaxPathLen 0`, критичные NameConstraints: DNS —
  зоны из формы (`home,home.arpa` по умолчанию; `local` запрещена), IP — частные диапазоны,
  email/URI — `invalid`. Украденным ключом нельзя выпустить сертификат на публичное имя или адрес.
  **Зоны нельзя изменить после создания.**
- **Листы:** по CSR потребителя (его ключ к CA не попадает), SAN — ровно запрошенные имена, срок
  `leaf_days` (90; 30…180), продление — Hestia сама на 2/3 срока. `test_lifetime_min` — тестовый
  срок в минутах (только для проверки продления).
- **Порты:** `tls` (`tls.cert`) — сертификаты сервисам и самой Hestia (HTTPS контроллера);
  `trust` (`ca.issuer`) — корень сервисам и доверие на устройствах (Debian/Ubuntu —
  `/usr/local/share/ca-certificates/hestia-root-<fp16>.crt` + `update-ca-certificates`, Arch/Garuda/
  Manjaro — `trust anchor`). Firefox и Chromium могут использовать своё хранилище.
- **Действия:** «Скачать корневой сертификат»; «Резервная копия ключа CA…» (пароль администратора
  Hestia + пароль файла ≥ 12 символов; файл шифрует сам ca-server: PBKDF2-SHA256 600 000 + AES-256-GCM);
  «Восстановить из резервной копии…» (экземпляр с `init: restore`). Параметры действий Hestia нигде
  не сохраняет.
- **Образ** `hestia.local/hestia-ca/ca-server:<версия>` Hestia собирает из бинарника в пакете и
  загружает `docker import` — без реестра и без интернета на цели. Compose: `read_only`, `cap_drop:
  ALL`, `tmpfs: /tmp`, том `ca-data:/data`, порт API `port` (9443).

**Безопасность.** Компрометация root на цели CA = компрометация CA; NameConstraints ограничивают
ущерб частной сетью. API CA доступен в сети на `port`: без токена — только `health`. Распространения
отзыва (CRL/OCSP) нет: отзыв — запись в журнале CA, выданный сертификат действует до своего срока.

Сборка: `make plugin ID=hestia-ca VERSION=v0.1.0` (плагин + `image-ca-server` из
`plugins/hestia-ca/server`). Разработка: `hestia serve --plugin-dev build/plugins/hestia-ca/plugin`
(образ — `build/plugins/hestia-ca/server` рядом); `HESTIA_CA_TEST_ADDR=127.0.0.1:<порт>` подменяет
адрес API CA только в dev-режиме.
