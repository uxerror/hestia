# 03. Дорожная карта

Порядок ориентировочный; каждый этап — отдельный документ перед началом работ.

1. **Этап 1** — подключение, самоустановка, обзор сети, AdGuard → hestia.home (02-stage-1.md).
2. **Основа (плагины-фундамент)**
   - CA: на базе собственного certbot (MyHomeCA, сроки 90 дн., выдача по токену) →
     HTTPS для самой Hestia;
   - DNS: AdGuard (adopt существующего или установка) — управление rewrite из Hestia;
   - reverse proxy: adopt Nginx Proxy Manager или свой; авто-проксирование новых сервисов.
3. **Агент ПК (Linux)** — доверие к CA, mount шар (systemd .mount/.automount, креды 600),
   подключение репозиториев. polkit для привилегированных действий.
4. **Samba** — установка с пресетами (большие файлы / мелкие / общая / только чтение /
   бэкапы), adopt существующих (shared .11), аудит настроек, просмотр файлов из панели,
   «подключить к ПК». Донор: hestia-backend/internal/provider/samba.
5. **Gitea + раннеры** — adopt существующей (git.home .12, runner .22), Linux/Android-раннеры,
   Windows-раннер (Windows VM), хранилище артефактов сборок.
6. **Arch-репозиторий** — repo-add + nginx + GPG-подпись; CI кладёт пакеты; агент добавляет
   репозиторий в pacman.conf.
7. **F-Droid** — fdroidserver по каталогу APK из CI, nginx; бэкап ключа подписи; adopt .24.
8. **Scoop** — bucket как git-репозиторий в Gitea, файлы через nginx; агент для Windows.
8a. **Роутер MikroTik** — adopt (RouterOS API/SSH): DHCP-резервации (в т.ч. для контроллера
   Hestia), DNS, просмотр leases; Hestia как полноценный настройщик HomeLAN.
9. **Аудит-правила** из ручного аудита: мёртвые гости, бэкапы не тех гостей, одинаковые
   machine-id/host keys у клонов, ключи 644, сертификаты на 10 лет, заполненные диски.
10. Iris, S3 (RustFS), SSO (LLDAP + Authelia/Authentik), мониторинг — по мере надобности.
