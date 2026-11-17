#!/bin/sh
# Hestia controller upgrade, run as root on the controller's machine, outside
# the hestia service's cgroup (systemd-run). Usage: upgrade.sh <port>
#
# Stops the service, backs up the database and the binary, swaps in
# hestia.new, starts the service and waits for it to become healthy with the
# new version. If it does not, the old binary and database are restored.
#
# HESTIA_ROOT (tests only) is a prefix for every path; HESTIA_HEALTH_TIMEOUT
# is the health wait in seconds.
set -eu

PORT=${1:?usage: upgrade.sh <port>}
ROOT=${HESTIA_ROOT:-}
BIN="$ROOT/usr/local/bin/hestia"
NEW="$BIN.new"
DATA="$ROOT/var/lib/hestia"
LOG="$DATA/upgrade.log"
STATE="$DATA/update.json"
TIMEOUT=${HESTIA_HEALTH_TIMEOUT:-60}
TS=$(date +%Y%m%d-%H%M%S)
BK="$DATA/backup/$TS"

# keep the logs of the last 5 runs: upgrade.log, upgrade.log.1 … .4
i=4
while [ "$i" -ge 1 ]; do
	[ -f "$LOG.$i" ] && mv -f "$LOG.$i" "$LOG.$((i + 1))"
	i=$((i - 1))
done
[ -f "$LOG" ] && mv -f "$LOG" "$LOG.1"
rm -f "$LOG.5"
exec >"$LOG" 2>&1
chmod 644 "$LOG"

say() { echo "$(date +%H:%M:%S) $*"; }

# prune keeps the newest $2 entries of directory $1 (names sort by time)
prune() {
	ls -1 "$1" 2>/dev/null | sort -r | tail -n +"$(($2 + 1))" | while read -r d; do
		rm -rf "${1:?}/$d"
	done
}

# mark_rolled_back rewrites update.json in place (keeping owner and mode)
# so the restarted controller reports the failure.
mark_rolled_back() {
	[ -f "$STATE" ] || return 0
	body=$(sed -e 's/}[[:space:]]*$//' "$STATE")
	printf '%s, "rolled_back": true, "reason": "%s"}\n' "$body" "$1" >"$STATE"
}

rollback() {
	reason=$1
	say "ОШИБКА: $reason — возвращаем прежнюю версию"
	systemctl stop hestia || true
	if [ -f "$BK/hestia" ]; then
		cp -p "$BK/hestia" "$BIN.rollback" && mv -f "$BIN.rollback" "$BIN"
	fi
	rm -f "$DATA/hestia.db" "$DATA/hestia.db-wal" "$DATA/hestia.db-shm"
	for f in "$BK"/hestia.db*; do
		[ -e "$f" ] && cp -p "$f" "$DATA/"
	done
	rm -f "$NEW"
	mark_rolled_back "$reason"
	systemctl start hestia || say "не удалось запустить прежнюю версию"
	say "возврат выполнен"
	exit 1
}

say "обновление: порт $PORT"
out=$("$NEW" version) || { say "hestia.new не запускается"; exit 1; }
want=$(echo "$out" | sed -e 's/^hestia //')
say "ожидаемая версия: $want"

systemctl stop hestia
backup() {
	mkdir -p "$BK" || return 1
	for f in "$DATA"/hestia.db*; do
		if [ -e "$f" ]; then cp -p "$f" "$BK/" || return 1; fi
	done
	cp -p "$BIN" "$BK/hestia"
}
if ! backup; then
	say "ОШИБКА: не удалось сделать резервную копию — обновление отменено"
	rm -rf "$BK" "$NEW"
	mark_rolled_back "не удалось сделать резервную копию"
	systemctl start hestia || say "не удалось запустить прежнюю версию"
	exit 1
fi
say "резервная копия: $BK"
prune "$DATA/backup" 3

mv -f "$NEW" "$BIN" || rollback "не удалось заменить бинарник"
systemctl start hestia || rollback "служба не запустилась"

waited=0
while [ "$waited" -lt "$TIMEOUT" ]; do
	if "$BIN" healthcheck --url "http://127.0.0.1:$PORT" --version "$want"; then
		say "новая версия работает: $want"
		rm -f "$STATE"
		exit 0
	fi
	sleep 1
	waited=$((waited + 1))
done
rollback "новая версия не ответила за $TIMEOUT с"
