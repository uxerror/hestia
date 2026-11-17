package update

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The upgrade script runs in a temporary root (HESTIA_ROOT) with fake
// systemctl and hestia programs; nothing on this machine is touched.

const fakeSystemctl = `#!/bin/sh
echo "$*" >> "$HESTIA_ROOT/systemctl.log"
if [ "$1" = start ] && grep -q NEWBINARY "$HESTIA_ROOT/usr/local/bin/hestia"; then
	# the new version migrates the database
	echo migrated > "$HESTIA_ROOT/var/lib/hestia/hestia.db"
	echo wal > "$HESTIA_ROOT/var/lib/hestia/hestia.db-wal"
	echo shm > "$HESTIA_ROOT/var/lib/hestia/hestia.db-shm"
fi
exit 0
`

const fakeNew = `#!/bin/sh
# NEWBINARY
case "$1" in
version) echo "hestia v0.2.0" ;;
healthcheck)
	echo "$*" >> "$HESTIA_ROOT/healthcheck.log"
	[ -f "$HESTIA_ROOT/healthy" ] ;;
esac
`

const fakeOld = `#!/bin/sh
# OLDBINARY
[ "$1" = version ] && echo "hestia v0.1.0"
exit 0
`

type upgradeEnv struct {
	t    *testing.T
	root string
	data string
	bin  string
}

func newUpgradeEnv(t *testing.T) *upgradeEnv {
	t.Helper()
	root := t.TempDir()
	u := &upgradeEnv{t: t, root: root, data: filepath.Join(root, "var/lib/hestia"), bin: filepath.Join(root, "usr/local/bin/hestia")}
	for _, d := range []string{filepath.Dir(u.bin), u.data, filepath.Join(root, "fakebin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	u.write(filepath.Join(root, "fakebin/systemctl"), fakeSystemctl, 0o755)
	u.write(u.bin, fakeOld, 0o755)
	u.write(u.bin+".new", fakeNew, 0o755)
	u.write(filepath.Join(u.data, "hestia.db"), "original", 0o600)
	u.write(filepath.Join(u.data, "hestia.db-wal"), "original-wal", 0o600)
	u.write(filepath.Join(u.data, StateFile), `{"job_id":"j1","from":"v0.1.0","to":"v0.2.0","started_at":"2026-11-18T10:00:00Z"}`+"\n", 0o600)
	return u
}

func (u *upgradeEnv) write(path, content string, mode os.FileMode) {
	u.t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		u.t.Fatal(err)
	}
}

func (u *upgradeEnv) read(rel string) string {
	b, _ := os.ReadFile(filepath.Join(u.root, rel))
	return string(b)
}

func (u *upgradeEnv) run() (string, error) {
	script := filepath.Join(u.root, "upgrade.sh")
	u.write(script, string(upgradeScript), 0o755)
	cmd := exec.Command("sh", script, "8081")
	cmd.Env = append(os.Environ(), "HESTIA_ROOT="+u.root, "HESTIA_HEALTH_TIMEOUT=2",
		"PATH="+filepath.Join(u.root, "fakebin")+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (u *upgradeEnv) backups() []string {
	ents, _ := os.ReadDir(filepath.Join(u.data, "backup"))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestUpgradeScriptSuccess(t *testing.T) {
	u := newUpgradeEnv(t)
	u.write(filepath.Join(u.root, "healthy"), "", 0o644)
	if out, err := u.run(); err != nil {
		t.Fatalf("%v\n%s\nlog:\n%s", err, out, u.read("var/lib/hestia/upgrade.log"))
	}
	if !strings.Contains(u.read("usr/local/bin/hestia"), "NEWBINARY") {
		t.Fatal("binary was not replaced")
	}
	if _, err := os.Stat(u.bin + ".new"); err == nil {
		t.Fatal("hestia.new must be gone")
	}
	if got := u.read("var/lib/hestia/hestia.db"); got != "migrated\n" {
		t.Fatalf("the migrated database must stay: %q", got)
	}
	bk := u.backups()
	if len(bk) != 1 {
		t.Fatalf("backups: %v", bk)
	}
	dir := filepath.Join("var/lib/hestia/backup", bk[0])
	if u.read(dir+"/hestia.db") != "original" || u.read(dir+"/hestia.db-wal") != "original-wal" || !strings.Contains(u.read(dir+"/hestia"), "OLDBINARY") {
		t.Fatal("backup is incomplete")
	}
	if sc := u.read("systemctl.log"); sc != "stop hestia\nstart hestia\n" {
		t.Fatalf("systemctl calls: %q", sc)
	}
	// the health check asks for the new version on the right port
	if hc := u.read("healthcheck.log"); !strings.Contains(hc, "--url http://127.0.0.1:8081") || !strings.Contains(hc, "--version v0.2.0") {
		t.Fatalf("healthcheck: %q", hc)
	}
	// the new controller already closed the job at start; once healthy the
	// script drops update.json so a later crash is not mistaken for this update
	if _, err := os.Stat(filepath.Join(u.data, StateFile)); err == nil {
		t.Fatal("update.json must be removed after a healthy start")
	}
	if !strings.Contains(u.read("var/lib/hestia/upgrade.log"), "новая версия работает: v0.2.0") {
		t.Fatalf("log: %s", u.read("var/lib/hestia/upgrade.log"))
	}
}

func TestUpgradeScriptRollsBackAnUnhealthyVersion(t *testing.T) {
	u := newUpgradeEnv(t) // no "healthy" file: the new binary never becomes healthy
	out, err := u.run()
	if err == nil {
		t.Fatalf("an unhealthy update must fail:\n%s", out)
	}
	if !strings.Contains(u.read("usr/local/bin/hestia"), "OLDBINARY") {
		t.Fatal("the old binary must be restored")
	}
	if _, err := os.Stat(u.bin + ".new"); err == nil {
		t.Fatal("hestia.new must be removed after a rollback")
	}
	if u.read("var/lib/hestia/hestia.db") != "original" || u.read("var/lib/hestia/hestia.db-wal") != "original-wal" {
		t.Fatalf("database not restored: %q %q", u.read("var/lib/hestia/hestia.db"), u.read("var/lib/hestia/hestia.db-wal"))
	}
	if _, err := os.Stat(filepath.Join(u.data, "hestia.db-shm")); err == nil {
		t.Fatal("the new version's -shm must be removed")
	}
	var h handoff
	if err := json.Unmarshal([]byte(u.read("var/lib/hestia/update.json")), &h); err != nil {
		t.Fatalf("update.json is not valid JSON: %v\n%s", err, u.read("var/lib/hestia/update.json"))
	}
	if !h.RolledBack || h.Reason == "" || h.JobID != "j1" || h.To != "v0.2.0" {
		t.Fatalf("update.json: %+v", h)
	}
	// stop, start (new), stop, start (old)
	if sc := u.read("systemctl.log"); sc != "stop hestia\nstart hestia\nstop hestia\nstart hestia\n" {
		t.Fatalf("systemctl calls: %q", sc)
	}
	if !strings.Contains(u.read("var/lib/hestia/upgrade.log"), "возврат выполнен") {
		t.Fatalf("log: %s", u.read("var/lib/hestia/upgrade.log"))
	}
}

func TestUpgradeScriptRefusesABrokenNewBinary(t *testing.T) {
	u := newUpgradeEnv(t)
	u.write(u.bin+".new", "#!/bin/sh\nexit 3\n", 0o755)
	if _, err := u.run(); err == nil {
		t.Fatal("must fail")
	}
	// nothing was stopped or replaced
	if !strings.Contains(u.read("usr/local/bin/hestia"), "OLDBINARY") || u.read("systemctl.log") != "" {
		t.Fatalf("the service must not be touched: %q", u.read("systemctl.log"))
	}
}

func TestUpgradeScriptRotatesBackupsAndLogs(t *testing.T) {
	u := newUpgradeEnv(t)
	u.write(filepath.Join(u.root, "healthy"), "", 0o644)
	for _, ts := range []string{"20200101-000000", "20200102-000000", "20200103-000000", "20200104-000000"} {
		if err := os.MkdirAll(filepath.Join(u.data, "backup", ts), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	u.write(filepath.Join(u.data, "upgrade.log"), "run0", 0o644)
	for i := 1; i <= 5; i++ {
		u.write(filepath.Join(u.data, fmt.Sprintf("upgrade.log.%d", i)), fmt.Sprintf("run%d", i), 0o644)
	}
	if out, err := u.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	bk := u.backups()
	if len(bk) != 3 || bk[0] != "20200103-000000" || bk[1] != "20200104-000000" {
		t.Fatalf("backups (the newest 3 stay): %v", bk)
	}
	if u.read("var/lib/hestia/upgrade.log.1") != "run0" || u.read("var/lib/hestia/upgrade.log.2") != "run1" ||
		u.read("var/lib/hestia/upgrade.log.4") != "run3" {
		t.Fatal("logs were not shifted")
	}
	if _, err := os.Stat(filepath.Join(u.data, "upgrade.log.5")); err == nil {
		t.Fatal("only the last 5 runs are kept")
	}
	if !strings.Contains(u.read("var/lib/hestia/upgrade.log"), "обновление: порт 8081") {
		t.Fatal("current log is missing")
	}
}
