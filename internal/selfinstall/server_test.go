package selfinstall_test

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"hestia/internal/selfinstall"
	"hestia/internal/sshx/sshxtest"
	"hestia/internal/store"
)

// newServerEnv connects a standalone server (kind ssh) backed by a fake
// machine; uid 0 = root, otherwise a sudo user.
func newServerEnv(t *testing.T, uid int, sudo bool) (*env, *fakeMachine) {
	t.Helper()
	e := newEnv(t)
	m := newMachine(t, testVersion)
	m.startHook = e.startController(m)
	e.node.server, e.node.uid, e.node.hasSudo = m, uid, sudo
	srv := sshxtest.New(t)
	user := "root"
	if uid != 0 {
		user = "deploy"
	}
	srv.KeyAuth = func(u string, k ssh.PublicKey) bool {
		return u == user && ssh.FingerprintSHA256(k) == ssh.FingerprintSHA256(e.svc.Identity.Signer.PublicKey())
	}
	srv.Handler = e.node.handle
	tg := store.Target{Kind: store.KindSSH, Name: "nas", Host: "127.0.0.1", Port: srv.Port, SSHUser: user, HostKeyFP: srv.HostKeyFP()}
	if err := e.st.CreateTarget(ctxBG(), &tg); err != nil {
		t.Fatal(err)
	}
	e.tgt = tg
	return e, m
}

func TestServerInstallRoot(t *testing.T) {
	e, m := newServerEnv(t, 0, true)
	res := e.mustProbe(selfinstall.ProbeRequest{})
	if res.Kind != "ssh" || res.Params.Port != 80 || res.Defaults.Port != 80 || res.Plan[0].ID != "binary" {
		t.Fatalf("probe: %+v", res)
	}
	out := e.install(res)
	if out.status != store.JobDone {
		t.Fatalf("%s: %s\n%s", out.status, out.err, strings.Join(out.logs, "\n"))
	}
	r := out.result_()
	if r.URL != "http://127.0.0.1" || r.Kind != "ssh" || r.MAC != "" || !strings.HasPrefix(r.HandoffURL, "http://127.0.0.1/#/handoff/") {
		t.Fatalf("result: %+v", r)
	}
	unit, _ := m.file("/etc/systemd/system/hestia.service")
	if !strings.Contains(string(unit), "--listen :80 ") || !m.enabled || !m.started {
		t.Fatalf("unit/service: %q %v %v", unit, m.enabled, m.started)
	}
	rem, err := selfinstall.ReadRemote(e.dir)
	if err != nil || rem == nil || rem.Kind != "ssh" || rem.Host != "127.0.0.1" || rem.VMID != 0 {
		t.Fatalf("remote.json: %+v %v", rem, err)
	}
	if out.steps["Подключение по SSH"] != store.StepDone || out.steps["Переключение"] != store.StepDone {
		t.Fatalf("steps: %v", out.steps)
	}
}

func TestServerInstallSudoUser(t *testing.T) {
	// every command must go through sudo -n: the fake refuses plain `sh -c` for non-root
	e, m := newServerEnv(t, 1000, true)
	res := e.mustProbe(selfinstall.ProbeRequest{})
	if !strings.Contains(strings.Join(res.Warnings, " "), "sudo") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	out := e.install(res)
	if out.status != store.JobDone {
		t.Fatalf("%s: %s", out.status, out.err)
	}
	if _, ok := m.file("/usr/local/bin/hestia"); !ok {
		t.Fatal("binary missing")
	}
}

func TestServerNeedsRootOrSudo(t *testing.T) {
	e, _ := newServerEnv(t, 1000, false)
	_, err := e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "нужен root или sudo без пароля")
}

func TestServerPort80Busy(t *testing.T) {
	e, m := newServerEnv(t, 0, true)
	m.port80 = true
	res := e.mustProbe(selfinstall.ProbeRequest{})
	if res.Defaults.Port != 8080 || res.Params.Port != 8080 {
		t.Fatalf("ports: %+v / %+v", res.Params, res.Defaults)
	}
	_, err := e.probe(selfinstall.ProbeRequest{Port: 80})
	asErr(t, err, 422, "порт 80 на сервере занят")
	m.busy[9000] = true
	_, err = e.probe(selfinstall.ProbeRequest{Port: 9000})
	asErr(t, err, 422, "порт 9000 на сервере занят")
	out := e.install(res)
	if out.status != store.JobDone {
		t.Fatalf("%s: %s", out.status, out.err)
	}
	if r := out.result_(); r.URL != "http://127.0.0.1:8080" {
		t.Fatalf("url: %s", r.URL)
	}
	unit, _ := m.file("/etc/systemd/system/hestia.service")
	if !strings.Contains(string(unit), "--listen :8080 ") {
		t.Fatalf("unit: %s", unit)
	}
}

func TestServerAlreadyInstalled(t *testing.T) {
	for _, p := range []string{"/usr/local/bin/hestia", "/etc/systemd/system/hestia.service"} {
		e, m := newServerEnv(t, 0, true)
		m.files[p] = []byte("x")
		_, err := e.probe(selfinstall.ProbeRequest{})
		asErr(t, err, 422, "уже установлена")
	}
	e, m := newServerEnv(t, 0, true)
	m.dirs["/var/lib/hestia"] = true
	_, err := e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "уже установлена")
}

func TestServerNotX86(t *testing.T) {
	e, _ := newServerEnv(t, 0, true)
	e.node.arch = "aarch64"
	_, err := e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "только x86_64")
}

func TestServerRollbackRemovesOnlyOwnChanges(t *testing.T) {
	e, m := newServerEnv(t, 0, true)
	m.users["hestia"] = true // the user pre-exists: it must survive the rollback
	m.files["/home/keep.txt"] = []byte("keep")
	m.failCmd = "systemctl enable"
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed || !strings.Contains(out.err, "systemctl enable") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	for _, p := range []string{"/usr/local/bin/hestia", "/etc/systemd/system/hestia.service", "/var/lib/hestia/hestia.db"} {
		if _, ok := m.file(p); ok {
			t.Errorf("%s survived the rollback", p)
		}
	}
	if m.dirs["/var/lib/hestia"] {
		t.Error("data dir survived the rollback")
	}
	if !m.users["hestia"] {
		t.Error("a user that existed before was deleted")
	}
	if _, ok := m.file("/home/keep.txt"); !ok {
		t.Error("unrelated file removed")
	}
	assertLocalIntact(t, e)
}

func TestServerRollbackRemovesCreatedUser(t *testing.T) {
	e, m := newServerEnv(t, 0, true)
	m.failCmd = "systemctl enable"
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed {
		t.Fatal(out.status)
	}
	if m.users["hestia"] {
		t.Fatal("the user created by this run must be removed")
	}
}

func TestServerHealthFailureRollsBack(t *testing.T) {
	e, m := newServerEnv(t, 0, true)
	e.noController = true
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed || !strings.Contains(out.err, "http://127.0.0.1") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	if m.started || m.enabled {
		t.Fatal("service left running/enabled")
	}
	if _, ok := m.file("/usr/local/bin/hestia"); ok {
		t.Fatal("binary left behind")
	}
	assertLocalIntact(t, e)
}
