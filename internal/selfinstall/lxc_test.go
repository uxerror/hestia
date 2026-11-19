package selfinstall_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
)

func asErr(t *testing.T, err error, status int, sub string) {
	t.Helper()
	var se *selfinstall.Error
	if !errors.As(err, &se) {
		t.Fatalf("want *selfinstall.Error, got %v", err)
	}
	if se.Status != status || !strings.Contains(se.Msg, sub) {
		t.Fatalf("got %d %q, want %d containing %q", se.Status, se.Msg, status, sub)
	}
}

func TestProbeDefaultsLXC(t *testing.T) {
	e := newEnv(t)
	res := e.mustProbe(selfinstall.ProbeRequest{})
	p := res.Params
	if res.Kind != "lxc" || p.Node != "pve1" || p.VMID != 900 || p.Hostname != "hestia" || p.Storage != "local-lvm" ||
		p.TemplateStorage != "local" || p.Bridge != "vmbr0" || p.IP != "dhcp" || p.Cores != 1 || p.MemoryMB != 512 ||
		p.SwapMB != 512 || p.DiskGB != 4 || p.Template != "debian-13-standard_13.6-1_amd64.tar.zst" || !p.TemplatePresent {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	if res.Defaults != p {
		t.Fatalf("defaults differ from params without overrides: %+v vs %+v", res.Defaults, p)
	}
	if got := res.Choices.Bridges; len(got) != 1 || got[0] != "vmbr0" {
		t.Fatalf("bridges: %v", got)
	}
	var names []string
	for _, s := range res.Choices.Storages {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "local-lvm,local" && strings.Join(names, ",") != "local-lvm" {
		t.Fatalf("rootdir storages: %v", names)
	}
	if len(res.Plan) < 8 || res.Plan[0].ID != "template" || res.Plan[len(res.Plan)-1].ID != "switch" {
		t.Fatalf("plan: %+v", res.Plan)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "Make Static") {
		t.Fatalf("expected the DHCP reservation hint: %v", res.Warnings)
	}
	if e.svc.SessionCount() != 1 {
		t.Fatal("probe must open a session")
	}
	// A probe changes nothing: only reads on the API.
	for _, c := range e.pve.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("probe made a write call: %s", c)
		}
	}
	if len(e.node.cts) != 0 {
		t.Fatal("probe created a container")
	}
}

func TestProbeVMIDRange(t *testing.T) {
	e := newEnv(t)
	e.pve.extraVMIDs = []int{900, 901, 902}
	if got := e.mustProbe(selfinstall.ProbeRequest{}).Params.VMID; got != 903 {
		t.Fatalf("VMID = %d, want 903", got)
	}
	_, err := e.probe(selfinstall.ProbeRequest{VMID: 901})
	asErr(t, err, 422, "VMID 901 уже занят")
}

func TestProbeOverridesAndErrors(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		req selfinstall.ProbeRequest
		sub string
	}{
		{selfinstall.ProbeRequest{Bridge: "vmbr9"}, "моста vmbr9 нет"},
		{selfinstall.ProbeRequest{Storage: "pbs01"}, "не поддерживает диски контейнеров"},
		{selfinstall.ProbeRequest{Storage: "local-lvm", DiskGB: 100000}, "диск"},
		{selfinstall.ProbeRequest{Node: "pve9"}, "не в сети"},
		{selfinstall.ProbeRequest{Hostname: "Bad_Name"}, "имя контейнера"},
		{selfinstall.ProbeRequest{IP: "10.10.10.300/24"}, "статический адрес"},
		{selfinstall.ProbeRequest{IP: "192.168.1.5"}, "статический адрес"},
	} {
		_, err := e.probe(tc.req)
		asErr(t, err, 422, tc.sub)
	}
	res := e.mustProbe(selfinstall.ProbeRequest{Hostname: "ctrl", Cores: 2, MemoryMB: 1024, DiskGB: 8, TemplateStorage: "local", Storage: "local-lvm"})
	if p := res.Params; p.Hostname != "ctrl" || p.Cores != 2 || p.MemoryMB != 1024 || p.DiskGB != 8 || p.Storage != "local-lvm" {
		t.Fatalf("overrides lost: %+v", p)
	}
	if _, err := e.svc.Probe(ctxBG(), selfinstall.ProbeRequest{TargetID: 999}); err == nil {
		t.Fatal("unknown target accepted")
	} else {
		asErr(t, err, 404, "цель не найдена")
	}
}

func TestProbeStaticIP(t *testing.T) {
	e := newEnv(t)
	// answers ping → busy
	e.node.pingBusy["192.168.50.20"] = true
	_, err := e.probe(selfinstall.ProbeRequest{IP: "192.168.50.20/24"})
	asErr(t, err, 422, "отвечает на ping")
	// used by a known guest
	snap, _ := json.Marshal(map[string]any{"guests": []map[string]any{{"vmid": 120, "name": "nas", "ips": []string{"192.168.50.21"}}}})
	if err := e.st.PutInventory(ctxBG(), e.tgt.ID, time.Now(), snap); err != nil {
		t.Fatal(err)
	}
	_, err = e.probe(selfinstall.ProbeRequest{IP: "192.168.50.21/24"})
	asErr(t, err, 422, "занят гостем nas")
	// free: the gateway defaults to the bridge's
	res := e.mustProbe(selfinstall.ProbeRequest{IP: "192.168.50.22/24"})
	if res.Params.IP != "192.168.50.22/24" || res.Params.Gateway == "" {
		t.Fatalf("static params: %+v", res.Params)
	}
	if strings.Contains(strings.Join(res.Warnings, " "), "Make Static") {
		t.Fatal("static address must not suggest a DHCP reservation")
	}
	res = e.mustProbe(selfinstall.ProbeRequest{IP: "192.168.50.22/24", Gateway: "192.168.50.1"})
	if res.Params.Gateway != "192.168.50.1" {
		t.Fatalf("explicit gateway lost: %+v", res.Params)
	}
}

func TestProbeNotX86(t *testing.T) {
	e := newEnv(t)
	e.node.arch = "aarch64"
	_, err := e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "только x86_64")
}

func TestProbeNoBinary(t *testing.T) {
	e := newEnv(t)
	e.svc.Binary = func() ([]byte, error) {
		return nil, errors.New("эта сборка не содержит серверного бинарника")
	}
	_, err := e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "не содержит серверного бинарника")
}

func TestProbeNodeWithoutKey(t *testing.T) {
	e := newEnv(t)
	// rebuild the target without a pinned node key
	if err := e.st.DeleteTarget(ctxBG(), e.tgt.ID); err != nil {
		t.Fatal(err)
	}
	ref, err := e.sec.Put(ctxBG(), secrets.PurposeAPIToken, []byte(apiSecret))
	if err != nil {
		t.Fatal(err)
	}
	tg := e.tgt
	tg.ID, tg.TokenSecretRef = 0, ref
	tg.Nodes = []store.Node{{Name: "pve1", IP: "127.0.0.1", Online: true}}
	if err := e.st.CreateTarget(ctxBG(), &tg); err != nil {
		t.Fatal(err)
	}
	e.tgt = tg
	_, err = e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "нет узла в сети")
}

func TestInstallLXC(t *testing.T) {
	e := newEnv(t)
	res := e.mustProbe(selfinstall.ProbeRequest{})
	keyBefore, err := os.ReadFile(filepath.Join(e.dir, secrets.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	out := e.install(res)
	if out.status != store.JobDone {
		t.Fatalf("job %s: %s\nlog: %s", out.status, out.err, strings.Join(out.logs, "\n"))
	}
	r := out.result_()
	if r.URL != "http://"+ctIP || r.IP != ctIP || r.MAC != "BC:24:11:BC:4C:F6" || r.VMID != 900 || r.Node != "pve1" || r.Kind != "lxc" {
		t.Fatalf("result: %+v", r)
	}
	if !strings.HasPrefix(r.HandoffURL, "http://"+ctIP+"/#/handoff/") || !strings.Contains(r.Hint, "Make Static") {
		t.Fatalf("handoff/hint: %+v", r)
	}
	for _, title := range []string{"Шаблон Debian 13", "Создание контейнера", "Запуск контейнера", "Уникальность контейнера",
		"Пользователь и бинарник", "Служба systemd", "Перенос состояния", "Запуск и проверка", "Переключение"} {
		if out.steps[title] != store.StepDone {
			t.Errorf("step %q: %q", title, out.steps[title])
		}
	}

	// The create request.
	if len(e.pve.createForms) != 1 {
		t.Fatalf("create calls: %d", len(e.pve.createForms))
	}
	f := e.pve.createForms[0]
	want := map[string]string{
		"vmid": "900", "hostname": "hestia", "ostemplate": "local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst",
		"rootfs": "local-lvm:4", "cores": "1", "memory": "512", "swap": "512", "unprivileged": "1", "features": "nesting=1",
		"onboot": "1", "start": "0", "tags": "hestia", "description": "Hestia controller",
		"net0": "name=eth0,bridge=vmbr0,ip=dhcp,firewall=0",
	}
	for k, v := range want {
		if f.Get(k) != v {
			t.Errorf("create %s = %q, want %q", k, f.Get(k), v)
		}
	}
	if len(e.pve.downloaded) != 0 {
		t.Fatalf("the template was present, yet downloaded: %v", e.pve.downloaded)
	}

	// Inside the container.
	m := e.node.ct(900)
	id, _ := m.file("/etc/machine-id")
	if s := strings.TrimSpace(string(id)); len(s) != 32 || s == e.node.nodeID {
		t.Fatalf("machine-id not regenerated: %q", s)
	}
	if _, ok := m.file("/etc/ssh/ssh_host_ed25519_key.pub"); !ok {
		t.Fatal("host keys not generated")
	}
	if !m.users["hestia"] || !m.dirs["/var/lib/hestia"] {
		t.Fatal("user or data dir missing")
	}
	bin, _ := m.file("/usr/local/bin/hestia")
	if string(bin) != string(fakeBinary) || m.modes["/usr/local/bin/hestia"] != "0755" || m.owners["/usr/local/bin/hestia"] != "root:root" {
		t.Fatalf("binary: mode %q owner %q", m.modes["/usr/local/bin/hestia"], m.owners["/usr/local/bin/hestia"])
	}
	unit, _ := m.file("/etc/systemd/system/hestia.service")
	for _, s := range []string{"ExecStart=/usr/local/bin/hestia serve --listen :80 --data /var/lib/hestia", "User=hestia",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE", "ProtectSystem=strict", "Restart=on-failure", "WantedBy=multi-user.target"} {
		if !strings.Contains(string(unit), s) {
			t.Errorf("unit lacks %q", s)
		}
	}
	if !m.enabled || !m.started {
		t.Fatal("service not enabled/started")
	}
	// State: the database copy and the master key, 0600 hestia:hestia.
	for _, p := range []string{"/var/lib/hestia/hestia.db", "/var/lib/hestia/master.key"} {
		if m.modes[p] != "0600" || m.owners[p] != "hestia:hestia" {
			t.Errorf("%s: mode %q owner %q", p, m.modes[p], m.owners[p])
		}
	}
	key, _ := m.file("/var/lib/hestia/master.key")
	if string(key) != string(keyBefore) {
		t.Fatal("master key on the target differs from the local one")
	}
	if e.ctrl == nil || e.duringXfer[0] != true {
		t.Fatalf("the controller must start while the transfer mode is on: %v", e.duringXfer)
	}

	// The shipped database is a valid copy: the job is done, the location is
	// recorded, the handoff token works exactly once.
	dir := t.TempDir()
	db, _ := m.file("/var/lib/hestia/hestia.db")
	if err := os.WriteFile(filepath.Join(dir, "hestia.db"), db, 0o600); err != nil {
		t.Fatal(err)
	}
	cp, err := store.OpenCopy(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	jobs, err := cp.ListJobs(ctxBG(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, j := range jobs {
		if j.Kind == selfinstall.JobKind {
			found = true
			full, _ := cp.GetJob(ctxBG(), j.ID)
			if full.Status != store.JobDone || full.Steps[len(full.Steps)-1].Title != "Состояние перенесено" {
				t.Fatalf("installation job in the copy: %s %+v", full.Status, full.Steps)
			}
			for _, st := range full.Steps {
				if st.Status != store.StepDone {
					t.Fatalf("step %q left %s in the copy", st.Title, st.Status)
				}
			}
		}
	}
	if !found {
		t.Fatal("installation job missing in the copy")
	}
	loc, err := cp.GetSetting(ctxBG(), store.SettingControllerLocation)
	if err != nil || !strings.Contains(loc, `"kind":"lxc"`) || !strings.Contains(loc, `"vmid":900`) || strings.Contains(loc, "http") {
		t.Fatalf("controller_location %q (%v)", loc, err)
	}
	token := r.HandoffURL[strings.LastIndex(r.HandoffURL, "/")+1:]
	au := auth.New(cp)
	if _, err := au.Handoff(ctxBG(), token); err != nil {
		t.Fatalf("handoff token rejected: %v", err)
	}
	if _, err := au.Handoff(ctxBG(), token); !errors.Is(err, auth.ErrBadHandoff) {
		t.Fatalf("handoff token must work once, got %v", err)
	}

	// The switch: remote.json, archive, the local database is gone.
	rem, err := selfinstall.ReadRemote(e.dir)
	if err != nil || rem == nil || rem.URL != r.URL || rem.Kind != "lxc" || rem.VMID != 900 || rem.IP != ctIP ||
		rem.MAC != "BC:24:11:BC:4C:F6" || rem.InstanceID == "" || rem.InstanceID != e.ctrl.id {
		t.Fatalf("remote.json: %+v (%v)", rem, err)
	}
	if e.gate.Moved() == nil || e.gate.Transferring() {
		t.Fatal("gate must be moved and not transferring")
	}
	for _, n := range []string{"hestia.db", "hestia.db-wal", "hestia.db-shm", secrets.KeyFile} {
		if _, err := os.Stat(filepath.Join(e.dir, n)); !os.IsNotExist(err) {
			t.Errorf("%s still in the data directory", n)
		}
	}
	arch, _ := filepath.Glob(filepath.Join(e.dir, "archive", "*"))
	if len(arch) != 1 {
		t.Fatalf("archive: %v", arch)
	}
	if st, err := os.Stat(arch[0]); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("archive dir: %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Join(arch[0], secrets.KeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("archived key: %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(arch[0], "hestia.db")); err != nil {
		t.Fatal("archived database missing")
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, "transfer-*")); len(left) != 0 {
		t.Fatalf("temporary snapshot left behind: %v", left)
	}
	e.noSecrets(out.logs, token)
}

func TestInstallLXCDownloadsTemplate(t *testing.T) {
	e := newEnv(t)
	e.pve.tplPresent = false
	res := e.mustProbe(selfinstall.ProbeRequest{})
	if res.Params.TemplatePresent || !strings.Contains(res.Plan[0].Title, "Скачать шаблон") {
		t.Fatalf("plan must offer the download: %+v %+v", res.Params, res.Plan[0])
	}
	out := e.install(res)
	if out.status != store.JobDone {
		t.Fatalf("%s: %s", out.status, out.err)
	}
	if len(e.pve.downloaded) != 1 || e.pve.downloaded[0] != "local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst" {
		t.Fatalf("downloaded: %v", e.pve.downloaded)
	}
	if len(e.pve.deleted) != 0 {
		t.Fatalf("a successful install must keep the template: %v", e.pve.deleted)
	}
	if !strings.Contains(strings.Join(out.logs, "\n"), "proxmox: TASK OK") {
		t.Fatal("the Proxmox task log is not relayed")
	}
}

func assertLocalIntact(t *testing.T, e *env) {
	t.Helper()
	if e.gate.Transferring() || e.gate.Moved() != nil {
		t.Fatal("transfer mode must be off after a failed install")
	}
	if _, err := os.Stat(filepath.Join(e.dir, selfinstall.RemoteFile)); !os.IsNotExist(err) {
		t.Fatal("remote.json written by a failed install")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "archive")); !os.IsNotExist(err) {
		t.Fatal("archive created by a failed install")
	}
	if _, err := os.Stat(filepath.Join(e.dir, secrets.KeyFile)); err != nil {
		t.Fatal("master key gone")
	}
	if n, err := e.st.CountUsers(ctxBG()); err != nil || n != 1 {
		t.Fatalf("local database damaged: %d %v", n, err)
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, "transfer-*")); len(left) != 0 {
		t.Fatalf("temporary snapshot left behind: %v", left)
	}
	st, err := e.svc.State(ctxBG())
	if err != nil || st.State != "local" {
		t.Fatalf("state: %+v %v", st, err)
	}
}

func TestInstallStartFailureRollsBack(t *testing.T) {
	e := newEnv(t)
	e.pve.tplPresent = false // downloaded by this run → removed again
	e.pve.failStart = true
	res := e.mustProbe(selfinstall.ProbeRequest{})
	out := e.install(res)
	if out.status != store.JobFailed || !strings.Contains(out.err, "startup for container failed") || !strings.Contains(out.err, "Созданное этой установкой удалено") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	if len(e.pve.destroyed) != 1 || e.pve.destroyed[0] != 900 {
		t.Fatalf("container not destroyed: %v", e.pve.destroyed)
	}
	if q := e.pve.purgeQuery[0]; !strings.Contains(q, "purge=1") || !strings.Contains(q, "destroy-unreferenced-disks=1") {
		t.Fatalf("delete query: %q", q)
	}
	if len(e.pve.deleted) != 1 || !strings.HasSuffix(e.pve.deleted[0], "vztmpl/debian-13-standard_13.6-1_amd64.tar.zst") {
		t.Fatalf("downloaded template not removed: %v", e.pve.deleted)
	}
	assertLocalIntact(t, e)
	e.noSecrets(out.logs)
	if e.svc.SessionCount() != 1 {
		t.Fatal("a failed install must leave the probe confirmable again")
	}
}

func TestRollbackKeepsPreexistingTemplate(t *testing.T) {
	e := newEnv(t)
	e.pve.failStart = true
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed {
		t.Fatal(out.status)
	}
	if len(e.pve.deleted) != 0 {
		t.Fatalf("a template that was already there must stay: %v", e.pve.deleted)
	}
	if len(e.pve.destroyed) != 1 {
		t.Fatalf("destroyed: %v", e.pve.destroyed)
	}
}

func TestHealthNotAnswering(t *testing.T) {
	e := newEnv(t)
	e.noController = true
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed || !strings.Contains(out.err, "http://"+ctIP) || !strings.Contains(out.err, "не отвечает") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	if len(e.duringXfer) != 1 || !e.duringXfer[0] {
		t.Fatalf("transfer mode must be on while starting: %v", e.duringXfer)
	}
	if len(e.pve.destroyed) != 1 {
		t.Fatalf("container not rolled back: %v", e.pve.destroyed)
	}
	assertLocalIntact(t, e)
	// the state copy was shipped before the check; the local database is still the live one
	if _, err := e.st.GetSetting(ctxBG(), store.SettingControllerLocation); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("controller_location must only exist in the copy")
	}
}

func TestInstanceIDMismatch(t *testing.T) {
	e := newEnv(t)
	e.forceID = "ffffffffffffffffffffffffffffffff"
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed || !strings.Contains(out.err, "другим идентификатором") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	if len(e.pve.destroyed) != 1 {
		t.Fatal("not rolled back")
	}
	assertLocalIntact(t, e)
}

func TestNoAddressRollsBackRunningContainer(t *testing.T) {
	e := newEnv(t)
	e.pve.noIP = true
	e.svc.IPTimeout = 80 * time.Millisecond
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed || !strings.Contains(out.err, "не получил IPv4-адрес") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	if e.pve.called("POST /api2/json/nodes/pve1/lxc/900/status/stop") != 1 || len(e.pve.destroyed) != 1 {
		t.Fatalf("a running container must be stopped, then destroyed: %v", e.pve.calls)
	}
	assertLocalIntact(t, e)
}

func TestVersionMismatchFails(t *testing.T) {
	e := newEnv(t)
	e.svc.Version = "other"
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobFailed || !strings.Contains(out.err, "не совпала с версией контроллера") {
		t.Fatalf("%s: %q", out.status, out.err)
	}
	assertLocalIntact(t, e)
}

func TestIdentityKept(t *testing.T) {
	// machine-id already unique, host keys present: nothing is regenerated
	e := newEnv(t)
	e.node.newCT = func(int) *fakeMachine {
		m := e.newCT()
		m.files["/etc/machine-id"] = []byte(randHex(16) + "\n")
		m.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte("ssh-ed25519 AAAAx root@ct\n")
		return m
	}
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobDone {
		t.Fatalf("%s: %s", out.status, out.err)
	}
	m := e.node.ct(900)
	if m.executed("systemd-machine-id-setup") != 0 || m.executed("ssh-keygen -A") != 0 {
		t.Fatal("unique identity must not be regenerated")
	}
	if !strings.Contains(strings.Join(out.logs, "\n"), "SHA256:fakeFingerprint") {
		t.Fatal("host key fingerprint not logged")
	}
}

func TestIdentityDuplicateOfNode(t *testing.T) {
	e := newEnv(t)
	e.node.newCT = func(int) *fakeMachine {
		m := e.newCT()
		m.files["/etc/machine-id"] = []byte(e.node.nodeID + "\n") // cloned from the node
		return m
	}
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobDone {
		t.Fatalf("%s: %s", out.status, out.err)
	}
	id, _ := e.node.ct(900).file("/etc/machine-id")
	if strings.TrimSpace(string(id)) == e.node.nodeID {
		t.Fatal("duplicate machine-id kept")
	}
}

func TestAlreadyInstalledConflict(t *testing.T) {
	e := newEnv(t)
	res := e.mustProbe(selfinstall.ProbeRequest{})
	loc, _ := json.Marshal(selfinstall.Location{Kind: "lxc", TargetID: e.tgt.ID, IP: ctIP})
	if err := e.st.SetSetting(ctxBG(), store.SettingControllerLocation, string(loc)); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.State(ctxBG())
	if err != nil || st.State != "installed" || st.Location == nil || st.Location.IP != ctIP {
		t.Fatalf("state: %+v %v", st, err)
	}
	_, err = e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, http.StatusConflict, "уже перенесена")
	_, err = e.svc.Start(ctxBG(), res.ProbeID, e.userID)
	asErr(t, err, http.StatusConflict, "уже перенесена")
}

func TestStartErrors(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.Start(ctxBG(), "nope", e.userID)
	asErr(t, err, http.StatusGone, "истекла")
	res := e.mustProbe(selfinstall.ProbeRequest{})
	// expired session
	e.svc.Now = func() time.Time { return time.Now().Add(selfinstall.SessionTTL + time.Minute) }
	_, err = e.svc.Start(ctxBG(), res.ProbeID, e.userID)
	asErr(t, err, http.StatusGone, "истекла")
}

func TestSecondInstallWhileRunning(t *testing.T) {
	e := newEnv(t)
	e.pve.runsPerTask = 30 // keeps the first job busy
	a := e.mustProbe(selfinstall.ProbeRequest{})
	b := e.mustProbe(selfinstall.ProbeRequest{VMID: 950})
	job, err := e.svc.Start(ctxBG(), a.ProbeID, e.userID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Start(ctxBG(), a.ProbeID, e.userID)
	asErr(t, err, http.StatusConflict, "уже выполняется")
	_, err = e.svc.Start(ctxBG(), b.ProbeID, e.userID)
	asErr(t, err, http.StatusConflict, "установка уже идёт")
	e.runner.Shutdown()
	_ = job
}

func TestStateCopyHashOfBinary(t *testing.T) {
	// the uploaded binary is verified through sha256sum inside the target
	e := newEnv(t)
	out := e.install(e.mustProbe(selfinstall.ProbeRequest{}))
	if out.status != store.JobDone {
		t.Fatal(out.err)
	}
	sum := sha256.Sum256(fakeBinary)
	if !strings.Contains(strings.Join(out.logs, "\n"), hex.EncodeToString(sum[:])[:12]) {
		t.Fatal("binary checksum not logged")
	}
}
