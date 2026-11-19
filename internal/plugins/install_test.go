package plugins

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallNewPlugin(t *testing.T) {
	h := newHarness(t)
	key := newKey(t)
	ctx := context.Background()

	up := h.upload(pkgFor(t, key, "v0.1.0"))
	if up.Preview.Author.Trust != TrustNew || up.Preview.Update != nil || up.Preview.ID != "demo" ||
		up.Preview.Author.Fingerprint != Fingerprint(pubOf(key)) {
		t.Fatalf("preview %+v", up.Preview)
	}
	// A new author must be trusted explicitly.
	_, err := h.m.Install(ctx, InstallRequest{UploadID: up.UploadID})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 400 {
		t.Fatalf("err %v", err)
	}
	job, err := h.m.Install(ctx, InstallRequest{UploadID: up.UploadID, TrustAuthor: true})
	if err != nil {
		t.Fatal(err)
	}
	j := h.wait(job.ID)
	if j.Status != store.JobDone {
		t.Fatalf("job %s: %s\n%s", j.Status, j.Error, jobLog(j))
	}

	// Files on the "machine".
	vdir := h.path(pluginsDir + "/demo/v0.1.0")
	if st, err := os.Stat(vdir + "/plugin"); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("plugin binary: %v %v", st, err)
	}
	tokPath := h.path(pluginsDir + "/demo/token")
	st, err := os.Stat(tokPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token: %v %v", st, err)
	}
	tok := readFile(t, tokPath)
	if cur, _ := os.Readlink(h.path(pluginsDir + "/demo/current")); cur != "v0.1.0" {
		t.Fatalf("current -> %q", cur)
	}
	if !bytes.Equal([]byte(readFile(t, h.path(unitPath))), unitTemplate) || readFile(t, h.path(tmpfilesPath)) != string(tmpfilesConf) {
		t.Fatal("unit template or tmpfiles not installed")
	}
	// No net.outbound → the network drop-in.
	if readFile(t, h.path(dropinDir("demo")+"/10-hestia.conf")) != string(noNetworkConf) {
		t.Fatal("no-network drop-in missing")
	}
	log := h.systemctlLog()
	if !strings.Contains(log, "daemon-reload") || !strings.Contains(log, "enable --now hestia-plugin@demo.service") {
		t.Fatalf("systemctl: %s", log)
	}

	// Database: hashed token, pinned author, never the token itself.
	p, err := h.st.GetPlugin(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenHash != HashToken(tok) || p.Source != store.PluginSourceFile || !p.Enabled || p.Version != "v0.1.0" || p.Readme == "" || p.Icon == "" {
		t.Fatalf("%+v", p)
	}
	if strings.Contains(jobLog(j), tok) {
		t.Fatal("token leaked into the job log")
	}
	if _, err := h.st.GetAuthor(ctx, pubOf(key)); err != nil {
		t.Fatal("author not pinned")
	}
	if !h.m.Listening() {
		t.Fatal("socket not opened")
	}
	if fi, err := os.Stat(h.m.SocketPath); err != nil || fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v %v", fi, err)
	}
	l, err := h.m.List(ctx)
	if err != nil || len(l.Plugins) != 1 || l.Plugins[0].State != StateConnected || !l.Available {
		t.Fatalf("%+v %v", l, err)
	}
	// The uploaded file is gone.
	if ents, _ := os.ReadDir(h.m.uploadDir()); len(ents) != 0 {
		t.Fatalf("uploads left: %v", ents)
	}
}

func TestUpdateKeepsOnePrevious(t *testing.T) {
	h := newHarness(t)
	key := newKey(t)
	ctx := context.Background()
	if j := h.install(pkgFor(t, key, "v0.1.0")); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	up := h.upload(pkgFor(t, key, "v0.2.0", sdk.PermTargetsRead, sdk.PermTargetsExec, sdk.PermNetOutbound))
	if up.Preview.Author.Trust != TrustPinned || up.Preview.Update == nil || up.Preview.Update.From != "v0.1.0" ||
		len(up.Preview.Update.NewPermissions) != 1 || up.Preview.Update.NewPermissions[0] != sdk.PermNetOutbound {
		t.Fatalf("%+v", up.Preview)
	}
	job, err := h.m.Install(ctx, InstallRequest{UploadID: up.UploadID})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if cur, _ := os.Readlink(h.path(pluginsDir + "/demo/current")); cur != "v0.2.0" {
		t.Fatalf("current -> %q", cur)
	}
	if _, err := os.Stat(h.path(dropinDir("demo"))); !os.IsNotExist(err) {
		t.Fatal("net.outbound: the drop-in must be removed")
	}
	if !strings.Contains(h.systemctlLog(), "restart hestia-plugin@demo.service") {
		t.Fatal("update must restart the unit")
	}
	p, _ := h.st.GetPlugin(ctx, "demo")
	if p.Version != "v0.2.0" || p.PrevVersion != "v0.1.0" || p.TokenHash != HashToken(readFile(t, h.path(pluginsDir+"/demo/token"))) {
		t.Fatalf("%+v", p)
	}
	if _, err := os.Stat(h.path(pluginsDir + "/demo/token.prev")); !os.IsNotExist(err) {
		t.Fatal("token.prev left")
	}
	h.waitConnected("demo")
	if j := h.install(pkgFor(t, key, "v0.3.0")); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	ents, _ := os.ReadDir(h.path(pluginsDir + "/demo"))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	got := strings.Join(names, ",")
	if got != "current,token,v0.2.0,v0.3.0" {
		t.Fatalf("plugin dir: %s", got)
	}
}

func TestUploadRefusals(t *testing.T) {
	h := newHarness(t)
	key, other := newKey(t), newKey(t)
	if j := h.install(pkgFor(t, key, "v0.2.0")); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	ctx := context.Background()
	cases := []struct {
		pkg  []byte
		code int
		want string
	}{
		{pkgFor(t, key, "v0.1.0"), 409, "понижение версии"},
		{pkgFor(t, key, "v0.2.0"), 409, "уже установлена"},
		{pkgFor(t, other, "v0.3.0"), 409, "Ключ автора изменился"},
		{[]byte("garbage"), 422, "tar.gz"},
	}
	for _, c := range cases {
		_, err := h.m.Upload(ctx, bytes.NewReader(c.pkg))
		var pe *Error
		if !errors.As(err, &pe) || pe.Status != c.code || !strings.Contains(pe.Msg, c.want) {
			t.Errorf("want %d %q, got %v", c.code, c.want, err)
		}
	}
	// Without a controller location: plugins are unavailable.
	h.m.Location = func(context.Context) (*selfinstall.Location, error) { return nil, nil }
	_, err := h.m.Upload(ctx, bytes.NewReader(pkgFor(t, key, "v0.3.0")))
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 409 || pe.Msg != msgNoLocation {
		t.Fatalf("%v", err)
	}
	h.m.Mode = "desktop"
	if ok, reason := h.m.Availability(ctx); ok || reason != msgDesktop {
		t.Fatal(reason)
	}
}

// failure points of an install (steps 2–4); update adds step 5.
var failurePoints = []struct {
	name  string
	setup func(h *harness)
}{
	{"binary upload", func(h *harness) { h.failOn("put " + h.root + pluginsDir + "/demo/v0.2.0/plugin") }},
	{"tmpfiles", func(h *harness) { h.failOn("systemd-tmpfiles --create") }},
	{"daemon-reload", func(h *harness) { h.failOn("systemctl daemon-reload") }},
	{"start", func(h *harness) {
		h.failOn("systemctl enable --now hestia-plugin@demo.service")
		h.failOn("systemctl restart hestia-plugin@demo.service")
	}},
	{"no hello", func(h *harness) { h.mu.Lock(); h.noStart = true; h.mu.Unlock() }},
	{"manifest mismatch", func(h *harness) {
		h.manifest = func(id string, m []byte) []byte {
			if strings.Contains(string(m), "v0.2.0") {
				return bytes.Replace(m, []byte(`"Demo"`), []byte(`"Другое"`), 1)
			}
			return m
		}
	}},
}

func TestInstallRollbackNew(t *testing.T) {
	key := newKey(t)
	for _, fp := range failurePoints {
		t.Run(fp.name, func(t *testing.T) {
			h := newHarness(t)
			fp.setup(h)
			j := h.install(pkgFor(t, key, "v0.2.0"))
			if j.Status != store.JobFailed {
				t.Fatalf("job %s\n%s", j.Status, jobLog(j))
			}
			if _, err := h.st.GetPlugin(context.Background(), "demo"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("plugin recorded despite the failure")
			}
			if _, err := os.Stat(h.path(pluginsDir + "/demo")); !os.IsNotExist(err) {
				t.Fatalf("plugin files left: %v", err)
			}
			if _, err := os.Stat(h.path(dropinDir("demo"))); !os.IsNotExist(err) {
				t.Fatal("drop-in left")
			}
			if h.m.conn("demo") != nil {
				t.Fatal("connection left")
			}
		})
	}
}

func TestInstallRollbackUpdate(t *testing.T) {
	key := newKey(t)
	points := append(failurePoints[:len(failurePoints):len(failurePoints)], struct {
		name  string
		setup func(h *harness)
	}{"instance status", func(h *harness) {
		h.plug = func(string) sdk.Plugin { return &testPlugin{statusErr: errors.New("broken")} }
	}})
	for _, fp := range points {
		t.Run(fp.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			if j := h.install(pkgFor(t, key, "v0.1.0")); j.Status != store.JobDone {
				t.Fatal(jobLog(j))
			}
			h.waitConnected("demo")
			before, _ := h.st.GetPlugin(ctx, "demo")
			oldTok := readFile(t, h.path(pluginsDir+"/demo/token"))
			inst := &store.PluginInstance{PluginID: "demo", Name: "a", Config: `{}`}
			if err := h.st.CreateInstance(ctx, inst, nil); err != nil {
				t.Fatal(err)
			}
			fp.setup(h)
			j := h.install(pkgFor(t, key, "v0.2.0"))
			if j.Status != store.JobFailed {
				t.Fatalf("job %s\n%s", j.Status, jobLog(j))
			}
			after, _ := h.st.GetPlugin(ctx, "demo")
			if after.Version != "v0.1.0" || after.TokenHash != before.TokenHash {
				t.Fatalf("database changed: %+v", after)
			}
			if cur, _ := os.Readlink(h.path(pluginsDir + "/demo/current")); cur != "v0.1.0" {
				t.Fatalf("current -> %q", cur)
			}
			if readFile(t, h.path(pluginsDir+"/demo/token")) != oldTok {
				t.Fatal("old token not restored")
			}
			if _, err := os.Stat(h.path(pluginsDir + "/demo/v0.1.0/plugin")); err != nil {
				t.Fatal("old version removed")
			}
			if _, err := os.Stat(h.path(pluginsDir + "/demo/v0.2.0")); !os.IsNotExist(err) {
				t.Fatal("new version left")
			}
			if !strings.Contains(jobLog(j), "Возвращена версия v0.1.0") {
				t.Fatal(jobLog(j))
			}
			// The old version runs again (or still runs) with its token.
			h.mu.Lock()
			h.noStart = false
			h.manifest = nil
			h.mu.Unlock()
			if h.m.conn("demo") == nil {
				h.startProc("demo") // what systemd's Restart= would do
			}
			h.waitConnected("demo")
		})
	}
}

func TestEnableDisableRemove(t *testing.T) {
	h := newHarness(t)
	key := newKey(t)
	ctx := context.Background()
	if j := h.install(pkgFor(t, key, "v0.1.0")); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	h.waitConnected("demo")
	job, err := h.m.SetEnabled(ctx, "demo", false)
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if p, _ := h.st.GetPlugin(ctx, "demo"); p.Enabled {
		t.Fatal("still enabled")
	}
	if h.m.conn("demo") != nil {
		t.Fatal("disabled plugin still connected")
	}
	if l, _ := h.m.List(ctx); l.Plugins[0].State != StateDisabled {
		t.Fatal(l.Plugins[0].State)
	}
	job, _ = h.m.SetEnabled(ctx, "demo", true)
	if j := h.wait(job.ID); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	h.waitConnected("demo")

	// Removing with instances is refused with their names.
	inst := &store.PluginInstance{PluginID: "demo", Name: "Первый", Config: `{}`}
	if err := h.st.CreateInstance(ctx, inst, nil); err != nil {
		t.Fatal(err)
	}
	_, err = h.m.Remove(ctx, "demo")
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 409 || len(pe.Instances) != 1 || pe.Instances[0] != "Первый" {
		t.Fatalf("%v", err)
	}
	_ = h.st.DeleteInstance(ctx, inst.ID)
	if _, err := h.sec.Put(ctx, SecretPurpose("demo", 99, "x"), []byte("s")); err != nil {
		t.Fatal(err)
	}
	job, err = h.m.Remove(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if _, err := h.st.GetPlugin(ctx, "demo"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("plugin kept")
	}
	if ids, _ := h.st.SecretIDsByPrefix(ctx, "plugin:demo:"); len(ids) != 0 {
		t.Fatal("secrets kept")
	}
	if _, err := os.Stat(h.path(pluginsDir + "/demo")); !os.IsNotExist(err) {
		t.Fatal("files kept")
	}
	if !strings.Contains(h.systemctlLog(), "clean --what=state hestia-plugin@demo.service") {
		t.Fatal("state directory not cleaned")
	}
	// The author stays pinned and can be forgotten now.
	if as, _ := h.m.Authors(ctx); len(as) != 1 || len(as[0].Plugins) != 0 {
		t.Fatalf("%+v", as)
	}
	if err := h.m.ForgetAuthor(ctx, pubOf(key)); err != nil {
		t.Fatal(err)
	}
}

func TestForgetAuthorInUse(t *testing.T) {
	h := newHarness(t)
	key := newKey(t)
	if j := h.install(pkgFor(t, key, "v0.1.0")); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	err := h.m.ForgetAuthor(context.Background(), pubOf(key))
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 409 {
		t.Fatal(err)
	}
}

func TestUnitState(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.root, "active"), []byte("failed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := h.m.UnitState(context.Background(), "demo")
	if err != nil || st != "failed" {
		t.Fatalf("%q %v", st, err)
	}
}

// A controller installed before plugins cannot write /run/hestia until it
// restarts with the drop-in: the install fails cleanly and schedules that
// restart.
func TestFirstPluginNeedsControllerRestart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.root, "ro-run"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	j := h.install(pkgFor(t, newKey(t), "v0.1.0"))
	if j.Status != store.JobFailed || j.Error != msgFirstRestart {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if readFile(t, h.path(controllerDropinPath)) != string(controllerDropin) {
		t.Fatal("controller drop-in not installed")
	}
	runLog, _ := os.ReadFile(filepath.Join(h.root, "systemd-run.log"))
	if !strings.Contains(string(runLog), "systemctl restart hestia.service") {
		t.Fatalf("restart not scheduled: %q", runLog)
	}
	if _, err := os.Stat(h.path(pluginsDir + "/demo")); !os.IsNotExist(err) {
		t.Fatal("plugin files left")
	}
	_ = os.Chmod(filepath.Join(h.root, "run", "hestia"), 0o755)
}

// The unit template (UMask=0077) and the drop-ins are rewritten when any
// plugin is installed or updated and their content differs.
func TestUnitTemplateRefresh(t *testing.T) {
	h := newHarness(t)
	key := newKey(t)
	if !strings.Contains(string(unitTemplate), "\nUMask=0077\n") {
		t.Fatal("UMask missing in the unit template")
	}
	if j := h.install(pkgFor(t, key, "v0.1.0")); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	// An older Hestia left another template and a changed drop-in.
	old := strings.Replace(string(unitTemplate), "UMask=0077\n", "", 1)
	if err := os.WriteFile(h.path(unitPath), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	dropin := h.path(dropinDir("demo") + "/10-hestia.conf")
	if err := os.WriteFile(dropin, []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Another plugin is installed: both files come back, systemd reloads.
	other := testPackage(t, key, func(m *sdk.Manifest) { m.ID, m.Name = "other", "Other" })
	before := strings.Count(h.systemctlLog(), "daemon-reload")
	j := h.install(other)
	if j.Status != store.JobDone || !strings.Contains(jobLog(j), "Шаблон юнита плагинов обновлён") {
		t.Fatal(jobLog(j))
	}
	if readFile(t, h.path(unitPath)) != string(unitTemplate) || readFile(t, dropin) != string(noNetworkConf) {
		t.Fatal("template or drop-in not rewritten")
	}
	if strings.Count(h.systemctlLog(), "daemon-reload") <= before {
		t.Fatal("no daemon-reload")
	}
	// Unchanged files are not written again.
	j = h.install(pkgFor(t, key, "v0.2.0"))
	if j.Status != store.JobDone || strings.Contains(jobLog(j), "Шаблон юнита плагинов обновлён") {
		t.Fatal(jobLog(j))
	}
}
