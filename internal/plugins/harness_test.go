package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

// fakeBin are stand-ins for systemctl and friends: they only log.
var fakeBin = map[string]string{
	"systemctl": `#!/bin/sh
echo "$*" >> "$HESTIA_ROOT/systemctl.log"
if [ "$1" = is-active ]; then cat "$HESTIA_ROOT/active" 2>/dev/null || echo active; fi
exit 0
`,
	"systemd-tmpfiles": `#!/bin/sh
echo "$*" >> "$HESTIA_ROOT/tmpfiles.log"
mkdir -p "$HESTIA_ROOT/run/hestia"
# ro-run: the controller cannot write there (ProtectSystem=strict before
# the drop-in takes effect).
if [ -f "$HESTIA_ROOT/ro-run" ]; then chmod 0555 "$HESTIA_ROOT/run/hestia"; fi
`,
	"systemd-run": `#!/bin/sh
echo "$*" >> "$HESTIA_ROOT/systemd-run.log"
`,
	"chown": `#!/bin/sh
exit 0
`,
}

// fakeShell runs root scripts locally under the test prefix.
type fakeShell struct {
	h *harness
}

func (s *fakeShell) Exec(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
	h := s.h
	if err := h.injected(script); err != nil {
		return sshx.Result{ExitCode: 1, Stderr: err.Error()}, err
	}
	h.mu.Lock()
	h.scripts = append(h.scripts, script)
	h.mu.Unlock()
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+h.bin+":"+os.Getenv("PATH"), "HESTIA_ROOT="+h.root)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := sshx.Result{Stdout: out.String(), Stderr: errb.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, &sshx.ExitError{Cmd: script, Result: res}
	}
	if err != nil {
		return res, err
	}
	h.afterScript(script)
	return res, nil
}

func (s *fakeShell) PutFile(ctx context.Context, log func(string), path string, data []byte, mode, owner string) error {
	h := s.h
	if !strings.HasPrefix(path, h.root+"/") {
		h.t.Errorf("PutFile outside the test root: %s", path)
		return errors.New("outside root")
	}
	if err := h.injected("put " + path); err != nil {
		return err
	}
	var m uint32
	_, _ = fmt.Sscanf(mode, "%o", &m)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, os.FileMode(m)); err != nil {
		return err
	}
	return os.Chmod(path, os.FileMode(m))
}

func (s *fakeShell) Close() error { return nil }

// harness is a Manager with a temporary root, fake systemd and an
// in-process plugin started on "systemctl enable/restart".
type harness struct {
	t      *testing.T
	m      *Manager
	st     *store.Store
	sec    *secrets.Service
	runner *jobs.Runner
	root   string
	bin    string
	exec   *fakeExec

	mu       sync.Mutex
	scripts  []string
	fail     map[string]error // substring of a script (or "put <path>") → error
	procs    map[string]context.CancelFunc
	plug     func(id string) sdk.Plugin
	manifest func(id string, installed []byte) []byte // what the process reports
	noStart  bool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	// Short root: the unix socket path must stay under 108 bytes.
	root, err := os.MkdirTemp("", "hp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range fakeBin {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.Open(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: st, sec: sec, runner: runner, root: root, bin: bin, exec: &fakeExec{files: map[string]string{}},
		fail: map[string]error{}, procs: map[string]context.CancelFunc{}}
	h.plug = func(string) sdk.Plugin { return &testPlugin{} }
	h.m = (&Manager{
		Store: st, Secrets: sec, Runner: runner, Version: "v0.2.0", DataDir: dir, Mode: "serve",
		SocketPath: root + "/run/hestia/plugins.sock", Root: root, Targets: h.exec,
		Location: func(context.Context) (*selfinstall.Location, error) {
			return &selfinstall.Location{Kind: "ssh", TargetID: 1, Host: "10.10.10.5", IP: "10.10.10.5"}, nil
		},
		Open:              func(context.Context, selfinstall.Location) (Shell, error) { return &fakeShell{h: h}, nil },
		HelloTimeout:      2 * time.Second,
		HeartbeatInterval: time.Hour,
	}).Init()
	h.m.Start()
	t.Cleanup(func() {
		h.mu.Lock()
		for _, c := range h.procs {
			c()
		}
		h.mu.Unlock()
		h.m.Close()
		runner.Shutdown()
		_ = st.Close()
	})
	return h
}

func (h *harness) injected(script string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// One-shot: the rollback may run the same command again.
	for sub, err := range h.fail {
		if strings.Contains(script, sub) {
			delete(h.fail, sub)
			return err
		}
	}
	return nil
}

func (h *harness) failOn(sub string) {
	h.mu.Lock()
	h.fail[sub] = errors.New("injected failure: " + sub)
	h.mu.Unlock()
}

var reUnit = regexp.MustCompile(`systemctl (enable --now|restart|disable --now) hestia-plugin@([a-z0-9-]+)\.service`)

// afterScript plays systemd: enable/restart start the plugin, disable stops it.
func (h *harness) afterScript(script string) {
	for _, m := range reUnit.FindAllStringSubmatch(script, -1) {
		id := m[2]
		h.stopProc(id)
		if m[1] != "disable --now" {
			h.startProc(id)
		}
	}
}

func (h *harness) stopProc(id string) {
	h.mu.Lock()
	c := h.procs[id]
	delete(h.procs, id)
	h.mu.Unlock()
	if c != nil {
		c()
	}
}

func (h *harness) startProc(id string) {
	h.mu.Lock()
	no := h.noStart
	h.mu.Unlock()
	if no {
		return
	}
	dir := filepath.Join(h.root, pluginsDir, id)
	tok, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		h.t.Logf("start %s: %v", id, err)
		return
	}
	man, err := os.ReadFile(filepath.Join(dir, "current", FileManifest))
	if err != nil {
		h.t.Logf("start %s: %v", id, err)
		return
	}
	if h.manifest != nil {
		man = h.manifest(id, man)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.mu.Lock()
	h.procs[id] = cancel
	p := h.plug(id)
	h.mu.Unlock()
	go func() {
		c, err := net.Dial("unix", h.m.SocketPath)
		if err != nil {
			h.t.Logf("dial: %v", err)
			return
		}
		_ = sdk.Run(ctx, man, p, c, strings.TrimSpace(string(tok)))
	}()
}

func (h *harness) systemctlLog() string {
	b, _ := os.ReadFile(filepath.Join(h.root, "systemctl.log"))
	return string(b)
}

func (h *harness) path(p string) string { return filepath.Join(h.root, p) }

// upload stores a package as the user would.
func (h *harness) upload(pkg []byte) *Uploaded {
	h.t.Helper()
	up, err := h.m.Upload(context.Background(), bytes.NewReader(pkg))
	if err != nil {
		h.t.Fatalf("upload: %v", err)
	}
	return up
}

// install runs a whole plugin-install and returns the finished job.
func (h *harness) install(pkg []byte) store.Job {
	h.t.Helper()
	up := h.upload(pkg)
	job, err := h.m.Install(context.Background(), InstallRequest{UploadID: up.UploadID, TrustAuthor: true})
	if err != nil {
		h.t.Fatalf("install: %v", err)
	}
	return h.wait(job.ID)
}

func (h *harness) wait(id string) store.Job {
	h.t.Helper()
	h.runner.Wait()
	j, err := h.st.GetJob(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return j
}

func (h *harness) waitConnected(id string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.m.conn(id) != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("plugin %s not connected", id)
}

func (h *harness) waitDisconnected(id string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.m.conn(id) == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("plugin %s still connected", id)
}

func jobLog(j store.Job) string {
	var sb strings.Builder
	for _, s := range j.Steps {
		sb.WriteString("step " + s.Title + " " + s.Status + " " + s.Error + "\n")
	}
	for _, l := range j.Log {
		sb.WriteString(l.Level + " " + l.Line + "\n")
	}
	return sb.String()
}

// fakeExec is a TargetExec with a tiny shared filesystem and a log.
type fakeExec struct {
	mu    sync.Mutex
	files map[string]string // ref + ":" + path → content
	calls []string
	fail  error
}

var (
	reFakeCat = regexp.MustCompile(`^cat (\S+) 2>/dev/null \|\| exit 3$`)
	reFakePut = regexp.MustCompile(`^umask 077 && cat > '([^']+)' && chmod (\d+) '([^']+)'$`)
	reFakeRm  = regexp.MustCompile(`^rm -f (\S+)$`)
)

func (f *fakeExec) Exec(ctx context.Context, ref, script string, stdin []byte) (sshx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ref+" "+script)
	if f.fail != nil {
		return sshx.Result{}, f.fail
	}
	if m := reFakeCat.FindStringSubmatch(script); m != nil {
		v, ok := f.files[ref+":"+m[1]]
		if !ok {
			r := sshx.Result{ExitCode: 3}
			return r, &sshx.ExitError{Cmd: script, Result: r}
		}
		return sshx.Result{Stdout: v}, nil
	}
	if m := reFakePut.FindStringSubmatch(script); m != nil {
		f.files[ref+":"+m[1]] = string(stdin)
		return sshx.Result{}, nil
	}
	if m := reFakeRm.FindStringSubmatch(script); m != nil {
		delete(f.files, ref+":"+m[1])
		return sshx.Result{}, nil
	}
	if strings.HasPrefix(script, "echo ") {
		return sshx.Result{Stdout: strings.TrimPrefix(script, "echo ") + "\n"}, nil
	}
	r := sshx.Result{ExitCode: 127, Stderr: "unknown command"}
	return r, &sshx.ExitError{Cmd: script, Result: r}
}

func (f *fakeExec) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// testPlugin is a scriptable plugin.
type testPlugin struct {
	mu        sync.Mutex
	statusErr error
	danger    bool
	planNonce string // changes the plan (hash mismatch)
	applyHook func(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error
	validate  []sdk.FieldError
}

func (p *testPlugin) Validate(ctx context.Context, cfg sdk.Config) []sdk.FieldError {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.validate
}

func (p *testPlugin) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	risk := sdk.RiskChange
	if p.danger {
		risk = sdk.RiskDanger
	}
	data, _ := json.Marshal(map[string]any{"target": req.Config.String("target"), "nonce": p.planNonce})
	return sdk.Plan{Actions: []sdk.Action{{Title: req.Action + " " + req.Instance.Name, Risk: risk}}, Data: data}, nil
}

func (p *testPlugin) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	p.mu.Lock()
	hook := p.applyHook
	p.mu.Unlock()
	if hook != nil {
		return hook(ctx, req, job)
	}
	return job.Run("Работа", func(ctx context.Context) error {
		job.Logf("applied %s", req.Action)
		return nil
	})
}

func (p *testPlugin) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.statusErr != nil {
		return sdk.Status{}, p.statusErr
	}
	return sdk.Status{State: sdk.StateOK, Detail: "fine", Endpoints: []sdk.Endpoint{
		{Name: "web", URL: "http://10.10.10.21:8080"}, {Name: "bad", URL: "javascript:alert(1)"}}}, nil
}

// pkgFor builds a package of the demo plugin with the given version and
// permissions.
func pkgFor(t *testing.T, key ed25519.PrivateKey, ver string, perms ...string) []byte {
	return testPackage(t, key, func(m *sdk.Manifest) {
		m.Version = ver
		if perms != nil {
			m.Permissions = perms
		}
	})
}
