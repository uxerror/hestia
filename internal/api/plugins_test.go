package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/uxerror/hestia/internal/api"
	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/sshx/sshxtest"
	"github.com/uxerror/hestia/internal/store"
)

// buildHello compiles the demo plugin (the build cache makes repeats cheap).
func buildHello(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "plugin")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/uxerror/hestia/plugins/hestia-hello")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// fakeFS is the filesystem of the fake SSH target (only what hello uses).
type fakeFS struct {
	mu    sync.Mutex
	files map[string]string
	cmds  []string
}

var (
	reHelloCat = regexp.MustCompile(`^cat (/tmp/hestia-hello-\d+) 2>/dev/null \|\| exit 3$`)
	reHelloPut = regexp.MustCompile(`^umask 077 && cat > '(/tmp/hestia-hello-\d+)' && chmod 0644 '/tmp/hestia-hello-\d+'$`)
	reHelloRm  = regexp.MustCompile(`^rm -f (/tmp/hestia-hello-\d+)$`)
)

// unquote reverses `sh -c '<script>'` as built by target.Quote.
func unquote(cmd string) (string, bool) {
	if !strings.HasPrefix(cmd, "sh -c '") || !strings.HasSuffix(cmd, "'") {
		return "", false
	}
	return strings.ReplaceAll(cmd[len("sh -c '"):len(cmd)-1], `'\''`, `'`), true
}

func (f *fakeFS) handle(user, cmd string, stdin []byte) (string, string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	script, ok := unquote(cmd)
	if !ok || user != "root" {
		return "", "unexpected: " + cmd, 127
	}
	f.cmds = append(f.cmds, script)
	if m := reHelloCat.FindStringSubmatch(script); m != nil {
		v, ok := f.files[m[1]]
		if !ok {
			return "", "", 3
		}
		return v, "", 0
	}
	if m := reHelloPut.FindStringSubmatch(script); m != nil {
		f.files[m[1]] = string(stdin)
		return "", "", 0
	}
	if m := reHelloRm.FindStringSubmatch(script); m != nil {
		delete(f.files, m[1])
		return "", "", 0
	}
	return "", "unexpected: " + script, 127
}

type pluginEnv struct {
	*env
	pm  *plugins.Manager
	fs  *fakeFS
	ref string
}

func newPluginEnv(t *testing.T) *pluginEnv {
	t.Helper()
	bin := buildHello(t)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.Open(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sec.EnsureIdentity(context.Background(), "testhost")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	// The target: an in-process SSH server that accepts Hestia's key.
	fs := &fakeFS{files: map[string]string{}}
	srv := sshxtest.New(t)
	want := string(id.Signer.PublicKey().Marshal())
	srv.KeyAuth = func(u string, k ssh.PublicKey) bool { return u == "root" && string(k.Marshal()) == want }
	srv.Handler = fs.handle
	tg := &store.Target{Kind: store.KindSSH, Name: "web", Host: srv.Host, Port: srv.Port, SSHUser: "root", HostKeyFP: srv.HostKeyFP()}
	if err := st.CreateTarget(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	pm := (&plugins.Manager{Store: st, Secrets: sec, Runner: runner, Identity: id, Version: "test", DataDir: dir,
		Mode: "serve", SocketPath: "-"}).Init()
	pm.Start()
	if err := pm.StartDev(bin); err != nil {
		t.Fatal(err)
	}
	h := api.New(api.Config{
		Store: st, Auth: auth.New(st), Runner: runner, Identity: id, Plugins: pm, Mode: "serve", Version: "test",
		Web: fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}},
	})
	hs := httptest.NewServer(h)
	jar, _ := cookiejar.New(nil)
	t.Cleanup(func() { hs.Close(); pm.Close(); runner.Shutdown(); _ = st.Close() })
	e := &env{srv: hs, client: &http.Client{Jar: jar}, runner: runner, store: st}
	return &pluginEnv{env: e, pm: pm, fs: fs, ref: fmt.Sprintf("ssh:%d", tg.ID)}
}

func decode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
}

type planResp struct {
	PlanID   string `json:"plan_id"`
	Hash     string `json:"hash"`
	Action   string `json:"action"`
	Instance struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"instance"`
	Plan struct {
		Actions []struct{ Title, Risk string } `json:"actions"`
	} `json:"plan"`
}

func (e *pluginEnv) apply(t *testing.T, p planResp) {
	t.Helper()
	resp, b := e.do(t, e.client, "POST", "/api/v1/plugins/plans/"+p.PlanID+"/apply", `{"hash":"`+p.Hash+`"}`)
	if resp.StatusCode != 202 {
		t.Fatalf("apply %d %s", resp.StatusCode, b)
	}
	var r struct{ Job struct{ ID string } }
	decode(t, b, &r)
	waitJobDone(t, e.env, r.Job.ID)
}

// E2E of the framework in dev mode: the real hestia-hello binary, a fake
// SSH target, plan → apply → status → remove over the HTTP API.
func TestPluginDevEndToEnd(t *testing.T) {
	e := newPluginEnv(t)
	login(t, e.env)

	// The dev plugin appears as connected.
	var list struct {
		Available bool
		Reason    string
		Plugins   []struct {
			ID, State, Source string
			Dev               bool
			Permissions       []string
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, b := e.do(t, e.client, "GET", "/api/v1/plugins", "")
		decode(t, b, &list)
		if len(list.Plugins) == 1 && list.Plugins[0].State == "connected" && len(list.Plugins[0].Permissions) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dev plugin not registered: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	p := list.Plugins[0]
	if p.ID != "hestia-hello" || !p.Dev || p.Source != "dev" || list.Available {
		t.Fatalf("%+v %+v", p, list)
	}

	// Target candidates.
	_, b := e.do(t, e.client, "GET", "/api/v1/plugins/targets", "")
	if !strings.Contains(string(b), `"id":"`+e.ref+`"`) {
		t.Fatalf("targets %s", b)
	}

	// Validation errors come back per field.
	resp, b := e.do(t, e.client, "POST", "/api/v1/plugins/hestia-hello/instances/plan", `{"name":"","config":{"message":""}}`)
	if resp.StatusCode != 422 || !strings.Contains(string(b), `"field":"target"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}

	// Create.
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/hestia-hello/instances/plan",
		`{"name":"","config":{"target":"`+e.ref+`","message":"Привет, сеть"}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("plan %d %s", resp.StatusCode, b)
	}
	var pl planResp
	decode(t, b, &pl)
	path := fmt.Sprintf("/tmp/hestia-hello-%d", pl.Instance.ID)
	if pl.Action != "create" || pl.Instance.Name != "Hestia Hello 1" || len(pl.Plan.Actions) != 1 ||
		!strings.Contains(pl.Plan.Actions[0].Title, path) {
		t.Fatalf("%+v", pl)
	}
	e.apply(t, pl)
	e.fs.mu.Lock()
	got := e.fs.files[path]
	e.fs.mu.Unlock()
	if got != "Привет, сеть\n" {
		t.Fatalf("file on the target: %q", got)
	}

	// Status.
	iid := fmt.Sprint(pl.Instance.ID)
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/instances/"+iid+"?status=refresh", "")
	var inst struct {
		Status, Detail string
		Targets        []string
	}
	decode(t, b, &inst)
	if inst.Status != "ok" || inst.Detail != "Привет, сеть" || len(inst.Targets) != 1 {
		t.Fatalf("%s", b)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/hestia-hello/instances", "")
	if !strings.Contains(string(b), `"name":"Hestia Hello 1"`) {
		t.Fatal(string(b))
	}

	// Somebody edits the file: degraded.
	e.fs.mu.Lock()
	e.fs.files[path] = "другое\n"
	e.fs.mu.Unlock()
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/instances/"+iid+"?status=refresh", "")
	decode(t, b, &inst)
	if inst.Status != "degraded" {
		t.Fatalf("%s", b)
	}

	// Remove.
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/instances/"+iid+"/plan", `{"action":"remove"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	decode(t, b, &pl)
	e.apply(t, pl)
	e.fs.mu.Lock()
	_, exists := e.fs.files[path]
	e.fs.mu.Unlock()
	if exists {
		t.Fatal("file not removed")
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/plugins/instances/"+iid, ""); resp.StatusCode != 404 {
		t.Fatalf("instance still there: %d", resp.StatusCode)
	}

	// Dev plugins are not enabled/disabled through the root path.
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/plugins/hestia-hello/disable", ""); resp.StatusCode != 409 {
		t.Fatalf("disable dev: %d", resp.StatusCode)
	}
}

func TestPluginAPIMisc(t *testing.T) {
	e := newPluginEnv(t)
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/plugins", ""); resp.StatusCode != 401 {
		t.Fatal("plugins without login")
	}
	login(t, e.env)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/plugins/catalog"}, {"POST", "/api/v1/plugins/catalog/refresh"}, {"POST", "/api/v1/plugins/packages/catalog"},
	} {
		resp, b := e.do(t, e.client, c.method, c.path, "{}")
		if resp.StatusCode != 501 || !strings.Contains(string(b), "следующем обновлении") {
			t.Fatalf("%s %s: %d %s", c.method, c.path, resp.StatusCode, b)
		}
	}
	// Uploads need a controller installed through Hestia.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "x.hpkg")
	_, _ = fw.Write([]byte("not a package"))
	_ = mw.Close()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/plugins/packages", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatalf("upload without location: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/plugins/packages/fetch", `{"url":"http://insecure"}`); resp.StatusCode != 400 {
		t.Fatalf("fetch http: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/plugins/install", `{"upload_id":"nope"}`); resp.StatusCode != 409 {
		t.Fatalf("install without location: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/plugins/nope", ""); resp.StatusCode != 404 {
		t.Fatal("unknown plugin")
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/plugins/instances/abc", ""); resp.StatusCode != 404 {
		t.Fatal("bad instance id")
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/plugins/plans/nope/apply", `{"hash":"x"}`); resp.StatusCode != 410 {
		t.Fatal("unknown plan")
	}
	_, b := e.do(t, e.client, "GET", "/api/v1/plugins/authors", "")
	if string(b) != "{\"authors\":[]}\n" {
		t.Fatalf("authors %s", b)
	}
}
