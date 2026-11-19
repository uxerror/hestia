package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/uxerror/hestia/internal/api"
	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/plugins/deploytest"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/update"
)

// buildHello compiles the demo plugin (the build cache makes repeats cheap).
func buildHello(t *testing.T) string { return buildPlugin(t, "hestia-hello") }

func buildPlugin(t *testing.T, id string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "plugin")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/uxerror/hestia/plugins/"+id)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

type pluginEnv struct {
	*env
	pm  *plugins.Manager
	tg  *deploytest.Target
	ref string
	// dev is a second fake target (a device for links).
	dev    *deploytest.Target
	devRef string
}

func newPluginEnv(t *testing.T, extra ...string) *pluginEnv {
	t.Helper()
	bins := []string{buildHello(t)}
	for _, id := range extra {
		bins = append(bins, buildPlugin(t, id))
	}
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
	// The target: an in-process SSH server that accepts Hestia's key, with
	// fake docker/apt-get/ss (nothing real is run).
	ft := deploytest.New(t, id.Signer.PublicKey())
	srv := ft.Srv
	tg := &store.Target{Kind: store.KindSSH, Name: "web", Host: srv.Host, Port: srv.Port, SSHUser: "root", HostKeyFP: srv.HostKeyFP()}
	if err := st.CreateTarget(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	ft2 := deploytest.New(t, id.Signer.PublicKey())
	tg2 := &store.Target{Kind: store.KindSSH, Name: "nas", Host: ft2.Srv.Host, Port: ft2.Srv.Port, SSHUser: "root", HostKeyFP: ft2.Srv.HostKeyFP()}
	if err := st.CreateTarget(context.Background(), tg2); err != nil {
		t.Fatal(err)
	}
	pm := (&plugins.Manager{Store: st, Secrets: sec, Runner: runner, Identity: id, Version: "test", DataDir: dir,
		Mode: "serve", SocketPath: "-", GitHub: &update.GitHub{BaseURL: "http://127.0.0.1:1"}, DeployPoll: 20 * time.Millisecond}).Init()
	pm.Start()
	for _, bin := range bins {
		if err := pm.StartDev(bin); err != nil {
			t.Fatal(err)
		}
	}
	h := api.New(api.Config{
		Store: st, Auth: auth.New(st), Runner: runner, Identity: id, Plugins: pm, Mode: "serve", Version: "test",
		Web: fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}},
	})
	hs := httptest.NewServer(h)
	jar, _ := cookiejar.New(nil)
	t.Cleanup(func() { hs.Close(); pm.Close(); runner.Shutdown(); _ = st.Close() })
	e := &env{srv: hs, client: &http.Client{Jar: jar}, runner: runner, store: st}
	return &pluginEnv{env: e, pm: pm, tg: ft, ref: fmt.Sprintf("ssh:%d", tg.ID), dev: ft2, devRef: fmt.Sprintf("ssh:%d", tg2.ID)}
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

// E2E in dev mode: the real hestia-hello binary, a fake SSH target with fake
// docker, plan → apply (deploy.up + HTTP check) → status → remove over the
// HTTP API. The "container" is a local HTTP server on the configured port.
func TestPluginDevEndToEnd(t *testing.T) {
	e := newPluginEnv(t)
	login(t, e.env)

	// The dev plugin appears as connected.
	var list struct {
		Available bool
		Reason    string
		Plugins   []struct {
			ID, State, Source, Version string
			Dev                        bool
			Permissions                []string
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, b := e.do(t, e.client, "GET", "/api/v1/plugins", "")
		decode(t, b, &list)
		if len(list.Plugins) == 1 && list.Plugins[0].State == "connected" && len(list.Plugins[0].Permissions) == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dev plugin not registered: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	p := list.Plugins[0]
	if p.ID != "hestia-hello" || p.Version != "v0.4.0" || !p.Dev || p.Source != "dev" || list.Available ||
		strings.Join(p.Permissions, ",") != "targets.read,targets.exec,deploy.docker,net.outbound,links.client" {
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

	// whoami: a local HTTP server stands for the container.
	who := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Name: Привет, сеть\nHostname: test\n")
	}))
	defer who.Close()
	_, portStr, _ := net.SplitHostPort(who.Listener.Addr().String())
	e.tg.Set("port", portStr)
	e.tg.Set("service", "whoami")

	// Create.
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/hestia-hello/instances/plan",
		`{"name":"","config":{"target":"`+e.ref+`","port":`+portStr+`,"message":"Привет, сеть"}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("plan %d %s", resp.StatusCode, b)
	}
	var pl planResp
	decode(t, b, &pl)
	url := "http://127.0.0.1:" + portStr + "/"
	proj := fmt.Sprintf("hestia-%d-whoami", pl.Instance.ID)
	var titles []string
	for _, a := range pl.Plan.Actions {
		titles = append(titles, a.Title)
	}
	all := strings.Join(titles, "\n")
	if pl.Action != "create" || pl.Instance.Name != "Hestia Hello 1" || !strings.Contains(all, "Создать проект "+proj) ||
		!strings.Contains(all, "Проверить "+url) || strings.Contains(all, "Установить Docker") {
		t.Fatalf("%+v", pl)
	}
	e.apply(t, pl)
	dir := fmt.Sprintf("/opt/hestia/%d-whoami", pl.Instance.ID)
	compose, ok := e.tg.File(dir + "/compose.yaml")
	if !ok || !strings.Contains(compose, "Привет, сеть") || !strings.Contains(compose, `"hestia.plugin": "hestia-hello"`) ||
		!strings.Contains(compose, portStr+":80") {
		t.Fatalf("compose.yaml: %q", compose)
	}
	if !strings.Contains(e.tg.Log("docker.log"), "compose -p "+proj+" -f compose.yaml up -d --remove-orphans") {
		t.Fatal(e.tg.Log("docker.log"))
	}

	// Status.
	iid := fmt.Sprint(pl.Instance.ID)
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/instances/"+iid+"?status=refresh", "")
	var inst struct {
		Status, Detail string
		Targets        []string
		Endpoints      []struct{ Name, URL string }
	}
	decode(t, b, &inst)
	if inst.Status != "ok" || inst.Detail != "Name: Привет, сеть" || len(inst.Targets) != 1 || len(inst.Endpoints) != 1 || inst.Endpoints[0].URL != url {
		t.Fatalf("%s", b)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/hestia-hello/instances", "")
	if !strings.Contains(string(b), `"name":"Hestia Hello 1"`) {
		t.Fatal(string(b))
	}

	// The service stops answering: down.
	who.Close()
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/instances/"+iid+"?status=refresh", "")
	decode(t, b, &inst)
	if inst.Status != "down" {
		t.Fatalf("%s", b)
	}

	// Remove: docker compose down -v and the directory goes.
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/instances/"+iid+"/plan", `{"action":"remove"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	decode(t, b, &pl)
	e.apply(t, pl)
	if !strings.Contains(e.tg.Log("docker.log"), "down -v --remove-orphans") {
		t.Fatal(e.tg.Log("docker.log"))
	}
	if _, ok := e.tg.File(dir + "/compose.yaml"); ok {
		t.Fatal("project directory kept")
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
	// The catalog: empty until fetched; GitHub unreachable → an error in
	// the answer, not an HTTP error.
	resp, b := e.do(t, e.client, "GET", "/api/v1/plugins/catalog", "")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"plugins":[]`) || !strings.Contains(string(b), `"error":""`) {
		t.Fatalf("catalog %d %s", resp.StatusCode, b)
	}
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/catalog/refresh", "")
	var cv struct {
		Error   string
		Plugins []any
	}
	decode(t, b, &cv)
	if resp.StatusCode != 200 || cv.Error == "" || len(cv.Plugins) != 0 {
		t.Fatalf("refresh %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/plugins/packages/catalog", `{"id":"hestia-hello"}`); resp.StatusCode != 409 {
		t.Fatalf("catalog install without location: %d", resp.StatusCode)
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
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins/authors", "")
	if string(b) != "{\"authors\":[]}\n" {
		t.Fatalf("authors %s", b)
	}
}
