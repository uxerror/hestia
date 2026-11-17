package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"hestia/internal/api"
	"hestia/internal/auth"
	"hestia/internal/inventory"
	"hestia/internal/jobs"
	"hestia/internal/onboard"
	"hestia/internal/secrets"
	"hestia/internal/selfinstall"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/testelf"
	"hestia/internal/update"
)

// machine is a controller host that only knows `hestia.new version`.
type machine struct{ files map[string][]byte }

func (m *machine) Exec(ctx context.Context, script string, _ []byte) (sshx.Result, error) {
	if strings.HasSuffix(script, "hestia.new version") {
		return sshx.Result{Stdout: "hestia v0.2.0\n"}, nil
	}
	return sshx.Result{}, nil
}

func (m *machine) PutFile(_ context.Context, _ func(string), path string, data []byte, _, _ string) error {
	m.files[path] = data
	return nil
}

func (m *machine) Close() error { return nil }

type updEnv struct {
	*env
	svc *update.Service
	loc *selfinstall.Location
	m   *machine
}

func newUpdEnv(t *testing.T) *updEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, _ := secrets.Open(st, dir)
	id, _ := sec.EnsureIdentity(context.Background(), "pc")
	runner, _ := jobs.NewRunner(context.Background(), st)
	gate := &selfinstall.Gate{}
	si := (&selfinstall.Service{Store: st, Secrets: sec, Runner: runner, Identity: id, Gate: gate, DataDir: dir, Version: "v0.1.0"}).Init()
	ue := &updEnv{m: &machine{files: map[string][]byte{}}}
	ue.svc = (&update.Service{Store: st, Runner: runner, DataDir: dir, Version: "v0.1.0", Self: si,
		Location: func(ctx context.Context) (*selfinstall.Location, error) { return ue.loc, nil },
		Open:     func(context.Context, selfinstall.Location) (update.Shell, error) { return ue.m, nil },
	}).Init()
	h := api.New(api.Config{
		Store: st, Auth: auth.New(st), Runner: runner,
		Onboard:   (&onboard.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init(),
		Inventory: (&inventory.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init(),
		Identity:  id, Selfinstall: si, Update: ue.svc, Gate: gate, Mode: "serve", Version: "v0.1.0", Web: spa,
	})
	srv := httptest.NewServer(h)
	jar, _ := cookiejar.New(nil)
	t.Cleanup(func() { srv.Close(); runner.Shutdown(); _ = st.Close() })
	ue.env = &env{srv: srv, client: &http.Client{Jar: jar}, runner: runner, store: st}
	return ue
}

func (e *updEnv) upload(t *testing.T, version string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/update/upload?version="+version, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func TestUpdateEndpointsNeedLogin(t *testing.T) {
	e := newUpdEnv(t)
	for _, c := range [][2]string{{"GET", "/api/v1/update"}, {"POST", "/api/v1/update/check"}, {"POST", "/api/v1/update/upload"}, {"POST", "/api/v1/update"}} {
		if resp, _ := e.do(t, e.client, c[0], c[1], ""); resp.StatusCode != 401 {
			t.Errorf("%s %s: %d", c[0], c[1], resp.StatusCode)
		}
	}
}

func TestUpdateStatusWithoutLocation(t *testing.T) {
	e := newUpdEnv(t)
	login(t, e.env)
	resp, b := e.do(t, e.client, "GET", "/api/v1/update", "")
	var st update.Status
	if err := json.Unmarshal(b, &st); err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if st.Current != "v0.1.0" || st.LocationOK || st.Reason == "" || st.GitHub.Configured {
		t.Fatalf("%+v", st)
	}
	// the GitHub channel is not configured: a check is refused without a request
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/update/check", ""); resp.StatusCode != 409 {
		t.Fatalf("check: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/update", `{"source":"github","version":"v0.2.0"}`); resp.StatusCode != 409 {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/update", `{`); resp.StatusCode != 400 {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
}

func TestUpdateUploadStatuses(t *testing.T) {
	e := newUpdEnv(t)
	login(t, e.env)
	good := testelf.Build(testelf.Opts{Payload: []byte("x")})
	for _, c := range []struct {
		name, ver string
		body      []byte
		want      int
	}{
		{"no version", "", good, 400},
		{"not elf", "v0.2.0", []byte("hello"), 422},
		{"dynamic", "v0.2.0", testelf.Build(testelf.Opts{Dynamic: true}), 422},
		{"arm", "v0.2.0", testelf.Build(testelf.Opts{Machine: 183}), 422},
		{"downgrade", "v0.0.9", good, 422},
		{"ok", "v0.2.0", good, 200},
		{"dirty", "v0.2.0-2-gabc1234-dirty", good, 200},
	} {
		resp, b := e.upload(t, c.ver, c.body)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, b)
		}
		if c.want == 200 {
			var u update.Uploaded
			_ = json.Unmarshal(b, &u)
			if u.UploadID == "" || len(u.SHA256) != 64 || u.Dirty != (c.name == "dirty") {
				t.Errorf("%s: %+v", c.name, u)
			}
		}
	}
	old := update.MaxUpload
	update.MaxUpload = 100
	defer func() { update.MaxUpload = old }()
	if resp, _ := e.upload(t, "v0.2.0", good); resp.StatusCode != 413 {
		t.Errorf("too large: %d", resp.StatusCode)
	}
}

func TestUpdateFromUploadEndToEnd(t *testing.T) {
	e := newUpdEnv(t)
	e.loc = &selfinstall.Location{Kind: "lxc", TargetID: 1, Node: "pve1", VMID: 900, IP: "198.51.100.9"}
	login(t, e.env)
	_, b := e.do(t, e.client, "GET", "/api/v1/update", "")
	var st update.Status
	_ = json.Unmarshal(b, &st)
	if !st.LocationOK || st.Where == nil || st.Where.VMID != 900 || st.Where.Node != "pve1" {
		t.Fatalf("%s", b)
	}
	bin := testelf.Build(testelf.Opts{Payload: []byte("new")})
	resp, b := e.upload(t, "v0.2.0", bin)
	var up update.Uploaded
	if resp.StatusCode != 200 || json.Unmarshal(b, &up) != nil {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, b = e.do(t, e.client, "POST", "/api/v1/update", `{"upload_id":"`+up.UploadID+`"}`)
	var out struct{ Job store.Job }
	if resp.StatusCode != 202 || json.Unmarshal(b, &out) != nil || out.Job.ID == "" {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	e.runner.Wait()
	if string(e.m.files["/usr/local/bin/hestia.new"]) != string(bin) {
		t.Fatal("the binary did not reach the machine")
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/jobs/"+out.Job.ID, "")
	if !strings.Contains(string(b), `"status":"running"`) {
		t.Fatalf("a handed-off job stays running: %s", b)
	}
	// a second one is refused while the first is in flight
	resp, _ = e.do(t, e.client, "POST", "/api/v1/update", `{"upload_id":"`+up.UploadID+`"}`)
	if resp.StatusCode != 410 && resp.StatusCode != 409 {
		t.Fatalf("second start: %d", resp.StatusCode)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/update", "")
	if !strings.Contains(string(b), `"running_job":"`+out.Job.ID+`"`) {
		t.Fatalf("running_job: %s", b)
	}
}

func TestUpdateConfirmIsReportedAsFlag(t *testing.T) {
	e := newUpdEnv(t)
	e.loc = &selfinstall.Location{Kind: "ssh", TargetID: 1, IP: "198.51.100.9"}
	login(t, e.env)
	bin := testelf.Build(testelf.Opts{})
	_, b := e.upload(t, "v0.2.0-2-gabc1234-dirty", bin)
	var up update.Uploaded
	_ = json.Unmarshal(b, &up)
	resp, b := e.do(t, e.client, "POST", "/api/v1/update", `{"upload_id":"`+up.UploadID+`"}`)
	if resp.StatusCode != 409 || !strings.Contains(string(b), `"confirm":true`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}
