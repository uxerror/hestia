package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/uxerror/hestia/internal/api"
	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/onboard"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
)

var spa = fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}

type siEnv struct {
	*env
	gate *selfinstall.Gate
	svc  *selfinstall.Service
	dir  string
}

func newSIEnv(t *testing.T) *siEnv {
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
	instance, _ := st.EnsureInstanceID(context.Background())
	svc := (&selfinstall.Service{Store: st, Secrets: sec, Runner: runner, Identity: id, Gate: gate, DataDir: dir, Version: "test"}).Init()
	h := api.New(api.Config{
		Store: st, Auth: auth.New(st), Runner: runner,
		Onboard:   (&onboard.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init(),
		Inventory: (&inventory.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init(),
		Identity:  id, Selfinstall: svc, Gate: gate, InstanceID: instance, Mode: "serve", Version: "test", Web: spa,
	})
	srv := httptest.NewServer(h)
	jar, _ := cookiejar.New(nil)
	t.Cleanup(func() { srv.Close(); runner.Shutdown(); _ = st.Close() })
	return &siEnv{env: &env{srv: srv, client: &http.Client{Jar: jar}, runner: runner, store: st}, gate: gate, svc: svc, dir: dir}
}

func TestHealthCarriesInstanceID(t *testing.T) {
	e := newSIEnv(t)
	_, b := e.do(t, e.client, "GET", "/api/v1/health", "")
	var h struct {
		Status       string `json:"status"`
		InstanceID   string `json:"instance_id"`
		Transferring bool   `json:"transferring"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	id, _ := e.store.EnsureInstanceID(context.Background())
	if h.Status != "ok" || len(h.InstanceID) != 32 || h.InstanceID != id || h.Transferring {
		t.Fatalf("health: %s", b)
	}
}

func TestSelfinstallEndpoints(t *testing.T) {
	e := newSIEnv(t)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/selfinstall", ""},
		{"POST", "/api/v1/selfinstall/probe", `{"target_id":1}`},
		{"POST", "/api/v1/selfinstall", `{"probe_id":"x"}`},
	} {
		if resp, _ := e.do(t, e.client, tc.method, tc.path, tc.body); resp.StatusCode != 401 {
			t.Fatalf("%s %s without login: %d", tc.method, tc.path, resp.StatusCode)
		}
	}
	e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody)
	resp, b := e.do(t, e.client, "GET", "/api/v1/selfinstall", "")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"state":"local"`) || strings.Contains(string(b), `"location"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, b = e.do(t, e.client, "POST", "/api/v1/selfinstall/probe", `{"target_id":99}`)
	if resp.StatusCode != 404 || !strings.Contains(string(b), "цель не найдена") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, _ = e.do(t, e.client, "POST", "/api/v1/selfinstall", `{"probe_id":"gone"}`)
	if resp.StatusCode != 410 {
		t.Fatalf("expired probe: %d", resp.StatusCode)
	}
	if resp, _ = e.do(t, e.client, "POST", "/api/v1/selfinstall", `nope`); resp.StatusCode != 400 {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
	// installed: 409
	loc, _ := json.Marshal(selfinstall.Location{Kind: "lxc", IP: "198.51.100.7", MovedAt: time.Now()})
	_ = e.store.SetSetting(context.Background(), store.SettingControllerLocation, string(loc))
	resp, b = e.do(t, e.client, "GET", "/api/v1/selfinstall", "")
	if !strings.Contains(string(b), `"state":"installed"`) || !strings.Contains(string(b), `"198.51.100.7"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if resp, _ = e.do(t, e.client, "POST", "/api/v1/selfinstall/probe", `{"target_id":1}`); resp.StatusCode != 409 {
		t.Fatalf("probe when installed: %d", resp.StatusCode)
	}
}

func TestTransferModeBlocksWrites(t *testing.T) {
	e := newSIEnv(t)
	e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody)
	e.gate.SetTransferring(true)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/v1/targets/probe"}, {"DELETE", "/api/v1/targets/1"}, {"POST", "/api/v1/jobs/demo"},
		{"POST", "/api/v1/inventory/1/refresh"}, {"POST", "/api/v1/selfinstall/probe"},
	} {
		resp, b := e.do(t, e.client, tc.method, tc.path, `{}`)
		if resp.StatusCode != 503 || !strings.Contains(string(b), `{"error":"идёт перенос Hestia на сервер"}`) {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, resp.StatusCode, b)
		}
	}
	// reads and auth keep working
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/jobs", ""); resp.StatusCode != 200 {
		t.Fatalf("GET during transfer: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/selfinstall", ""); resp.StatusCode != 200 {
		t.Fatalf("selfinstall state during transfer: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/login", adminBody); resp.StatusCode != 200 {
		t.Fatalf("login during transfer: %d", resp.StatusCode)
	}
	_, b := e.do(t, e.client, "GET", "/api/v1/health", "")
	if !strings.Contains(string(b), `"transferring":true`) {
		t.Fatalf("health: %s", b)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/logout", ""); resp.StatusCode != 204 {
		t.Fatalf("logout during transfer: %d", resp.StatusCode)
	}
	e.gate.SetTransferring(false)
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/login", adminBody); resp.StatusCode != 200 {
		t.Fatal("login after transfer")
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/jobs/demo", ""); resp.StatusCode != 202 {
		t.Fatalf("write after the transfer mode ended: %d", resp.StatusCode)
	}
}

func TestHandoffEndpoint(t *testing.T) {
	e := newSIEnv(t)
	ctx := context.Background()
	u, _ := e.store.CreateFirstUser(ctx, "admin", "x")
	token, hash, _ := auth.NewHandoff()
	if err := e.store.CreateHandoff(ctx, hash, u.ID, time.Now().Add(auth.HandoffTTL)); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/auth/me", ""); resp.StatusCode != 401 {
		t.Fatal("must start signed out")
	}
	for _, bad := range []string{`{"token":"nope"}`, `{"token":""}`, `{}`} {
		if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/handoff", bad); resp.StatusCode != 401 {
			t.Fatalf("%s: %d", bad, resp.StatusCode)
		}
	}
	resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/handoff", `{"token":"`+token+`"}`)
	if resp.StatusCode != 204 || len(resp.Cookies()) != 1 || resp.Cookies()[0].Name != auth.CookieName {
		t.Fatalf("handoff: %d %v", resp.StatusCode, resp.Cookies())
	}
	if resp, b := e.do(t, e.client, "GET", "/api/v1/auth/me", ""); resp.StatusCode != 200 || !strings.Contains(string(b), "admin") {
		t.Fatalf("session from handoff: %d %s", resp.StatusCode, b)
	}
	other := &http.Client{}
	if resp, _ := e.do(t, other, "POST", "/api/v1/auth/handoff", `{"token":"`+token+`"}`); resp.StatusCode != 401 {
		t.Fatalf("a token must work once: %d", resp.StatusCode)
	}
	// expired
	token2, hash2, _ := auth.NewHandoff()
	_ = e.store.CreateHandoff(ctx, hash2, u.ID, time.Now().Add(-time.Second))
	if resp, _ := e.do(t, other, "POST", "/api/v1/auth/handoff", `{"token":"`+token2+`"}`); resp.StatusCode != 401 {
		t.Fatalf("expired token: %d", resp.StatusCode)
	}
}

func TestMovedMode(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","instance_id":"inst-9"}`))
	}))
	defer remote.Close()
	gate := &selfinstall.Gate{}
	gate.SetMoved(selfinstall.Remote{URL: remote.URL, InstanceID: "inst-9", Location: selfinstall.Location{Kind: "lxc", IP: "198.51.100.7"}})
	srv := httptest.NewServer(api.NewMoved(gate, spa, "test"))
	defer srv.Close()
	e := &env{srv: srv}
	c := &http.Client{}

	resp, b := e.do(t, c, "GET", "/api/v1/health", "")
	var h map[string]any
	_ = json.Unmarshal(b, &h)
	if resp.StatusCode != 200 || h["status"] != "moved" || h["remote"] != remote.URL {
		t.Fatalf("health: %d %s", resp.StatusCode, b)
	}
	resp, b = e.do(t, c, "GET", "/api/v1/remote", "")
	var rm struct {
		URL        string `json:"url"`
		InstanceID string `json:"instance_id"`
		Reachable  bool   `json:"reachable"`
	}
	_ = json.Unmarshal(b, &rm)
	if resp.StatusCode != 200 || rm.URL != remote.URL || rm.InstanceID != "inst-9" || !rm.Reachable {
		t.Fatalf("remote: %d %s", resp.StatusCode, b)
	}
	remote.Close()
	_, b = e.do(t, c, "GET", "/api/v1/remote", "")
	if !strings.Contains(string(b), `"reachable":false`) {
		t.Fatalf("closed remote must be unreachable: %s", b)
	}
	// the SPA is served, everything else is refused
	if resp, b := e.do(t, c, "GET", "/", ""); resp.StatusCode != 200 || !strings.Contains(string(b), "spa") {
		t.Fatalf("spa: %d %s", resp.StatusCode, b)
	}
	if resp, b := e.do(t, c, "GET", "/some/route", ""); resp.StatusCode != 200 || !strings.Contains(string(b), "spa") {
		t.Fatalf("spa route: %d %s", resp.StatusCode, b)
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/jobs"}, {"GET", "/api/v1/setup"}, {"POST", "/api/v1/auth/login"}, {"POST", "/api/v1/targets"},
		{"POST", "/api/v1/selfinstall"}, {"DELETE", "/api/v1/targets/1"},
	} {
		resp, b := e.do(t, c, tc.method, tc.path, `{}`)
		if resp.StatusCode != 503 || !strings.Contains(string(b), remote.URL) {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, resp.StatusCode, b)
		}
	}
	if resp, _ := e.do(t, c, "POST", "/", `{}`); resp.StatusCode != 405 {
		t.Fatalf("POST to the SPA: %d", resp.StatusCode)
	}
}

// A running controller that moved (step 9) answers like a moved one.
func TestRunningControllerTurnsMoved(t *testing.T) {
	e := newSIEnv(t)
	e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody)
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/jobs", ""); resp.StatusCode != 200 {
		t.Fatal("before the switch")
	}
	e.gate.SetMoved(selfinstall.Remote{URL: "http://198.51.100.7", InstanceID: "i"})
	_, b := e.do(t, e.client, "GET", "/api/v1/health", "")
	if !strings.Contains(string(b), `"status":"moved"`) {
		t.Fatalf("health: %s", b)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/jobs", ""); resp.StatusCode != 503 {
		t.Fatalf("jobs after the switch: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/jobs/demo", ""); resp.StatusCode != 503 {
		t.Fatalf("POST after the switch: %d", resp.StatusCode)
	}
}
