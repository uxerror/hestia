package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/uxerror/hestia/internal/api"
	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/dnsname"
	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/netscan"
	"github.com/uxerror/hestia/internal/onboard"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/store"
)

type env struct {
	srv    *httptest.Server
	client *http.Client
	runner *jobs.Runner
	store  *store.Store
	net    *netscan.Manager
	dns    *dnsname.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
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
	ob := (&onboard.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init()
	inv := (&inventory.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init()
	// The scanner never touches a network: every connect fails at once.
	nm := (&netscan.Manager{Store: st, Runner: runner, Inventory: inv, Version: "test",
		Scanner: &netscan.Scanner{Dialer: noNet{}}}).Init()
	dns := (&dnsname.Service{Store: st, Secrets: sec, Runner: runner, Hosts: nm, InstanceID: "inst-test",
		DNSAttempts: 2, DNSPause: time.Millisecond}).Init()
	h := api.New(api.Config{
		Store: st, Auth: auth.New(st), Runner: runner, Onboard: ob, Inventory: inv, Netscan: nm, DNS: dns, InstanceID: "inst-test", Identity: id, Mode: "serve", Version: "test",
		Web: fstest.MapFS{
			"index.html":    {Data: []byte("<html>spa</html>")},
			"assets/app.js": {Data: []byte("console.log(1)")},
		},
	})
	srv := httptest.NewServer(h)
	if u, err := url.Parse(srv.URL); err == nil {
		dns.HealthPort, _ = strconv.Atoi(u.Port()) // the name is checked against this very server
	}
	jar, _ := cookiejar.New(nil)
	t.Cleanup(func() { srv.Close(); runner.Shutdown(); _ = st.Close() })
	return &env{srv: srv, client: &http.Client{Jar: jar}, runner: runner, store: st, net: nm, dns: dns}
}

// noNet is a Dialer on which nothing is reachable: every connect fails after
// a short wait (long enough for tests to catch a scan while it runs).
type noNet struct{}

func (noNet) DialContext(ctx context.Context, _ netip.Addr, _ int) (net.Conn, error) {
	select {
	case <-time.After(30 * time.Millisecond):
	case <-ctx.Done():
	}
	return nil, errors.New("no route to host")
}

func (e *env) do(t *testing.T, c *http.Client, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

const adminBody = `{"username":"admin","password":"correct horse"}`

func TestHealthAndSetupStatus(t *testing.T) {
	e := newEnv(t)
	resp, b := e.do(t, e.client, "GET", "/api/v1/health", "")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"status":"ok"`) || !strings.Contains(string(b), `"version":"test"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/setup", "")
	if !strings.Contains(string(b), `"needs_admin":true`) || !strings.Contains(string(b), `"mode":"serve"`) {
		t.Fatalf("%s", b)
	}
}

func TestSetupValidation(t *testing.T) {
	e := newEnv(t)
	for _, body := range []string{
		`{"username":"admin","password":"short"}`,
		`{"username":"Admin","password":"correct horse"}`,
		`{"username":"a","password":"correct horse"}`,
		`not json`,
	} {
		resp, b := e.do(t, e.client, "POST", "/api/v1/setup/admin", body)
		if resp.StatusCode != 400 || !strings.Contains(string(b), `"error"`) {
			t.Errorf("%s -> %d %s", body, resp.StatusCode, b)
		}
	}
}

func TestFirstAdminRace(t *testing.T) {
	e := newEnv(t)
	const n = 8
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := e.do(t, &http.Client{}, "POST", "/api/v1/setup/admin", adminBody)
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for c := range codes {
		got[c]++
	}
	if got[201] != 1 || got[409] != n-1 {
		t.Fatalf("status counts = %v", got)
	}
	if c, _ := e.store.CountUsers(context.Background()); c != 1 {
		t.Fatalf("users = %d", c)
	}
}

func TestSetupLoginLogoutMe(t *testing.T) {
	e := newEnv(t)

	if resp, _ := e.do(t, e.client, "GET", "/api/v1/auth/me", ""); resp.StatusCode != 401 {
		t.Fatalf("me before login = %d", resp.StatusCode)
	}

	resp, b := e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody)
	if resp.StatusCode != 201 || !strings.Contains(string(b), `"username":"admin"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "hestia_session" {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", ck)
	}
	// Only the sha256 of the token may be stored.
	var raw int
	_ = e.store.DB().QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, ck.Value).Scan(&raw)
	if raw != 0 {
		t.Fatal("raw token stored in DB")
	}

	_, b = e.do(t, e.client, "GET", "/api/v1/setup", "")
	if !strings.Contains(string(b), `"needs_admin":false`) {
		t.Fatalf("%s", b)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody); resp.StatusCode != 409 {
		t.Fatalf("second setup = %d", resp.StatusCode)
	}
	resp, b = e.do(t, e.client, "GET", "/api/v1/auth/me", "")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"admin"`) {
		t.Fatalf("me = %d %s", resp.StatusCode, b)
	}

	if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/logout", ""); resp.StatusCode != 204 {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/auth/me", ""); resp.StatusCode != 401 {
		t.Fatalf("me after logout = %d", resp.StatusCode)
	}

	// Login: wrong password, unknown user, then success.
	for _, body := range []string{
		`{"username":"admin","password":"wrong password"}`,
		`{"username":"nobody","password":"correct horse"}`,
	} {
		if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/login", body); resp.StatusCode != 401 {
			t.Fatalf("bad login %s = %d", body, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/auth/login", adminBody); resp.StatusCode != 200 {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/auth/me", ""); resp.StatusCode != 200 {
		t.Fatalf("me after login = %d", resp.StatusCode)
	}
}

func TestAuthMiddleware401(t *testing.T) {
	e := newEnv(t)
	anon := &http.Client{}
	for _, rt := range [][2]string{
		{"POST", "/api/v1/auth/logout"}, {"GET", "/api/v1/auth/me"}, {"GET", "/api/v1/jobs"},
		{"GET", "/api/v1/jobs/x"}, {"GET", "/api/v1/jobs/x/events"}, {"POST", "/api/v1/jobs/demo"},
	} {
		resp, b := e.do(t, anon, rt[0], rt[1], "")
		if resp.StatusCode != 401 || !strings.Contains(string(b), `"error"`) {
			t.Errorf("%v -> %d %s", rt, resp.StatusCode, b)
		}
	}
	// A forged cookie is rejected too.
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "hestia_session", Value: "forged"})
	resp, _ := anon.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("forged = %d", resp.StatusCode)
	}
}

func TestSPAFallback(t *testing.T) {
	e := newEnv(t)
	for path, want := range map[string]string{
		"/": "spa", "/jobs/12": "spa", "/assets/app.js": "console.log", "/missing.png": "spa",
	} {
		resp, b := e.do(t, e.client, "GET", path, "")
		if resp.StatusCode != 200 || !strings.Contains(string(b), want) {
			t.Errorf("%s -> %d %s", path, resp.StatusCode, b)
		}
	}
	resp, b := e.do(t, e.client, "GET", "/api/v1/nope", "")
	if resp.StatusCode != 404 || !strings.Contains(string(b), `"error"`) {
		t.Errorf("unknown api -> %d %s", resp.StatusCode, b)
	}
}

func login(t *testing.T, e *env) {
	t.Helper()
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody); resp.StatusCode != 201 {
		t.Fatalf("setup = %d", resp.StatusCode)
	}
}

type sseEvent struct{ name, data string }

func readSSE(t *testing.T, resp *http.Response) []sseEvent {
	t.Helper()
	var evs []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.name = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.data = line[6:]
		case line == "" && cur.name != "":
			evs = append(evs, cur)
			cur = sseEvent{}
		}
	}
	return evs
}

func TestDemoJobAndSSE(t *testing.T) {
	e := newEnv(t)
	login(t, e)

	resp, b := e.do(t, e.client, "POST", "/api/v1/jobs/demo", "")
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var created struct{ Job store.Job }
	if err := json.Unmarshal(b, &created); err != nil || created.Job.ID == "" {
		t.Fatalf("%v %s", err, b)
	}
	id := created.Job.ID

	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/jobs/"+id+"/events", nil)
	sse, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sse.Body.Close()
	if ct := sse.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}
	done := make(chan []sseEvent, 1)
	go func() { done <- readSSE(t, sse) }()
	var evs []sseEvent
	select {
	case evs = <-done: // the stream must close itself after the final status
	case <-time.After(15 * time.Second):
		t.Fatal("SSE did not close after final status")
	}

	if len(evs) < 2 || evs[0].name != "snapshot" {
		t.Fatalf("events = %+v", evs)
	}
	last := evs[len(evs)-1]
	if last.name != "status" || !strings.Contains(last.data, `"status":"done"`) {
		t.Fatalf("last = %+v", last)
	}
	kinds := map[string]bool{}
	for _, ev := range evs {
		kinds[ev.name] = true
	}
	if !kinds["step"] || !kinds["log"] {
		t.Fatalf("kinds = %v", kinds)
	}

	// Persisted state via REST.
	_, b = e.do(t, e.client, "GET", "/api/v1/jobs/"+id, "")
	var got struct{ Job store.Job }
	_ = json.Unmarshal(b, &got)
	if got.Job.Status != "done" || len(got.Job.Steps) != 3 || len(got.Job.Log) == 0 {
		t.Fatalf("job = %+v", got.Job)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/jobs", "")
	if !strings.Contains(string(b), id) {
		t.Fatalf("list = %s", b)
	}

	// A finished job: snapshot, then the stream closes immediately.
	sse2, err := e.client.Get(e.srv.URL + "/api/v1/jobs/" + id + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer sse2.Body.Close()
	if evs := readSSE(t, sse2); len(evs) != 1 || evs[0].name != "snapshot" {
		t.Fatalf("finished-job events = %+v", evs)
	}

	if resp, _ := e.do(t, e.client, "GET", "/api/v1/jobs/unknown", ""); resp.StatusCode != 404 {
		t.Fatalf("unknown job = %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/jobs/unknown/events", ""); resp.StatusCode != 404 {
		t.Fatalf("unknown job events = %d", resp.StatusCode)
	}
}
