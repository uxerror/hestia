package api_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const apiAGPassword = "api-adguard-Passw0rd"

// agDouble is a minimal AdGuard Home plus its DNS server.
type agDouble struct {
	srv  *httptest.Server
	dns  net.PacketConn
	mu   sync.Mutex
	list []map[string]any
	// seen collects everything AdGuard received, to look for secrets in.
	hits int
}

func newAGDouble(t *testing.T) *agDouble {
	a := &agDouble{}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a.dns = conn
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			off := 12
			var labels []string
			for q[off] != 0 {
				l := int(q[off])
				labels = append(labels, string(q[off+1:off+1+l]))
				off += 1 + l
			}
			r := append([]byte(nil), q[:off+5]...)
			r[2], r[3] = 0x81, 0x80
			var ans []string
			a.mu.Lock()
			for _, x := range a.list {
				if x["domain"] == strings.Join(labels, ".") {
					ans = append(ans, x["answer"].(string))
				}
			}
			a.mu.Unlock()
			if len(ans) == 0 {
				r[3] = 0x83
			}
			binary.BigEndian.PutUint16(r[6:], uint16(len(ans)))
			for _, s := range ans {
				r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				r = append(r, net.ParseIP(s).To4()...)
			}
			_, _ = conn.WriteTo(r, addr)
		}
	}()
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != apiAGPassword {
			http.Error(w, "Unauthorized", 401)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.hits++
		var body struct {
			Domain, Answer string
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.Method + " " + r.URL.Path {
		case "GET /control/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v0.107.79", "running": true,
				"dns_port": conn.LocalAddr().(*net.UDPAddr).Port, "dns_addresses": []string{"127.0.0.1"}})
		case "GET /control/rewrite/settings":
			_, _ = w.Write([]byte(`{"enabled":true}`))
		case "GET /control/rewrite/list":
			if a.list == nil {
				a.list = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(a.list)
		case "POST /control/rewrite/add":
			a.list = append(a.list, map[string]any{"domain": body.Domain, "answer": body.Answer, "enabled": true})
		case "POST /control/rewrite/delete":
			for i, x := range a.list {
				if x["domain"] == body.Domain && x["answer"] == body.Answer {
					a.list = append(a.list[:i], a.list[i+1:]...)
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() { a.srv.Close(); _ = conn.Close() })
	return a
}

func TestDNSEndpointsRequireAuth(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{
		{"GET", "/api/v1/dns"}, {"POST", "/api/v1/dns/adguard/probe"}, {"POST", "/api/v1/dns/adguard"},
		{"PUT", "/api/v1/dns/adguard"}, {"DELETE", "/api/v1/dns/adguard"}, {"POST", "/api/v1/dns/plan"},
		{"POST", "/api/v1/dns/apply"}, {"POST", "/api/v1/dns/check"},
	} {
		if resp, _ := e.do(t, e.client, c[0], c[1], `{}`); resp.StatusCode != 401 {
			t.Errorf("%s %s = %d", c[0], c[1], resp.StatusCode)
		}
	}
}

func TestDNSEmptyState(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	resp, b := e.do(t, e.client, "GET", "/api/v1/dns", "")
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var v struct {
		Candidates  []any `json:"candidates"`
		Integration any   `json:"integration"`
		Name        any   `json:"name"`
	}
	if json.Unmarshal(b, &v) != nil || v.Candidates == nil || len(v.Candidates) != 0 || v.Integration != nil || v.Name != nil {
		t.Fatalf("%s", b)
	}
	if !strings.Contains(string(b), `"candidates":[]`) || !strings.Contains(string(b), `"integration":null`) {
		t.Fatalf("%s", b)
	}
	// Health announces no name.
	_, b = e.do(t, e.client, "GET", "/api/v1/health", "")
	if strings.Contains(string(b), "dns_url") {
		t.Fatalf("%s", b)
	}
	// Plan without a connection.
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/dns/plan", `{"action":"add","domain":"hestia.home"}`); resp.StatusCode != 409 {
		t.Fatal(resp.StatusCode)
	}
}

// The whole way over HTTP, with the password searched for in every output.
func TestDNSFlowAndPasswordNeverLeaks(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	e := newEnv(t)
	e.login(t)
	ag := newAGDouble(t)
	var outputs []string
	call := func(method, path, body string, want int) []byte {
		t.Helper()
		resp, b := e.do(t, e.client, method, path, body)
		outputs = append(outputs, string(b))
		if resp.StatusCode != want {
			t.Fatalf("%s %s → %d, want %d: %s", method, path, resp.StatusCode, want, b)
		}
		return b
	}

	// Probe (no password).
	b := call("POST", "/api/v1/dns/adguard/probe", `{"url":"`+ag.srv.URL+`"}`, 200)
	if !strings.Contains(string(b), `"status_code":401`) || !strings.Contains(string(b), `"tls":null`) {
		t.Fatalf("%s", b)
	}
	call("POST", "/api/v1/dns/adguard/probe", `{"url":"nonsense"}`, 400)

	// A wrong password is a 400 with a code, never a 401 (that would sign the user out).
	b = call("POST", "/api/v1/dns/adguard", `{"url":"`+ag.srv.URL+`","username":"admin","password":"wrong-pass-123"}`, 400)
	if !strings.Contains(string(b), `"code":"auth_failed"`) {
		t.Fatalf("%s", b)
	}
	b = call("POST", "/api/v1/dns/adguard", `{"url":"`+ag.srv.URL+`","username":"admin","password":"`+apiAGPassword+`"}`, 201)
	if !strings.Contains(string(b), `"has_password":true`) || !strings.Contains(string(b), `"dns_port"`) {
		t.Fatalf("%s", b)
	}
	call("POST", "/api/v1/dns/adguard", `{"url":"`+ag.srv.URL+`","username":"admin","password":"`+apiAGPassword+`"}`, 409)

	b = call("GET", "/api/v1/dns", "", 200)
	if !strings.Contains(string(b), `"has_password":true`) || !strings.Contains(string(b), `"name":null`) || !strings.Contains(string(b), `"default_domain":"hestia.home"`) {
		t.Fatalf("%s", b)
	}

	// Plan → apply → job → name.
	b = call("POST", "/api/v1/dns/plan", `{"action":"add","domain":"hestia.home"}`, 200)
	var plan struct {
		PlanID string `json:"plan_id"`
		Hash   string `json:"hash"`
		Answer string `json:"answer"`
	}
	if json.Unmarshal(b, &plan) != nil || plan.PlanID == "" || plan.Answer != "127.0.0.1" {
		t.Fatalf("%s", b)
	}
	call("POST", "/api/v1/dns/apply", `{"plan_id":"`+plan.PlanID+`","hash":"bad"}`, 400)
	b = call("POST", "/api/v1/dns/apply", `{"plan_id":"`+plan.PlanID+`","hash":"`+plan.Hash+`"}`, 202)
	var job struct {
		JobID string `json:"job_id"`
	}
	if json.Unmarshal(b, &job) != nil || job.JobID == "" {
		t.Fatalf("%s", b)
	}
	e.runner.Wait()
	b = call("GET", "/api/v1/jobs/"+job.JobID, "", 200)
	if !strings.Contains(string(b), `"status":"done"`) {
		t.Fatalf("%s", b)
	}
	call("GET", "/api/v1/jobs", "", 200)

	// The name is verified: health announces it, the list shows it.
	_, hb := e.do(t, e.client, "GET", "/api/v1/health", "")
	if !strings.Contains(string(hb), `"dns_url":"http://hestia.home"`) {
		t.Fatalf("%s", hb)
	}
	b = call("GET", "/api/v1/dns", "", 200)
	if !strings.Contains(string(b), `"domain":"hestia.home"`) || !strings.Contains(string(b), `"status":"ok"`) {
		t.Fatalf("%s", b)
	}
	b = call("POST", "/api/v1/dns/check", "", 200)
	if !strings.Contains(string(b), `"status":"ok"`) {
		t.Fatalf("%s", b)
	}

	// The record goes missing: status changes, health stops announcing the name.
	ag.mu.Lock()
	ag.list = nil
	ag.mu.Unlock()
	b = call("POST", "/api/v1/dns/check", "", 200)
	if !strings.Contains(string(b), `"status":"missing"`) {
		t.Fatalf("%s", b)
	}
	_, hb = e.do(t, e.client, "GET", "/api/v1/health", "")
	if strings.Contains(string(hb), "dns_url") {
		t.Fatalf("a broken name must not be announced: %s", hb)
	}

	// Remove and disconnect.
	b = call("POST", "/api/v1/dns/plan", `{"action":"remove"}`, 200)
	_ = json.Unmarshal(b, &plan)
	call("POST", "/api/v1/dns/apply", `{"plan_id":"`+plan.PlanID+`","hash":"`+plan.Hash+`"}`, 202)
	e.runner.Wait()
	call("DELETE", "/api/v1/dns/adguard", "", 204)
	call("DELETE", "/api/v1/dns/adguard", "", 409)

	// Nowhere is the password: not in answers, jobs, logs or the database.
	jobs, _ := e.store.ListJobs(context.Background(), 50)
	for _, j := range jobs {
		full, _ := e.store.GetJob(context.Background(), j.ID)
		out, _ := json.Marshal(full)
		outputs = append(outputs, string(out))
	}
	outputs = append(outputs, logs.String())
	for i, o := range outputs {
		if strings.Contains(o, apiAGPassword) || strings.Contains(o, "wrong-pass-123") {
			t.Fatalf("a password leaked in output %d: %.300s", i, o)
		}
	}
	var n int
	_ = e.store.DB().QueryRow(`SELECT COUNT(*) FROM secrets WHERE purpose LIKE 'adguard:%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("secret left after disconnect: %d", n)
	}
}
