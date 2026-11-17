package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"hestia/internal/sshx/sshxtest"
	"hestia/internal/store"
)

func TestInventoryEndpointsRequireAuth(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{
		{"GET", "/api/v1/inventory"}, {"GET", "/api/v1/inventory/1"}, {"POST", "/api/v1/inventory/1/refresh"},
		{"GET", "/api/v1/inventory/events"}, {"GET", "/api/v1/inventory/1/role-fix"}, {"POST", "/api/v1/inventory/1/role-fix"},
	} {
		if resp, _ := e.do(t, e.client, c[0], c[1], `{}`); resp.StatusCode != 401 {
			t.Errorf("%s %s = %d", c[0], c[1], resp.StatusCode)
		}
	}
}

func facts(user, cmd string, stdin []byte) (string, string, int) {
	switch cmd {
	case "uname -srm":
		return "Linux 6.1.0 x86_64\n", "", 0
	case "hostname":
		return "mini\n", "", 0
	case "nproc":
		return "2\n", "", 0
	case "id -u":
		return "0\n", "", 0
	}
	return "", "", 1
}

func TestInventoryLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	if _, b := e.do(t, e.client, "GET", "/api/v1/inventory", ""); strings.TrimSpace(string(b)) != `{"inventory":[]}` {
		t.Fatalf("%s", b)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/inventory/42", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/inventory/42/refresh", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}

	srv := sshxtest.New(t)
	srv.KeyAuth = func(string, ssh.PublicKey) bool { return true }
	srv.Handler = facts
	tg := store.Target{Kind: store.KindSSH, Name: "mini", Host: srv.Host, Port: srv.Port, SSHUser: "root", HostKeyFP: srv.HostKeyFP()}
	if err := e.store.CreateTarget(context.Background(), &tg); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/inventory/" + itoa(int(tg.ID))

	// Nothing collected yet.
	_, b := e.do(t, e.client, "GET", path, "")
	var ent struct {
		TargetID   int64 `json:"target_id"`
		Snapshot   *struct{ Kind string }
		Collecting bool
		Error      string
	}
	_ = json.Unmarshal(b, &ent)
	if ent.TargetID != tg.ID || ent.Snapshot != nil || strings.Contains(string(b), `"snapshot":{`) {
		t.Fatalf("%s", b)
	}

	// Subscribe, then refresh: the stream carries the entry.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/api/v1/inventory/events", nil)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)

	resp2, b := e.do(t, e.client, "POST", path+"/refresh", "")
	if resp2.StatusCode != 202 {
		t.Fatalf("%d %s", resp2.StatusCode, b)
	}
	var jr struct{ Job struct{ ID string } }
	_ = json.Unmarshal(b, &jr)
	waitJobDone(t, e, jr.Job.ID)

	got := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"collecting":false`) && strings.Contains(line, `"kind":"ssh"`) {
			got = true
			break
		}
	}
	if !got {
		t.Fatal("no snapshot event with the finished entry")
	}
	cancel()

	_, b = e.do(t, e.client, "GET", path, "")
	if !strings.Contains(string(b), `"hostname"`) && !strings.Contains(string(b), `"name":"mini"`) {
		t.Fatalf("%s", b)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/inventory", "")
	if !strings.Contains(string(b), `"age_seconds"`) || !strings.Contains(string(b), `"collected_at"`) {
		t.Fatalf("%s", b)
	}

	// Role fix: SSH servers have no role; a confirmation is mandatory.
	if resp, _ := e.do(t, e.client, "GET", path+"/role-fix", ""); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", path+"/role-fix", `{}`); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/inventory/42/role-fix", `{"confirm":true}`); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "POST", path+"/role-fix", `{"confirm":true}`); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
}
