package api_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type stepResp struct {
	Kind, Action, Title, Rollback string
}

type compResp struct {
	planResp
	Steps []stepResp `json:"steps"`
}

// E2E in dev mode with both demo plugins: probe with a new hello in one
// composite plan, a link hello → device (/etc/hosts of a second fake
// target), statuses, the graph, and the removal of hello with its links.
func TestLinksDevEndToEnd(t *testing.T) {
	e := newPluginEnv(t, "hestia-probe")
	login(t, e.env)
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, b := e.do(t, e.client, "GET", "/api/v1/plugins", "")
		if strings.Count(string(b), `"state":"connected"`) == 2 && strings.Contains(string(b), `"id":"hestia-probe"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dev plugins not registered: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}

	who := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hostname: test\nName: Привет от Hestia\n")
	}))
	defer who.Close()
	_, port, _ := net.SplitHostPort(who.Listener.Addr().String())
	e.tg.Set("port", port)
	e.tg.Set("service", "whoami")

	// A new hello without a target: a validation error of that field.
	resp, b := e.do(t, e.client, "POST", "/api/v1/plugins/compose/plan",
		`{"root":{"plugin_id":"hestia-probe","config":{}},"deps":[{"port":"target","new":{"plugin_id":"hestia-hello","config":{}}}]}`)
	if resp.StatusCode != 422 || !strings.Contains(string(b), `"field":"deps[0].new.target"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	// Probe with a new hello, one plan.
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/compose/plan",
		`{"root":{"plugin_id":"hestia-probe","config":{"interval_s":30}},"deps":[{"port":"target","new":{"plugin_id":"hestia-hello","config":{"target":"`+e.ref+`","port":`+port+`}}}]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var cp compResp
	decode(t, b, &cp)
	if cp.Action != "compose" || len(cp.Steps) != 3 || cp.Steps[2].Kind != "link" || !strings.Contains(cp.Steps[0].Title, "Hestia Hello 1") {
		t.Fatalf("%s", b)
	}
	e.apply(t, cp.planResp)
	probeID := cp.Instance.ID

	_, b = e.do(t, e.client, "GET", fmt.Sprintf("/api/v1/plugins/instances/%d?status=refresh", probeID), "")
	var inst struct{ Status, Detail string }
	decode(t, b, &inst)
	if inst.Status != "ok" || !strings.HasPrefix(inst.Detail, "200, ") || !strings.HasSuffix(inst.Detail, "Name: Привет от Hestia") {
		t.Fatalf("probe %s", b)
	}

	// The graph: both instances, the service link, containers from deploy.up.
	_, b = e.do(t, e.client, "GET", "/api/v1/graph", "")
	var g struct {
		Instances []struct {
			ID         int64
			PluginID   string `json:"plugin_id"`
			HostRef    string `json:"host_ref"`
			Controller bool
			Containers []struct{ Name, State string }
		}
		Links []struct {
			ID     int64
			Kind   string
			Status string
		}
	}
	decode(t, b, &g)
	if len(g.Instances) != 2 || len(g.Links) != 1 || g.Links[0].Kind != "service" {
		t.Fatalf("%s", b)
	}
	var helloID int64
	for _, in := range g.Instances {
		switch in.PluginID {
		case "hestia-hello":
			helloID = in.ID
			if in.HostRef != e.ref || len(in.Containers) != 1 || in.Containers[0].State != "running" {
				t.Fatalf("hello %+v", in)
			}
		case "hestia-probe":
			if !in.Controller || in.HostRef != "" {
				t.Fatalf("probe %+v", in)
			}
		}
	}

	// Candidates of the client port list the device.
	_, b = e.do(t, e.client, "GET", fmt.Sprintf("/api/v1/plugins/links/candidates?instance=%d&port=web&dir=provides", helloID), "")
	if !strings.Contains(string(b), `"device":"`+e.devRef+`"`) {
		t.Fatalf("%s", b)
	}
	// hello → device: a line in /etc/hosts of the device.
	resp, b = e.do(t, e.client, "POST", "/api/v1/plugins/links/plan",
		fmt.Sprintf(`{"kind":"device","provider":{"instance":%d,"port":"web"},"device":{"ref":"%s"},"config":{}}`, helloID, e.devRef))
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var lp compResp
	decode(t, b, &lp)
	e.apply(t, lp.planResp)
	hosts, _ := e.dev.File("/etc/hosts")
	if !strings.HasPrefix(hosts, "127.0.0.1 localhost\n") || !strings.Contains(hosts, "127.0.0.1 hello.home # hestia-link-") {
		t.Fatalf("hosts %q", hosts)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/graph", "")
	decode(t, b, &g)
	if len(g.Links) != 2 {
		t.Fatalf("%s", b)
	}
	for _, l := range g.Links {
		_, b = e.do(t, e.client, "GET", fmt.Sprintf("/api/v1/plugins/links/%d?status=refresh", l.ID), "")
		var lv struct{ Status, Detail string }
		decode(t, b, &lv)
		if lv.Status != "ok" {
			t.Fatalf("link %s", b)
		}
	}
	if resp, _ := e.do(t, e.client, "PUT", "/api/v1/graph/positions", `{"positions":{"host:a":{"x":1,"y":2}}}`); resp.StatusCode != 204 {
		t.Fatalf("positions %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/graph/positions", ""); resp.StatusCode != 204 {
		t.Fatalf("positions reset %d", resp.StatusCode)
	}

	// Removing hello removes both links first.
	resp, b = e.do(t, e.client, "POST", fmt.Sprintf("/api/v1/plugins/instances/%d/plan", helloID), `{"action":"remove"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var rp compResp
	decode(t, b, &rp)
	if len(rp.Steps) != 3 || rp.Steps[2].Kind != "instance" {
		t.Fatalf("%s", b)
	}
	e.apply(t, rp.planResp)
	hosts, _ = e.dev.File("/etc/hosts")
	if hosts != "127.0.0.1 localhost\n" {
		t.Fatalf("hosts %q", hosts)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/graph", "")
	decode(t, b, &g)
	if len(g.Links) != 0 || len(g.Instances) != 1 {
		t.Fatalf("%s", b)
	}
	_, b = e.do(t, e.client, "GET", fmt.Sprintf("/api/v1/plugins/instances/%d?status=refresh", probeID), "")
	decode(t, b, &inst)
	if inst.Status != "degraded" || inst.Detail != "Не подключён к сервису" {
		t.Fatalf("probe after %s", b)
	}
	var raw json.RawMessage
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins", "")
	decode(t, b, &raw)
}
