package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
)

func TestNetworkEndpointsRequireAuth(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{
		{"GET", "/api/v1/network"}, {"POST", "/api/v1/network/scan"}, {"DELETE", "/api/v1/network/scan"},
		{"PUT", "/api/v1/network/settings"}, {"DELETE", "/api/v1/network/hosts/10.10.10.5"},
	} {
		if resp, _ := e.do(t, e.client, c[0], c[1], `{}`); resp.StatusCode != 401 {
			t.Errorf("%s %s = %d", c[0], c[1], resp.StatusCode)
		}
	}
}

type netView struct {
	LastScan   *struct{ ID int64 } `json:"last_scan"`
	NextScanAt *time.Time          `json:"next_scan_at"`
	Scanning   bool                `json:"scanning"`
	Interval   int                 `json:"interval_hours"`
	Subnets    []struct {
		CIDR   string `json:"cidr"`
		Source string `json:"source"`
		Error  string `json:"error"`
	} `json:"subnets"`
	Extra   []string `json:"extra_subnets"`
	Exclude []string `json:"exclude"`
	Hosts   []struct {
		IP    string `json:"ip"`
		Alive bool   `json:"alive"`
	} `json:"hosts"`
}

func TestNetworkSettingsScanAndForgetOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.login(t)

	// Empty network: no scan yet, but the next one is planned; lists are arrays, not null.
	resp, b := e.do(t, e.client, "GET", "/api/v1/network", "")
	var v netView
	if resp.StatusCode != 200 || json.Unmarshal(b, &v) != nil {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if v.LastScan != nil || v.NextScanAt == nil || v.Scanning || v.Interval != 6 || len(v.Hosts) != 0 {
		t.Fatalf("%s", b)
	}
	for _, f := range []string{`"subnets":[]`, `"exclude":[]`, `"extra_subnets":[]`, `"hosts":[]`} {
		if !strings.Contains(string(b), f) {
			t.Errorf("%s missing in %s", f, b)
		}
	}

	// Refused settings.
	for _, body := range []string{
		`{"extra_subnets":["10.10.0.0/16"]}`, `{"extra_subnets":["127.0.0.0/30"]}`, `{"extra_subnets":["169.254.1.0/24"]}`,
		`{"extra_subnets":["nope"]}`, `{"exclude":["10.10.10.300"]}`, `not json`,
	} {
		resp, b := e.do(t, e.client, "PUT", "/api/v1/network/settings", body)
		if resp.StatusCode != 400 || !strings.Contains(string(b), `"error"`) {
			t.Errorf("%s → %d %s", body, resp.StatusCode, b)
		}
	}
	resp, b = e.do(t, e.client, "PUT", "/api/v1/network/settings", `{"extra_subnets":["10.10.10.7/29"],"exclude":["10.10.10.2"]}`)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"10.10.10.0/29"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/network", "")
	v = netView{}
	_ = json.Unmarshal(b, &v)
	if len(v.Subnets) != 1 || v.Subnets[0].CIDR != "10.10.10.0/29" || v.Subnets[0].Source != "manual" || len(v.Exclude) != 1 || v.Exclude[0] != "10.10.10.2" || len(v.Extra) != 1 || v.Extra[0] != "10.10.10.0/29" {
		t.Fatalf("%s", b)
	}

	// A scan on an unreachable network: the job finishes, nothing is found.
	resp, b = e.do(t, e.client, "POST", "/api/v1/network/scan", "")
	var sc struct {
		Job struct{ ID string }
	}
	if resp.StatusCode != 202 || json.Unmarshal(b, &sc) != nil || sc.Job.ID == "" {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	e.runner.Wait()
	job, err := e.store.GetJob(context.Background(), sc.Job.ID)
	if err != nil || job.Status != store.JobDone || job.Kind != "netscan" {
		t.Fatalf("%+v %v", job, err)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/network", "")
	v = netView{}
	_ = json.Unmarshal(b, &v)
	if v.LastScan == nil || v.Scanning {
		t.Fatalf("%s", b)
	}

	// Nothing to cancel; unknown host.
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/network/scan", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/network/hosts/10.10.10.9", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if err := e.store.SaveScanHosts(context.Background(), 1, []store.NetHost{{IP: "10.10.10.9", FirstSeen: time.Now(), LastSeen: time.Now(), Source: "scan"}}); err != nil {
		t.Fatal(err)
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/network", "")
	if !strings.Contains(string(b), `"10.10.10.9"`) {
		t.Fatalf("%s", b)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/network/hosts/10.10.10.9", ""); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
}

func TestSecondScanWhileRunningIs409(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	e.do(t, e.client, "PUT", "/api/v1/network/settings", `{"extra_subnets":["10.10.10.0/24"]}`)
	// 254 addresses × the port list through a dialer that waits 20 ms: long enough to collide.
	resp, b := e.do(t, e.client, "POST", "/api/v1/network/scan", "")
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, b = e.do(t, e.client, "POST", "/api/v1/network/scan", "")
	if resp.StatusCode != 409 || !strings.Contains(string(b), `"job"`) {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/network/scan", ""); resp.StatusCode != 204 {
		t.Fatalf("cancel: %d", resp.StatusCode)
	}
	e.runner.Wait()
}
