package proxmox_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hestia/internal/proxmox"
)

// Real outputs of PVE 9.2 (`pvesh … --output-format json`), see testdata.
func siFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "real-pve9-selfinstall", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNetHWAddrFromRealConfig(t *testing.T) {
	var cfg map[string]any
	if err := json.Unmarshal(siFixture(t, "lxc-config-127.json"), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := proxmox.NetHWAddr(cfg["net0"].(string)); got != "BC:24:11:BC:4C:F6" {
		t.Fatalf("MAC = %q", got)
	}
	if proxmox.NetHWAddr("name=eth0,bridge=vmbr0,ip=dhcp") != "" {
		t.Fatal("MAC without hwaddr")
	}
}

func TestIfaceIPv4FromRealInterfaces(t *testing.T) {
	var ifs []proxmox.Iface
	if err := json.Unmarshal(siFixture(t, "lxc-interfaces-127.json"), &ifs); err != nil {
		t.Fatal(err)
	}
	if got := proxmox.IfaceIPv4(ifs, "eth0"); got != "10.10.10.33" {
		t.Fatalf("IP = %q", got)
	}
	if proxmox.IfaceIPv4(ifs, "eth9") != "" {
		t.Fatal("unknown interface")
	}
}

func TestTaskFromRealStatus(t *testing.T) {
	var tk proxmox.Task
	if err := json.Unmarshal(siFixture(t, "task-status-ok.json"), &tk); err != nil {
		t.Fatal(err)
	}
	if !tk.OK() || tk.Running() || tk.Type != "qmdestroy" {
		t.Fatalf("task: %+v", tk)
	}
	var lines []proxmox.TaskLine
	if err := json.Unmarshal(siFixture(t, "task-log.json"), &lines); err != nil || len(lines) != 4 || lines[3].T != "TASK OK" {
		t.Fatalf("log: %+v %v", lines, err)
	}
	if (proxmox.Task{Status: "running"}).OK() || (proxmox.Task{Status: "stopped", ExitStatus: "boom"}).OK() {
		t.Fatal("OK()")
	}
	if !(proxmox.Task{Status: "stopped", ExitStatus: "WARNINGS: 1"}).OK() {
		t.Fatal("warnings are not failures")
	}
}

type recorded struct {
	method, path, query string
	form                url.Values
	auth, ctype         string
}

// writeServer records requests and answers with the given bodies.
func writeServer(t *testing.T, answer func(r *recorded) (int, string)) (*proxmox.Client, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var seen []recorded
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rec := recorded{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, form: r.PostForm,
			auth: r.Header.Get("Authorization"), ctype: r.Header.Get("Content-Type")}
		mu.Lock()
		seen = append(seen, rec)
		mu.Unlock()
		code, body := answer(&rec)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	fp, err := proxmox.FetchCertFP(context.Background(), h, port)
	if err != nil {
		t.Fatal(err)
	}
	return proxmox.NewClient(proxmox.ClientConfig{Host: h, Port: port, TokenID: proxmox.TokenID, Secret: "s3cret", PinFP: fp}), &seen
}

func TestWriteRequests(t *testing.T) {
	c, seen := writeServer(t, func(r *recorded) (int, string) { return 200, `{"data":"UPID:pve1:1:2:3:x:900:u:"}` })
	ctx := context.Background()
	form := url.Values{"vmid": {"900"}, "net0": {"name=eth0,bridge=vmbr0,ip=dhcp"}}
	if up, err := c.CreateLXC(ctx, "pve1", form); err != nil || !strings.HasPrefix(up, "UPID:") {
		t.Fatalf("create: %q %v", up, err)
	}
	_, _ = c.StartLXC(ctx, "pve1", 900)
	_, _ = c.StopLXC(ctx, "pve1", 900)
	_, _ = c.DeleteLXC(ctx, "pve1", 900)
	_, _ = c.DownloadTemplate(ctx, "pve1", "local", "debian-13-standard_13.6-1_amd64.tar.zst")
	_, _ = c.DeleteVolume(ctx, "pve1", "local", "local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst")
	want := []struct{ method, path string }{
		{"POST", "/api2/json/nodes/pve1/lxc"},
		{"POST", "/api2/json/nodes/pve1/lxc/900/status/start"},
		{"POST", "/api2/json/nodes/pve1/lxc/900/status/stop"},
		{"DELETE", "/api2/json/nodes/pve1/lxc/900"},
		{"POST", "/api2/json/nodes/pve1/aplinfo"},
		{"DELETE", "/api2/json/nodes/pve1/storage/local/content/local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst"},
	}
	if len(*seen) != len(want) {
		t.Fatalf("requests: %d", len(*seen))
	}
	for i, w := range want {
		g := (*seen)[i]
		if g.method != w.method || g.path != w.path {
			t.Errorf("#%d: %s %s, want %s %s", i, g.method, g.path, w.method, w.path)
		}
		if g.auth != "PVEAPIToken=hestia@pve!hestia=s3cret" {
			t.Errorf("#%d: auth header %q", i, g.auth)
		}
	}
	if (*seen)[0].form.Get("net0") != "name=eth0,bridge=vmbr0,ip=dhcp" || !strings.HasPrefix((*seen)[0].ctype, "application/x-www-form-urlencoded") {
		t.Fatalf("create body: %+v", (*seen)[0])
	}
	q, _ := url.ParseQuery((*seen)[3].query)
	if q.Get("purge") != "1" || q.Get("destroy-unreferenced-disks") != "1" {
		t.Fatalf("delete query: %v", q)
	}
	if (*seen)[4].form.Get("storage") != "local" || (*seen)[4].form.Get("template") == "" {
		t.Fatalf("download body: %+v", (*seen)[4].form)
	}
}

func TestWaitTask(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	c, _ := writeServer(t, func(r *recorded) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.path, "/status"):
			polls++
			if polls < 3 {
				return 200, `{"data":{"status":"running"}}`
			}
			return 200, string(siFixtureWrap("task-status-ok.json"))
		case strings.HasSuffix(r.path, "/log"):
			return 200, string(siFixtureWrap("task-log.json"))
		}
		return 404, ""
	})
	var lines []string
	err := c.WaitTask(context.Background(), "pve1", "UPID:pve1:0027D056:126F7C79:6AFC6FFA:qmdestroy:126:root@pam:", time.Millisecond,
		func(l string) { lines = append(lines, l) })
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 4 || lines[3] != "TASK OK" || polls != 3 {
		t.Fatalf("lines %v polls %d", lines, polls)
	}
}

func siFixtureWrap(name string) []byte {
	b, _ := os.ReadFile(filepath.Join("testdata", "real-pve9-selfinstall", name))
	return append(append([]byte(`{"data":`), b...), '}')
}

func TestWaitTaskFailureAndCancel(t *testing.T) {
	c, _ := writeServer(t, func(r *recorded) (int, string) {
		if strings.HasSuffix(r.path, "/status") {
			return 200, `{"data":{"status":"stopped","exitstatus":"startup failed"}}`
		}
		return 200, `{"data":[{"n":1,"t":"TASK ERROR: startup failed"}]}`
	})
	err := c.WaitTask(context.Background(), "pve1", "UPID:x", time.Millisecond, nil)
	var tf *proxmox.TaskFailed
	if !errors.As(err, &tf) || tf.Exit != "startup failed" || !strings.Contains(err.Error(), "TASK ERROR") {
		t.Fatalf("err = %v", err)
	}
	c2, _ := writeServer(t, func(r *recorded) (int, string) { return 200, `{"data":{"status":"running"}}` })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := c2.WaitTask(ctx, "pve1", "UPID:x", time.Millisecond, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	// an API error (task unknown) ends the wait at once
	c3, _ := writeServer(t, func(r *recorded) (int, string) { return 500, `{"data":null,"message":"no such task"}` })
	var ae *proxmox.APIError
	if err := c3.WaitTask(context.Background(), "pve1", "UPID:x", time.Millisecond, nil); !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
}

func TestLXCConfigAndStatus(t *testing.T) {
	c, _ := writeServer(t, func(r *recorded) (int, string) {
		if strings.HasSuffix(r.path, "/config") {
			return 200, string(siFixtureWrap("lxc-config-127.json"))
		}
		return 200, string(siFixtureWrap("lxc-status-127.json"))
	})
	cfg, err := c.LXCConfig(context.Background(), "pve1", 127)
	if err != nil || cfg["net0"] == "" || cfg["cores"] != "2" || cfg["unprivileged"] != "1" {
		t.Fatalf("%v %v", cfg, err)
	}
	if st, err := c.LXCStatus(context.Background(), "pve1", 127); err != nil || st != "running" {
		t.Fatalf("%q %v", st, err)
	}
}
