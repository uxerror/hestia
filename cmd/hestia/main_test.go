package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/selfinstall"
)

// A data directory with remote.json starts in "moved" mode: the database is
// never opened (no hestia.db appears) and only the redirect screen is served.
func TestMovedModeDoesNotOpenDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := selfinstall.WriteRemote(dir, selfinstall.Remote{URL: "http://198.51.100.7", InstanceID: "abc",
		Location: selfinstall.Location{Kind: "lxc", IP: "198.51.100.7"}}); err != nil {
		t.Fatal(err)
	}
	a, err := newApp(context.Background(), dir, "serve", "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	if a.remote == nil || a.store != nil {
		t.Fatalf("moved app: remote=%v store=%v", a.remote, a.store)
	}
	srv := httptest.NewServer(a.handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), `"status":"moved"`) {
		t.Fatalf("health: %s", buf[:n])
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != selfinstall.RemoteFile {
			t.Fatalf("moved mode touched the data directory: %s", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "hestia.db")); !os.IsNotExist(err) {
		t.Fatal("hestia.db was created")
	}
}

func TestNormalStartCreatesInstanceID(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(context.Background(), dir, "serve", "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	srv := httptest.NewServer(a.handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), `"instance_id":"`) {
		t.Fatalf("health: %s", buf[:n])
	}
}

func TestHealthcheckCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","version":"v0.2.0"}`))
	}))
	defer srv.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"starting","version":"v0.2.0"}`))
	}))
	defer bad.Close()
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"--url", srv.URL}, 0},
		{[]string{"--url", srv.URL, "--version", "v0.2.0"}, 0},
		{[]string{"--url", srv.URL, "--version", "v0.3.0"}, 1},
		{[]string{"--url", bad.URL}, 1},
		{[]string{"--url", "http://127.0.0.1:1", "--timeout", "200ms"}, 1},
	} {
		if got := run(append([]string{"healthcheck"}, c.args...)); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, got, c.want)
		}
	}
}
