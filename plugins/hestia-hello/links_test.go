package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/sdktest"
	"github.com/uxerror/hestia/sdk/types"
)

// fakeDevice runs target.exec of a device locally: /etc/hosts is a file
// under a temporary root and PATH holds only links to a few tools and a
// fake getent (nothing of the real system is touched).
type fakeDevice struct {
	t     *testing.T
	root  string
	bin   string
	mu    sync.Mutex
	cmds  []string
	hosts string
}

func newDevice(t *testing.T, h *sdktest.Host) *fakeDevice {
	dir := t.TempDir()
	d := &fakeDevice{t: t, root: filepath.Join(dir, "root"), bin: filepath.Join(dir, "bin")}
	for _, p := range []string{d.root + "/etc", d.bin} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sh", "cat", "cp", "mv", "rm", "grep", "mktemp", "printf", "echo", "true"} {
		if p, err := exec.LookPath(name); err == nil {
			if err := os.Symlink(p, filepath.Join(d.bin, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	getent := `#!/bin/sh
[ "$1" = hosts ] || exit 2
while read -r ip rest; do
  for n in $rest; do [ "$n" = "#" ] && break; [ "$n" = "$2" ] && { echo "$ip       $2"; exit 0; }; done
done < "$HOSTS"
exit 2
`
	if err := os.WriteFile(filepath.Join(d.bin, "getent"), []byte(getent), 0o755); err != nil {
		t.Fatal(err)
	}
	d.hosts = d.root + "/etc/hosts"
	if err := os.WriteFile(d.hosts, []byte("127.0.0.1 localhost\n10.10.10.9 other.home # hestia-link-12\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	h.OnExec(func(r sdk.ExecRequest) (sdk.ExecResult, error) {
		d.mu.Lock()
		d.cmds = append(d.cmds, r.Target+" "+r.Cmd)
		d.mu.Unlock()
		if r.Target != "ssh:9" {
			return sdk.ExecResult{Code: 1, Stderr: "not the device"}, nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, filepath.Join(d.bin, "sh"), "-c", strings.ReplaceAll(r.Cmd, "/etc/hosts", d.hosts))
		c.Env = []string{"PATH=" + d.bin, "HOSTS=" + d.hosts, "LC_ALL=C"}
		var out, errb bytes.Buffer
		c.Stdout, c.Stderr = &out, &errb
		err := c.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			return sdk.ExecResult{}, err
		}
		return sdk.ExecResult{Code: code, Stdout: out.String(), Stderr: errb.String()}, nil
	})
	return d
}

func (d *fakeDevice) read() string {
	b, err := os.ReadFile(d.hosts)
	if err != nil {
		d.t.Fatal(err)
	}
	return string(b)
}

func TestLinkProvider(t *testing.T) {
	h, _, _ := newHost(t)
	ctx := context.Background()
	srv, port := whoami(t)
	inst := sdk.Instance{ID: 7, Name: "Hello 1", Config: cfg("ssh:1", port, "Привет")}
	req := sdk.LinkRequest{Link: 4, Kind: sdk.LinkService, Role: sdk.RoleProvider, Action: sdk.ActionCreate, Instance: inst, Port: "web",
		Type: "http.service", Peer: &sdk.LinkPeer{Plugin: "hestia-probe", Instance: 8, Name: "Probe 1", Port: "target"}}
	pl, err := h.LinkPlan(ctx, req)
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	if err != nil || len(pl.Actions) != 1 || !strings.Contains(pl.Actions[0].Title, url) || !strings.Contains(pl.Actions[0].Title, "Probe 1") {
		t.Fatalf("%+v %v", pl, err)
	}
	raw, err := h.LinkApply(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := types.Validate(types.HTTPServiceType, raw, false); err != nil {
		t.Fatalf("binding %s: %v", raw, err)
	}
	var b types.HTTPService
	_ = json.Unmarshal(raw, &b)
	if b.URL != url || b.Host != "127.0.0.1" || b.Port != int(port) || b.Scheme != "http" {
		t.Fatalf("%+v", b)
	}
	if st, err := h.LinkStatus(ctx, req); err != nil || st.State != sdk.StateOK {
		t.Fatalf("%+v %v", st, err)
	}
	// A new port: link.refresh gives the new binding.
	inst.Config = cfg("ssh:1", port+1, "Привет")
	req.Instance = inst
	raw, err = h.LinkRefresh(ctx, req)
	if err != nil || !strings.Contains(string(raw), fmt.Sprintf(":%d/", port+1)) {
		t.Fatalf("%s %v", raw, err)
	}
	if err := h.LinkRemove(ctx, req); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if st, _ := h.LinkStatus(ctx, req); st.State != sdk.StateDown {
		t.Fatalf("%+v", st)
	}
	// Without an address there is no binding.
	req.Instance = sdk.Instance{ID: 9, Name: "x", Config: cfg("lxc:3:pve:105", 8080, "hi")}
	if _, err := h.LinkApply(ctx, req); err == nil || !strings.Contains(err.Error(), "нет известного адреса") {
		t.Fatalf("%v", err)
	}
}

func TestLinkClientHosts(t *testing.T) {
	h, f, _ := newHost(t)
	d := newDevice(t, h)
	ctx := context.Background()
	inst := sdk.Instance{ID: 7, Name: "Hello 1", Config: cfg("ssh:1", 8080, "Привет")}
	dev := &sdk.TargetInfo{ID: "ssh:9", Kind: "ssh", Name: "nas", Address: "10.10.10.30"}
	req := sdk.LinkRequest{Link: 1, Kind: sdk.LinkDevice, Role: sdk.RoleClient, Action: sdk.ActionCreate, Instance: inst, Port: "web",
		Type: "http.service", Device: dev, Config: sdk.Config{"hostname": "hello.home"}}
	pl, err := h.LinkPlan(ctx, req)
	if err != nil || len(pl.Actions) != 1 || !strings.Contains(pl.Actions[0].Title, "127.0.0.1 hello.home") || !strings.HasPrefix(pl.Actions[0].Detail, "на nas; ") {
		t.Fatalf("%+v %v", pl, err)
	}
	if _, err := h.LinkApply(ctx, req); err != nil {
		t.Fatal(err)
	}
	want := "127.0.0.1 localhost\n10.10.10.9 other.home # hestia-link-12\n127.0.0.1 hello.home # hestia-link-1\n"
	if got := d.read(); got != want {
		t.Fatalf("hosts:\n%s", got)
	}
	if st, _ := os.Stat(d.hosts); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	if st, err := h.LinkStatus(ctx, req); err != nil || st.State != sdk.StateOK {
		t.Fatalf("%+v %v", st, err)
	}
	// Applied again (new address): the line is replaced, not added.
	f.mu.Lock()
	f.targets[0].Address = "10.10.10.21"
	f.mu.Unlock()
	if st, _ := h.LinkStatus(ctx, req); st.State != sdk.StateDegraded {
		t.Fatalf("old address: %+v", st)
	}
	req.Action = sdk.ActionUpdate
	if _, err := h.LinkApply(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := d.read(); strings.Count(got, "hestia-link-1\n") != 1 || !strings.Contains(got, "10.10.10.21 hello.home # hestia-link-1\n") ||
		!strings.Contains(got, "hestia-link-12") {
		t.Fatalf("hosts:\n%s", got)
	}
	// Remove: only this link's line goes.
	req.Action = sdk.ActionRemove
	if err := h.LinkRemove(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := d.read(); got != "127.0.0.1 localhost\n10.10.10.9 other.home # hestia-link-12\n" {
		t.Fatalf("hosts:\n%s", got)
	}
	if st, _ := h.LinkStatus(ctx, req); st.State != sdk.StateDown {
		t.Fatalf("%+v", st)
	}
	// A bad name is refused before anything runs.
	req.Config = sdk.Config{"hostname": "Bad name;rm"}
	if _, err := h.LinkPlan(ctx, req); err == nil {
		t.Fatal("bad hostname accepted")
	}
	for _, c := range d.cmds {
		if !strings.HasPrefix(c, "ssh:9 ") {
			t.Fatalf("command on another target: %s", c)
		}
	}
}
