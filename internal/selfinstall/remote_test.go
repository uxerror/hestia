package selfinstall_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hestia/internal/selfinstall"
)

func TestRemoteFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if r, err := selfinstall.ReadRemote(dir); r != nil || err != nil {
		t.Fatalf("missing file: %v %v", r, err)
	}
	want := selfinstall.Remote{URL: "http://" + ctIP, InstanceID: "abc", Location: selfinstall.Location{
		Kind: "lxc", TargetID: 3, Node: "pve1", VMID: 900, IP: ctIP, MAC: "BC:24:11:BC:4C:F6", MovedAt: time.Unix(1700000000, 0).UTC()}}
	if err := selfinstall.WriteRemote(dir, want); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, selfinstall.RemoteFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("remote.json: %v %v", st, err)
	}
	got, err := selfinstall.ReadRemote(dir)
	if err != nil || *got != want {
		t.Fatalf("got %+v %v", got, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
	for _, k := range []string{`"url"`, `"instance_id"`, `"kind"`, `"target_id"`, `"node"`, `"vmid"`, `"mac"`, `"ip"`, `"moved_at"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("remote.json lacks %s: %s", k, raw)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, selfinstall.RemoteFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := selfinstall.ReadRemote(dir); err == nil {
		t.Fatal("corrupt remote.json accepted")
	}
}

func TestCheckRemote(t *testing.T) {
	status, id := "ok", "inst-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"` + status + `","instance_id":"` + id + `"}`))
	}))
	defer srv.Close()
	r := selfinstall.Remote{URL: srv.URL, InstanceID: "inst-1"}
	if !selfinstall.CheckRemote(ctxBG(), r) {
		t.Fatal("healthy remote reported unreachable")
	}
	id = "other"
	if selfinstall.CheckRemote(ctxBG(), r) {
		t.Fatal("a different instance must not count as the remote controller")
	}
	id, status = "inst-1", "moved"
	if selfinstall.CheckRemote(ctxBG(), r) {
		t.Fatal("a moved controller is not the destination")
	}
	srv.Close()
	if selfinstall.CheckRemote(ctxBG(), r) {
		t.Fatal("closed server reported reachable")
	}
}

func TestGate(t *testing.T) {
	var g selfinstall.Gate
	if g.Transferring() || g.Moved() != nil {
		t.Fatal("fresh gate")
	}
	g.SetTransferring(true)
	g.SetMoved(selfinstall.Remote{URL: "http://x"})
	if !g.Transferring() || g.Moved().URL != "http://x" {
		t.Fatal("gate state")
	}
	var nilGate *selfinstall.Gate
	if nilGate.Transferring() || nilGate.Moved() != nil {
		t.Fatal("nil gate must be inert")
	}
}
