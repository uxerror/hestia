package selfinstall_test

import (
	"context"
	"errors"
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

// controller is a fake Hestia: health answers with an instance id and,
// optionally, the announced DNS name.
type healthDouble struct {
	srv    *httptest.Server
	status string
	id     string
	dns    string
}

func newHealthDouble(t *testing.T, id string) *healthDouble {
	c := &healthDouble{status: "ok", id: id}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			http.NotFound(w, r)
			return
		}
		body := `{"status":"` + c.status + `","instance_id":"` + c.id + `"`
		if c.dns != "" {
			body += `,"dns_url":"` + c.dns + `"`
		}
		_, _ = w.Write([]byte(body + "}"))
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func TestRemoteFallbackURLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := selfinstall.Remote{URL: "http://hestia.home", FallbackURL: "http://" + ctIP, InstanceID: "abc"}
	if err := selfinstall.WriteRemote(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := selfinstall.ReadRemote(dir)
	if err != nil || *got != want {
		t.Fatalf("%+v %v", got, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
	if !strings.Contains(string(raw), `"fallback_url"`) {
		t.Fatalf("%s", raw)
	}
	// Without a fallback the field is not written (old files stay byte-compatible).
	if err := selfinstall.WriteRemote(dir, selfinstall.Remote{URL: "http://x", InstanceID: "a"}); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
	if strings.Contains(string(raw), "fallback_url") {
		t.Fatalf("%s", raw)
	}
}

func TestReachableURLFallsBack(t *testing.T) {
	c := newHealthDouble(t, "inst-1")
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	r := selfinstall.Remote{URL: deadURL, FallbackURL: c.srv.URL, InstanceID: "inst-1"}
	if u, ok := selfinstall.ReachableURL(ctxBG(), r); !ok || u != c.srv.URL {
		t.Fatalf("%q %v", u, ok)
	}
	if !selfinstall.CheckRemote(ctxBG(), r) {
		t.Fatal("fallback ignored")
	}
	// The fallback must be the same controller.
	r.InstanceID = "other"
	if _, ok := selfinstall.ReachableURL(ctxBG(), r); ok {
		t.Fatal("another instance accepted at the fallback")
	}
	// The primary wins when both answer.
	r = selfinstall.Remote{URL: c.srv.URL, FallbackURL: deadURL, InstanceID: "inst-1"}
	if u, _ := selfinstall.ReachableURL(ctxBG(), r); u != c.srv.URL {
		t.Fatal(u)
	}
}

func okResolve(context.Context, string) error  { return nil }
func badResolve(context.Context, string) error { return errors.New("NXDOMAIN") }

func TestResolveStartSwitchesToDNSName(t *testing.T) {
	dir := t.TempDir()
	byIP := newHealthDouble(t, "inst-1")
	byName := newHealthDouble(t, "inst-1") // "http://hestia.home" is served by this one
	byIP.dns = "http://" + byName.srv.Listener.Addr().String()

	start := selfinstall.Remote{URL: byIP.srv.URL, InstanceID: "inst-1", Location: selfinstall.Location{Kind: "lxc", IP: ctIP}}
	if err := selfinstall.WriteRemote(dir, start); err != nil {
		t.Fatal(err)
	}
	got, ok := selfinstall.ResolveStart(ctxBG(), dir, start, selfinstall.StartOptions{Resolve: okResolve})
	if !ok || got.URL != byIP.dns || got.FallbackURL != byIP.srv.URL || got.Kind != "lxc" {
		t.Fatalf("%+v %v", got, ok)
	}
	// Persisted atomically with mode 0600.
	disk, err := selfinstall.ReadRemote(dir)
	if err != nil || *disk != got {
		t.Fatalf("%+v %v", disk, err)
	}
	if st, _ := os.Stat(filepath.Join(dir, selfinstall.RemoteFile)); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if _, err := os.Stat(filepath.Join(dir, selfinstall.RemoteFile+".tmp")); err == nil {
		t.Fatal("temp file left")
	}

	// Next start: the name is already the url, nothing to change; the file stays as it is.
	before, _ := os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
	byName.dns = byIP.dns
	got2, ok := selfinstall.ResolveStart(ctxBG(), dir, got, selfinstall.StartOptions{Resolve: okResolve})
	after, _ := os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
	if !ok || got2.URL != got.URL || string(before) != string(after) {
		t.Fatalf("%+v %v", got2, ok)
	}

	// The name is dead (primary does not answer): the fallback opens, the file is untouched.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	broken := selfinstall.Remote{URL: deadURL, FallbackURL: byIP.srv.URL, InstanceID: "inst-1"}
	got3, ok := selfinstall.ResolveStart(ctxBG(), dir, broken, selfinstall.StartOptions{Resolve: badResolve})
	if !ok || got3.URL != byIP.srv.URL {
		t.Fatalf("%+v %v", got3, ok)
	}
	// Nothing answers.
	if _, ok := selfinstall.ResolveStart(ctxBG(), dir, selfinstall.Remote{URL: deadURL, InstanceID: "inst-1"}, selfinstall.StartOptions{}); ok {
		t.Fatal("dead controller reported reachable")
	}
}

func TestResolveStartKeepsRemoteWhenNameIsNotUsable(t *testing.T) {
	byIP := newHealthDouble(t, "inst-1")
	name := newHealthDouble(t, "inst-1")
	cases := map[string]struct {
		dns     string
		resolve func(context.Context, string) error
		nameID  string
	}{
		"does not resolve on this PC": {"http://" + name.srv.Listener.Addr().String(), badResolve, "inst-1"},
		"answers as another instance": {"http://" + name.srv.Listener.Addr().String(), okResolve, "other"},
		"not announced":               {"", okResolve, "inst-1"},
		"garbage":                     {"hestia.home", okResolve, "inst-1"},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			start := selfinstall.Remote{URL: byIP.srv.URL, InstanceID: "inst-1"}
			if err := selfinstall.WriteRemote(dir, start); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
			byIP.dns, name.id = c.dns, c.nameID
			got, ok := selfinstall.ResolveStart(ctxBG(), dir, start, selfinstall.StartOptions{Resolve: c.resolve})
			after, _ := os.ReadFile(filepath.Join(dir, selfinstall.RemoteFile))
			if !ok || got.URL != start.URL || got.FallbackURL != "" || string(before) != string(after) {
				t.Fatalf("%+v %v\n%s", got, ok, after)
			}
		})
	}
}
