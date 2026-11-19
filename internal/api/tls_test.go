package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/uxerror/hestia/internal/api"
	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/tlsself"
	"github.com/uxerror/hestia/internal/update"
	"github.com/uxerror/hestia/sdk"
)

func newTLSAPIEnv(t *testing.T) (*env, *plugins.Manager) {
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
	runner, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	pm := (&plugins.Manager{Store: st, Secrets: sec, Runner: runner, Version: "test", DataDir: dir, Mode: "serve", SocketPath: "-",
		GitHub: &update.GitHub{BaseURL: "http://127.0.0.1:1"}}).Init()
	pm.Start()
	ts := &tlsself.Service{DataDir: dir, Store: st, Addr: "127.0.0.1:0", InstanceID: "inst-test"}
	if err := ts.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := pm.StartBuiltin(context.Background(), tlsself.Manifest("test"), ts.Plugin()); err != nil {
		t.Fatal(err)
	}
	h := api.New(api.Config{Store: st, Auth: auth.New(st), Runner: runner, Plugins: pm, TLS: ts, InstanceID: "inst-test", Mode: "serve", Version: "test",
		Web: fstest.MapFS{"index.html": {Data: []byte("<html>spa</html>")}}})
	ts.SetHandler(h)
	ts.Start()
	srv := httptest.NewServer(h)
	jar, _ := cookiejar.New(nil)
	t.Cleanup(func() { srv.Close(); ts.Close(); pm.Close(); runner.Shutdown(); _ = st.Close() })
	return &env{srv: srv, client: &http.Client{Jar: jar}, runner: runner, store: st}, pm
}

func TestTLSAPIOff(t *testing.T) {
	e, _ := newTLSAPIEnv(t)
	resp, b := e.do(t, e.client, "GET", "/api/v1/health", "")
	var h struct {
		TLS struct {
			Enabled bool `json:"enabled"`
			Port    int  `json:"port"`
		} `json:"tls"`
	}
	decode(t, b, &h)
	if resp.StatusCode != 200 || h.TLS.Enabled {
		t.Fatalf("health %s", b)
	}
	if resp, _ := e.do(t, e.client, "GET", "/ca.crt", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ca.crt %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/tls", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tls without login %d", resp.StatusCode)
	}
	login(t, e)
	resp, b = e.do(t, e.client, "GET", "/api/v1/tls", "")
	var v struct {
		Mode       string `json:"mode"`
		Listener   string `json:"listener"`
		LinkID     *int64 `json:"link_id"`
		DesktopMin string `json:"desktop_min"`
	}
	decode(t, b, &v)
	if resp.StatusCode != 200 || v.Mode != "off" || v.Listener != "down" || v.LinkID != nil || v.DesktopMin != "v0.4.0" {
		t.Fatalf("tls %s", b)
	}
	// The built-in plugin is not among the plugins.
	_, b = e.do(t, e.client, "GET", "/api/v1/plugins", "")
	if strings.Contains(string(b), `"id":"hestia"`) {
		t.Fatalf("plugins %s", b)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/plugins/hestia", ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("remove builtin %d", resp.StatusCode)
	}
}

func TestActionPassword(t *testing.T) {
	e, _ := newTLSAPIEnv(t)
	ctx := context.Background()
	man, _ := json.Marshal(sdk.Manifest{Protocol: 1, ID: "acts", Name: "Acts", Version: "v0.1.0", Permissions: []string{},
		Actions: []sdk.ActionDef{{Name: "backup", Label: "Копия", Confirm: sdk.ConfirmPassword}, {Name: "root", Label: "Корень"}}})
	if err := e.store.SavePlugin(ctx, store.Plugin{ID: "acts", Version: "v0.1.0", AuthorKey: store.DevAuthorKey, Manifest: string(man),
		Source: store.PluginSourceDev, Enabled: true}, &store.PluginAuthor{Key: store.DevAuthorKey, Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	in := &store.PluginInstance{PluginID: "acts", Name: "A", Config: "{}", Status: "unknown"}
	if err := e.store.CreateInstance(ctx, in, nil); err != nil {
		t.Fatal(err)
	}
	login(t, e)
	path := fmt.Sprintf("/api/v1/plugins/instances/%d/actions/", in.ID)
	if resp, b := e.do(t, e.client, "POST", path+"backup", `{"params":{},"password":"wrong password"}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong password %d %s", resp.StatusCode, b)
	}
	// The right password passes the check (then: the plugin is not connected).
	if resp, b := e.do(t, e.client, "POST", path+"backup", `{"params":{},"password":"correct horse"}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("right password %d %s", resp.StatusCode, b)
	}
	if resp, _ := e.do(t, e.client, "POST", path+"nosuch", `{}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown action %d", resp.StatusCode)
	}
}
