package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/sdktest"
	"github.com/uxerror/hestia/sdk/types"
)

func whoami(t *testing.T, code int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		fmt.Fprint(w, "Hostname: test\nName: Привет от Hestia\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func binding(t *testing.T, url string) json.RawMessage {
	b, err := types.Marshal(types.HTTPService{URL: url + "/", Host: "127.0.0.1", Port: 8080, Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func linkReq(inst sdk.Instance, link int64, b json.RawMessage) sdk.LinkRequest {
	return sdk.LinkRequest{JobID: "j", Link: link, Kind: sdk.LinkService, Role: sdk.RoleConsumer, Action: sdk.ActionCreate, Instance: inst,
		Port: "target", Type: "http.service", Binding: b,
		Peer: &sdk.LinkPeer{Plugin: "hestia-hello", Instance: 1, Name: "Hestia Hello 1", Port: "web"}}
}

func TestManifest(t *testing.T) {
	h := sdktest.New(t, manifest, newProbe())
	hl := h.Hello()
	if hl.ID != "hestia-probe" || hl.Version != "v0.1.0" {
		t.Fatalf("%+v", hl)
	}
	raw, _ := h.Manifest(context.Background())
	m, err := sdk.ParseManifest(raw)
	if err != nil || len(m.Requires) != 1 || m.Requires[0].PortName() != "target" || m.Requires[0].Type != "http.service" ||
		m.Requires[0].Optional || m.Requires[0].IsMulti(false) || strings.Join(m.Permissions, ",") != "net.outbound" {
		t.Fatalf("%+v %v", m, err)
	}
	errs, _ := h.Validate(context.Background(), sdk.Config{"interval_s": float64(10)})
	if len(errs) != 1 || errs[0].Field != "interval_s" {
		t.Fatalf("%+v", errs)
	}
}

func TestProbeLifecycle(t *testing.T) {
	dir := t.TempDir()
	p := newProbe()
	p.StateDir = dir
	h := sdktest.New(t, manifest, p)
	ctx := context.Background()
	inst := sdk.Instance{ID: 3, Name: "Probe 1", Config: sdk.Config{"interval_s": float64(60)}}

	// Created within a composite plan: the link is announced.
	pl, err := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionCreate,
		Links: []sdk.PlannedLink{{Port: "target", Peer: sdk.LinkPeer{Plugin: "hestia-hello", Instance: 1, Name: "Hestia Hello 1", Port: "web"}}}})
	if err != nil || len(pl.Actions) != 2 || !strings.Contains(pl.Actions[1].Title, "Hestia Hello 1") || len(pl.Warnings) != 0 {
		t.Fatalf("%+v %v", pl, err)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	// Not linked yet.
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateDegraded || st.Detail != "Не подключён к сервису" {
		t.Fatalf("%+v", st)
	}
	srv := whoami(t, 200)
	req := linkReq(inst, 5, binding(t, srv.URL))
	if pl, err := h.LinkPlan(ctx, req); err != nil || len(pl.Actions) != 1 {
		t.Fatalf("%+v %v", pl, err)
	}
	if _, err := h.LinkApply(ctx, req); err != nil {
		t.Fatal(err)
	}
	st, err := h.Status(ctx, inst)
	if err != nil || st.State != sdk.StateOK || !strings.HasPrefix(st.Detail, "200, ") || !strings.HasSuffix(st.Detail, " мс, Name: Привет от Hestia") ||
		len(st.Endpoints) != 1 || st.Endpoints[0].URL != srv.URL+"/" {
		t.Fatalf("%+v %v", st, err)
	}
	if ls, _ := h.LinkStatus(ctx, req); ls.State != sdk.StateOK {
		t.Fatalf("%+v", ls)
	}
	// The binding is kept in the state directory.
	if b, err := os.ReadFile(filepath.Join(dir, stateFile)); err != nil || !strings.Contains(string(b), srv.URL) {
		t.Fatalf("%s %v", b, err)
	}
	// Another link id is not this one.
	if ls, _ := h.LinkStatus(ctx, linkReq(inst, 6, nil)); ls.State != sdk.StateDown {
		t.Fatalf("%+v", ls)
	}
	// Errors: down.
	srv.Close()
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateDown {
		t.Fatalf("%+v", st)
	}
	bad := whoami(t, 503)
	if _, err := h.LinkApply(ctx, linkReq(inst, 5, binding(t, bad.URL))); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateDegraded || !strings.HasPrefix(st.Detail, "503") {
		t.Fatalf("%+v", st)
	}
	// Remove the link: not linked again.
	if err := h.LinkRemove(ctx, linkReq(inst, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateDegraded {
		t.Fatalf("%+v", st)
	}
	// probe is only a consumer.
	req.Role = sdk.RoleProvider
	if _, err := h.LinkApply(ctx, req); err == nil {
		t.Fatal("provider role accepted")
	}
	if _, err := h.LinkRefresh(ctx, req); err == nil {
		t.Fatal("refresh accepted")
	}
	// Without a binding the link fails.
	if _, err := h.LinkApply(ctx, linkReq(inst, 7, json.RawMessage(`{}`))); err == nil {
		t.Fatal("empty binding accepted")
	}
}

// After a restart the bindings come from the welcome of Hestia.
func TestRestoreFromWelcome(t *testing.T) {
	srv := whoami(t, 200)
	inst := sdk.Instance{ID: 4, Name: "Probe 2", Config: sdk.Config{"interval_s": float64(30)}}
	w := sdk.Welcome{Protocol: sdk.Protocol, HestiaVersion: "v0.0.0-test", Instances: []sdk.Instance{inst},
		Links: []sdk.LinkInfo{{Link: 9, Kind: sdk.LinkService, Role: sdk.RoleConsumer, Instance: 4, Port: "target", Binding: binding(t, srv.URL)}}}
	h := sdktest.NewWith(t, manifest, newProbe(), w)
	st, err := h.Status(context.Background(), inst)
	if err != nil || st.State != sdk.StateOK {
		t.Fatalf("%+v %v", st, err)
	}
	if ls, _ := h.LinkStatus(context.Background(), linkReq(inst, 9, nil)); ls.State == sdk.StateDown {
		t.Fatalf("%+v", ls)
	}
}
