package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/sdktest"
)

// fakeDeploy answers deploy.* and target.list like Hestia would.
type fakeDeploy struct {
	mu      sync.Mutex
	plans   []sdk.DeployRequest
	ups     []sdk.DeployRequest
	downs   []sdk.DeployDownRequest
	exists  map[string]bool // target → project deployed
	upErr   error
	targets []sdk.TargetInfo
}

func (f *fakeDeploy) install(h *sdktest.Host) {
	h.Handle(sdk.MethodTargetList, func(json.RawMessage) (any, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.targets, nil
	})
	h.OnDeployPlan(func(r sdk.DeployRequest) (sdk.DeployPlan, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.plans = append(f.plans, r)
		return sdk.DeployPlan{Project: fmt.Sprintf("hestia-%d-%s", r.Instance, r.Project),
			Actions:  []sdk.Action{{Title: "Создать проект", Risk: sdk.RiskChange}, {Title: "Запустить", Risk: sdk.RiskChange}},
			Warnings: []string{"Порт занят"}}, nil
	})
	h.OnDeployUp(func(r sdk.DeployRequest) (sdk.DeployStatus, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.ups = append(f.ups, r)
		if f.upErr != nil {
			return sdk.DeployStatus{}, f.upErr
		}
		f.exists[r.Target] = true
		return sdk.DeployStatus{Exists: true, Docker: true, Containers: []sdk.DeployContainer{{Name: "c-1", Service: "whoami", State: "running", Status: "Up"}}}, nil
	})
	h.OnDeployDown(func(r sdk.DeployDownRequest) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.downs = append(f.downs, r)
		delete(f.exists, r.Target)
		return nil
	})
	h.OnDeployStatus(func(r sdk.DeployStatusRequest) (sdk.DeployStatus, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return sdk.DeployStatus{Exists: f.exists[r.Target]}, nil
	})
}

// whoami is a stand-in for the container: the test's HTTP server.
func whoami(t *testing.T) (*httptest.Server, int64) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Name: Привет\nHostname: test\n")
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var port int64
	fmt.Sscan(p, &port)
	return srv, port
}

func newHost(t *testing.T) (*sdktest.Host, *fakeDeploy, *hello) {
	checkTimeout, checkInterval = 500*time.Millisecond, 20*time.Millisecond
	pl := &hello{}
	h := sdktest.New(t, manifest, pl)
	f := &fakeDeploy{exists: map[string]bool{}, targets: []sdk.TargetInfo{
		{ID: "ssh:1", Kind: "ssh", Name: "web", Address: "127.0.0.1"},
		{ID: "ssh:2", Kind: "ssh", Name: "db", Address: "127.0.0.1"},
		{ID: "lxc:3:pve:105", Kind: "lxc", Name: "ct (CT 105, pve)"},
	}}
	f.install(h)
	return h, f, pl
}

func cfg(target string, port int64, msg string) sdk.Config {
	return sdk.Config{"target": target, "port": float64(port), "message": msg}
}

func TestManifest(t *testing.T) {
	h, _, _ := newHost(t)
	hl := h.Hello()
	if hl.ID != "hestia-hello" || hl.Version != "v0.3.0" || hl.Protocol != sdk.Protocol || hl.Token != "test-token" {
		t.Fatalf("hello %+v", hl)
	}
	raw, err := h.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m, err := sdk.ParseManifest(raw)
	if err != nil || m.ID != "hestia-hello" || len(m.Schema.Fields) != 3 || len(m.Provides) != 1 || m.Provides[0].Type != "http.service" ||
		m.Provides[0].PortName() != "web" || !m.Provides[0].Client || m.Provides[0].LinkSchema == nil {
		t.Fatalf("%+v %v", m, err)
	}
	if strings.Join(m.Permissions, ",") != "targets.read,targets.exec,deploy.docker,net.outbound,links.client" {
		t.Fatalf("permissions %v", m.Permissions)
	}
	if m.Schema.Fields[1].Name != "port" || m.Schema.Fields[1].Default != json.Number("8080") && m.Schema.Fields[1].Default != float64(8080) {
		t.Fatalf("port field %+v", m.Schema.Fields[1])
	}
}

func TestValidate(t *testing.T) {
	h, _, _ := newHost(t)
	errs, err := h.Validate(context.Background(), sdk.Config{"message": "  ", "port": float64(0)})
	if err != nil || len(errs) != 3 {
		t.Fatalf("%v %v", errs, err)
	}
	errs, err = h.Validate(context.Background(), cfg("ssh:1", 8080, "hi"))
	if err != nil || len(errs) != 0 {
		t.Fatalf("%v %v", errs, err)
	}
}

func TestCreateApplyStatusRemove(t *testing.T) {
	h, f, _ := newHost(t)
	ctx := context.Background()
	srv, port := whoami(t)
	inst := sdk.Instance{ID: 7, Name: "Hello 1", Config: cfg("ssh:1", port, "Привет")}

	pl, err := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionCreate})
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	if len(pl.Actions) != 3 || pl.Actions[2].Title != "Проверить "+url || len(pl.Warnings) != 1 {
		t.Fatalf("%+v", pl)
	}
	// The compose file: one whoami service, the message as an argument.
	var c struct {
		Services map[string]struct {
			Image   string   `json:"image"`
			Command []string `json:"command"`
			Ports   []string `json:"ports"`
		} `json:"services"`
	}
	if err := json.Unmarshal(f.plans[0].Compose, &c); err != nil {
		t.Fatal(err)
	}
	w := c.Services["whoami"]
	if f.plans[0].Project != "whoami" || f.plans[0].Instance != 7 || w.Image != "traefik/whoami:v1.10" ||
		strings.Join(w.Command, "|") != "--name|Привет" || w.Ports[0] != fmt.Sprintf("%d:80", port) {
		t.Fatalf("%+v %s", f.plans[0], f.plans[0].Compose)
	}

	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j1", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if len(f.ups) != 1 || f.ups[0].JobID != "j1" || f.ups[0].Target != "ssh:1" {
		t.Fatalf("%+v", f.ups)
	}
	steps := h.Steps()
	if len(steps) != 1 || steps[0].Title != "Проверка "+url || !steps[0].Done || steps[0].Error != "" {
		t.Fatalf("%+v", steps)
	}
	st, err := h.Status(ctx, inst)
	if err != nil || st.State != sdk.StateOK || st.Detail != "Name: Привет" || len(st.Endpoints) != 1 || st.Endpoints[0].URL != url {
		t.Fatalf("%+v %v", st, err)
	}

	// Remove: deploy.down with volumes.
	pl, err = h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionRemove})
	if err != nil || len(pl.Actions) != 1 || !strings.Contains(pl.Actions[0].Title, "удалить whoami") {
		t.Fatalf("%+v %v", pl, err)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j2", Instance: inst, Config: inst.Config, Action: sdk.ActionRemove, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if len(f.downs) != 1 || !f.downs[0].Volumes || f.downs[0].JobID != "j2" || f.downs[0].Project != "whoami" {
		t.Fatalf("%+v", f.downs)
	}
	// Nothing left: the remove plan only warns.
	pl, _ = h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionRemove})
	if len(pl.Actions) != 0 || len(pl.Warnings) != 1 {
		t.Fatalf("%+v", pl)
	}

	// The service is gone: down.
	srv.Close()
	st, _ = h.Status(ctx, inst)
	if st.State != sdk.StateDown {
		t.Fatalf("%+v", st)
	}
}

func TestApplyCheckFails(t *testing.T) {
	h, f, _ := newHost(t)
	ctx := context.Background()
	srv, port := whoami(t)
	srv.Close() // nothing answers
	inst := sdk.Instance{ID: 3, Name: "x", Config: cfg("ssh:1", port, "hi")}
	pl, _ := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionCreate})
	err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate, Plan: pl})
	if err == nil || !strings.Contains(err.Error(), "не ответил 200") {
		t.Fatalf("%v", err)
	}
	steps := h.Steps()
	if len(steps) != 1 || steps[0].Error == "" {
		t.Fatalf("%+v", steps)
	}
	// deploy.up failing is reported as is.
	f.mu.Lock()
	f.upErr = fmt.Errorf("контейнеры не запустились")
	f.mu.Unlock()
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate, Plan: pl}); err == nil ||
		!strings.Contains(err.Error(), "не запустились") {
		t.Fatalf("%v", err)
	}
}

func TestUpdateMovesTarget(t *testing.T) {
	h, f, _ := newHost(t)
	ctx := context.Background()
	_, port := whoami(t)
	inst := sdk.Instance{ID: 5, Name: "x", Config: cfg("ssh:1", port, "one")}
	next := cfg("ssh:2", port, "two")
	pl, err := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: next, Action: sdk.ActionUpdate})
	if err != nil || !strings.Contains(pl.Actions[0].Title, "старой цели") || pl.Actions[0].Detail != "web" {
		t.Fatalf("%+v %v", pl, err)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: next, Action: sdk.ActionUpdate, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if len(f.downs) != 1 || f.downs[0].Target != "ssh:1" || len(f.ups) != 1 || f.ups[0].Target != "ssh:2" {
		t.Fatalf("%+v %+v", f.downs, f.ups)
	}
}

func TestNoAddress(t *testing.T) {
	h, f, _ := newHost(t)
	ctx := context.Background()
	inst := sdk.Instance{ID: 9, Name: "x", Config: cfg("lxc:3:pve:105", 8080, "hi")}
	pl, err := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionCreate})
	if err != nil || len(pl.Actions) != 2 || len(pl.Warnings) != 2 {
		t.Fatalf("%+v %v", pl, err)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if len(f.ups) != 1 {
		t.Fatal("not deployed")
	}
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateUnknown {
		t.Fatalf("%+v", st)
	}
	// A plan without data is refused.
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate}); err == nil {
		t.Fatal("apply without plan data")
	}
}
