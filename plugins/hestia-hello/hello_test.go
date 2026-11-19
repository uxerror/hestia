package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
	"github.com/uxerror/hestia/sdk/sdktest"
)

// fakeTargets is a tiny filesystem per target behind target.exec/put_file.
type fakeTargets struct {
	mu    sync.Mutex
	files map[string]map[string]string // target → path → content
	execs []string
}

var (
	reCat = regexp.MustCompile(`^cat (\S+) 2>/dev/null \|\| exit 3$`)
	reRm  = regexp.MustCompile(`^rm -f (\S+)$`)
)

func (f *fakeTargets) install(h *sdktest.Host) {
	h.Handle(sdk.MethodTargetExec, func(p json.RawMessage) (any, error) {
		var req sdk.ExecRequest
		_ = json.Unmarshal(p, &req)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.execs = append(f.execs, req.Target+": "+req.Cmd)
		fs := f.files[req.Target]
		if fs == nil {
			return nil, rpc.Errorf(rpc.CodePermission, "permission denied: цель %s не выдана", req.Target)
		}
		if m := reCat.FindStringSubmatch(req.Cmd); m != nil {
			v, ok := fs[m[1]]
			if !ok {
				return sdk.ExecResult{Code: 3}, nil
			}
			return sdk.ExecResult{Stdout: v}, nil
		}
		if m := reRm.FindStringSubmatch(req.Cmd); m != nil {
			delete(fs, m[1])
			return sdk.ExecResult{}, nil
		}
		return sdk.ExecResult{Code: 127, Stderr: "unexpected command"}, nil
	})
	h.Handle(sdk.MethodTargetPut, func(p json.RawMessage) (any, error) {
		var req sdk.PutFileRequest
		_ = json.Unmarshal(p, &req)
		b, _ := base64.StdEncoding.DecodeString(req.DataB64)
		f.mu.Lock()
		defer f.mu.Unlock()
		if req.Mode != "0644" {
			return nil, errors.New("mode " + req.Mode)
		}
		f.files[req.Target][req.Path] = string(b)
		return struct{}{}, nil
	})
	h.Handle(sdk.MethodTargetList, func(json.RawMessage) (any, error) {
		return []sdk.TargetInfo{{ID: "ssh:1", Kind: "ssh", Name: "web", Address: "10.10.10.21"},
			{ID: "ssh:2", Kind: "ssh", Name: "db", Address: "10.10.10.22"}}, nil
	})
}

func newHost(t *testing.T) (*sdktest.Host, *fakeTargets) {
	h := sdktest.New(t, manifest, &hello{})
	f := &fakeTargets{files: map[string]map[string]string{"ssh:1": {}, "ssh:2": {}}}
	f.install(h)
	return h, f
}

func cfg(target, msg string) sdk.Config { return sdk.Config{"target": target, "message": msg} }

func TestHelloAndManifest(t *testing.T) {
	h, _ := newHost(t)
	hl := h.Hello()
	if hl.ID != "hestia-hello" || hl.Version != "v0.1.0" || hl.Protocol != sdk.Protocol || hl.Token != "test-token" {
		t.Fatalf("hello %+v", hl)
	}
	raw, err := h.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m, err := sdk.ParseManifest(raw)
	if err != nil || m.ID != "hestia-hello" || len(m.Schema.Fields) != 2 {
		t.Fatalf("%+v %v", m, err)
	}
	for _, p := range m.Permissions {
		if p != sdk.PermTargetsRead && p != sdk.PermTargetsExec {
			t.Fatalf("unexpected permission %s", p)
		}
	}
}

func TestValidate(t *testing.T) {
	h, _ := newHost(t)
	errs, err := h.Validate(context.Background(), cfg("", "  "))
	if err != nil || len(errs) != 2 {
		t.Fatalf("%v %v", errs, err)
	}
	errs, err = h.Validate(context.Background(), cfg("ssh:1", "hi"))
	if err != nil || len(errs) != 0 {
		t.Fatalf("%v %v", errs, err)
	}
}

func TestCreateApplyStatusRemove(t *testing.T) {
	h, f := newHost(t)
	ctx := context.Background()
	inst := sdk.Instance{ID: 7, Name: "Hello 1", Config: cfg("ssh:1", "Привет")}
	pl, err := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionCreate})
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Actions) != 1 || pl.Actions[0].Risk != sdk.RiskChange || !strings.Contains(pl.Actions[0].Title, "/tmp/hestia-hello-7") ||
		!strings.Contains(pl.Actions[0].Detail, "web") {
		t.Fatalf("plan %+v", pl)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j1", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if got := f.files["ssh:1"]["/tmp/hestia-hello-7"]; got != "Привет\n" {
		t.Fatalf("file %q", got)
	}
	steps := h.Steps()
	if len(steps) != 2 || steps[0].Title != "Запись приветствия" || !steps[1].Done || steps[1].Error != "" {
		t.Fatalf("steps %+v", steps)
	}
	st, err := h.Status(ctx, inst)
	if err != nil || st.State != sdk.StateOK || st.Detail != "Привет" {
		t.Fatalf("%+v %v", st, err)
	}

	// The same plan again: nothing to change.
	pl, err = h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionUpdate})
	if err != nil || pl.Actions[0].Risk != sdk.RiskInfo {
		t.Fatalf("%+v %v", pl, err)
	}

	// Somebody changed the file: degraded.
	f.files["ssh:1"]["/tmp/hestia-hello-7"] = "чужое\n"
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateDegraded {
		t.Fatalf("%+v", st)
	}

	// Move to another target: remove from the old one, write on the new one.
	next := cfg("ssh:2", "Привет")
	pl, err = h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: next, Action: sdk.ActionUpdate})
	if err != nil || len(pl.Actions) != 2 {
		t.Fatalf("%+v %v", pl, err)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j2", Instance: inst, Config: next, Action: sdk.ActionUpdate, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.files["ssh:1"]["/tmp/hestia-hello-7"]; ok {
		t.Fatal("old file kept")
	}
	if f.files["ssh:2"]["/tmp/hestia-hello-7"] != "Привет\n" {
		t.Fatal("new file missing")
	}

	inst.Config = next
	pl, err = h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: next, Action: sdk.ActionRemove})
	if err != nil || len(pl.Actions) != 1 {
		t.Fatalf("%+v %v", pl, err)
	}
	if err := h.Apply(ctx, sdk.ApplyRequest{JobID: "j3", Instance: inst, Config: next, Action: sdk.ActionRemove, Plan: pl}); err != nil {
		t.Fatal(err)
	}
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateDown {
		t.Fatalf("%+v", st)
	}
	// Removing again: only a warning.
	pl, _ = h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: next, Action: sdk.ActionRemove})
	if len(pl.Actions) != 0 || len(pl.Warnings) != 1 {
		t.Fatalf("%+v", pl)
	}
}

func TestApplyFailureClosesStep(t *testing.T) {
	h, _ := newHost(t)
	ctx := context.Background()
	inst := sdk.Instance{ID: 3, Name: "x", Config: cfg("ssh:9", "hi")} // not granted
	_, err := h.Plan(ctx, sdk.PlanRequest{Instance: inst, Config: inst.Config, Action: sdk.ActionCreate})
	if !rpc.IsCode(err, rpc.CodePermission) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("plan err %v", err)
	}
	data, _ := json.Marshal(planData{Path: "/tmp/hestia-hello-3", Target: "ssh:9", Write: true})
	err = h.Apply(ctx, sdk.ApplyRequest{JobID: "j", Instance: inst, Config: inst.Config, Action: sdk.ActionCreate,
		Plan: sdk.Plan{Data: data}})
	if err == nil {
		t.Fatal("apply must fail")
	}
	steps := h.Steps()
	if len(steps) != 1 || !steps[0].Done || steps[0].Error == "" {
		t.Fatalf("steps %+v", steps)
	}
	if st, _ := h.Status(ctx, inst); st.State != sdk.StateUnknown {
		t.Fatalf("%+v", st)
	}
}

func TestApplyWithoutData(t *testing.T) {
	h, _ := newHost(t)
	err := h.Apply(context.Background(), sdk.ApplyRequest{JobID: "j", Instance: sdk.Instance{ID: 1}, Action: sdk.ActionCreate})
	if err == nil || !strings.Contains(err.Error(), "план без данных") {
		t.Fatal(err)
	}
}
