// Package sdktest is a fake Hestia for unit tests of plugins: it runs the
// plugin over an in-memory connection, records every call the plugin makes
// and answers with results set by the test. Secrets and job steps/logs work
// out of the box; target.*, inventory.get and anything else need Handle.
package sdktest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// HandlerFunc answers one call of the plugin.
type HandlerFunc func(params json.RawMessage) (any, error)

// Call is a recorded call of the plugin.
type Call struct {
	Method string
	Params json.RawMessage
}

// Step is a recorded job step.
type Step struct {
	Title string
	Error string
	Done  bool
}

// Host is the fake Hestia side.
type Host struct {
	// Welcome is returned to hello (set before New returns; change it only
	// before calling New through NewWith).
	Welcome sdk.Welcome

	t    testing.TB
	conn *rpc.Conn

	mu       sync.Mutex
	handlers map[string]HandlerFunc
	calls    []Call
	steps    []Step
	logs     []sdk.JobLog
	syslog   []sdk.LogLine
	secrets  map[string]string
	hello    sdk.Hello
	helloed  chan struct{}
	runErr   chan error
}

// New starts the plugin against a fake Hestia and waits for its hello.
// Everything is stopped on test cleanup.
func New(t testing.TB, manifest []byte, p sdk.Plugin) *Host {
	return NewWith(t, manifest, p, sdk.Welcome{Protocol: sdk.Protocol, HestiaVersion: "v0.0.0-test", Instances: []sdk.Instance{}})
}

// NewWith is New with a custom answer to hello.
func NewWith(t testing.TB, manifest []byte, p sdk.Plugin, welcome sdk.Welcome) *Host {
	t.Helper()
	h := &Host{
		Welcome: welcome, t: t, handlers: map[string]HandlerFunc{}, secrets: map[string]string{},
		helloed: make(chan struct{}), runErr: make(chan error, 1),
	}
	a, b := net.Pipe()
	h.conn = rpc.NewConn(a, h.handle, rpc.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { h.runErr <- sdk.Run(ctx, manifest, p, b, "test-token") }()
	t.Cleanup(func() {
		cancel()
		_ = h.conn.Close()
		select {
		case <-h.runErr:
		case <-time.After(5 * time.Second):
			t.Error("sdktest: plugin did not stop")
		}
	})
	select {
	case <-h.helloed:
	case err := <-h.runErr:
		t.Fatalf("sdktest: plugin stopped before hello: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("sdktest: no hello from the plugin")
	}
	return h
}

// Hello returns what the plugin sent in hello.
func (h *Host) Hello() sdk.Hello {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hello
}

// Handle sets the answer to a method.
func (h *Host) Handle(method string, fn HandlerFunc) {
	h.mu.Lock()
	h.handlers[method] = fn
	h.mu.Unlock()
}

// OnDeployPlan answers deploy.plan.
func (h *Host) OnDeployPlan(fn func(sdk.DeployRequest) (sdk.DeployPlan, error)) {
	h.Handle(sdk.MethodDeployPlan, func(p json.RawMessage) (any, error) {
		var req sdk.DeployRequest
		if err := json.Unmarshal(p, &req); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "sdktest: %v", err)
		}
		return fn(req)
	})
}

// OnDeployUp answers deploy.up.
func (h *Host) OnDeployUp(fn func(sdk.DeployRequest) (sdk.DeployStatus, error)) {
	h.Handle(sdk.MethodDeployUp, func(p json.RawMessage) (any, error) {
		var req sdk.DeployRequest
		if err := json.Unmarshal(p, &req); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "sdktest: %v", err)
		}
		return fn(req)
	})
}

// OnDeployDown answers deploy.down.
func (h *Host) OnDeployDown(fn func(sdk.DeployDownRequest) error) {
	h.Handle(sdk.MethodDeployDown, func(p json.RawMessage) (any, error) {
		var req sdk.DeployDownRequest
		if err := json.Unmarshal(p, &req); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "sdktest: %v", err)
		}
		if err := fn(req); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	})
}

// OnDeployStatus answers deploy.status.
func (h *Host) OnDeployStatus(fn func(sdk.DeployStatusRequest) (sdk.DeployStatus, error)) {
	h.Handle(sdk.MethodDeployStatus, func(p json.RawMessage) (any, error) {
		var req sdk.DeployStatusRequest
		if err := json.Unmarshal(p, &req); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "sdktest: %v", err)
		}
		return fn(req)
	})
}

// Calls returns the recorded calls of a method ("" for all).
func (h *Host) Calls(method string) []Call {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []Call
	for _, c := range h.calls {
		if method == "" || c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// Steps returns the recorded job steps.
func (h *Host) Steps() []Step {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Step(nil), h.steps...)
}

// JobLog returns the recorded job log lines.
func (h *Host) JobLog() []sdk.JobLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sdk.JobLog(nil), h.logs...)
}

// SysLog returns the recorded plugin log lines.
func (h *Host) SysLog() []sdk.LogLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sdk.LogLine(nil), h.syslog...)
}

// Secret returns a stored secret (instance, name).
func (h *Host) Secret(instance int64, name string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.secrets[fmt.Sprintf("%d/%s", instance, name)]
	return v, ok
}

// SetSecret stores a secret as if the user had entered it.
func (h *Host) SetSecret(instance int64, name, value string) {
	h.mu.Lock()
	h.secrets[fmt.Sprintf("%d/%s", instance, name)] = value
	h.mu.Unlock()
}

func (h *Host) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	h.mu.Lock()
	h.calls = append(h.calls, Call{Method: method, Params: append(json.RawMessage(nil), params...)})
	fn := h.handlers[method]
	h.mu.Unlock()
	if fn != nil {
		return fn(params)
	}
	switch method {
	case sdk.MethodHello:
		var hl sdk.Hello
		_ = json.Unmarshal(params, &hl)
		h.mu.Lock()
		h.hello = hl
		h.mu.Unlock()
		defer func() {
			select {
			case <-h.helloed:
			default:
				close(h.helloed)
			}
		}()
		return h.Welcome, nil
	case sdk.MethodJobStep:
		var p sdk.JobStep
		_ = json.Unmarshal(params, &p)
		h.mu.Lock()
		h.steps = append(h.steps, Step{Title: p.Title})
		h.mu.Unlock()
		return struct{}{}, nil
	case sdk.MethodJobStepDone:
		var p sdk.JobStepDone
		_ = json.Unmarshal(params, &p)
		h.mu.Lock()
		if n := len(h.steps); n > 0 {
			h.steps[n-1].Done, h.steps[n-1].Error = true, p.Error
		}
		h.mu.Unlock()
		return struct{}{}, nil
	case sdk.MethodJobLog:
		var p sdk.JobLog
		_ = json.Unmarshal(params, &p)
		h.mu.Lock()
		h.logs = append(h.logs, p)
		h.mu.Unlock()
		return struct{}{}, nil
	case sdk.MethodLog:
		var p sdk.LogLine
		_ = json.Unmarshal(params, &p)
		h.mu.Lock()
		h.syslog = append(h.syslog, p)
		h.mu.Unlock()
		return struct{}{}, nil
	case sdk.MethodSecretPut, sdk.MethodSecretGet, sdk.MethodSecretDelete:
		var p sdk.SecretRequest
		_ = json.Unmarshal(params, &p)
		key := fmt.Sprintf("%d/%s", p.Instance, p.Name)
		h.mu.Lock()
		defer h.mu.Unlock()
		switch method {
		case sdk.MethodSecretPut:
			h.secrets[key] = p.Value
		case sdk.MethodSecretDelete:
			delete(h.secrets, key)
		default:
			v, ok := h.secrets[key]
			return sdk.SecretValue{Value: v, Exists: ok}, nil
		}
		return struct{}{}, nil
	}
	return nil, rpc.Errorf(rpc.CodeMethodNotFound, "sdktest: нет обработчика для %s (Host.Handle)", method)
}

// Manifest asks the plugin for its manifest.
func (h *Host) Manifest(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := h.conn.Call(ctx, sdk.MethodManifest, struct{}{}, &out)
	return out, err
}

// Validate calls instance.validate.
func (h *Host) Validate(ctx context.Context, cfg sdk.Config) ([]sdk.FieldError, error) {
	var out []sdk.FieldError
	err := h.conn.Call(ctx, sdk.MethodValidate, map[string]any{"config": cfg}, &out)
	return out, err
}

// Plan calls instance.plan.
func (h *Host) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	var out sdk.Plan
	err := h.conn.Call(ctx, sdk.MethodPlan, req, &out)
	return out, err
}

// Apply calls instance.apply (no default timeout, like Hestia).
func (h *Host) Apply(ctx context.Context, req sdk.ApplyRequest) error {
	return h.conn.CallNoTimeout(ctx, sdk.MethodApply, req, nil)
}

// Status calls instance.status.
func (h *Host) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	var out sdk.Status
	err := h.conn.Call(ctx, sdk.MethodStatus, map[string]any{"instance": inst}, &out)
	return out, err
}
