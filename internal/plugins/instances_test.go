package plugins

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

func addSSHTarget(t *testing.T, h *harness, name, host string) string {
	t.Helper()
	tg := &store.Target{Kind: store.KindSSH, Name: name, Host: host, Port: 22, SSHUser: "root", HostKeyFP: "SHA256:test"}
	if err := h.st.CreateTarget(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("ssh:%d", tg.ID)
}

// setupInstances installs the demo plugin with a secret field and returns
// the scriptable plugin and two targets.
func setupInstances(t *testing.T, mod func(*sdk.Manifest)) (*harness, *testPlugin, string, string) {
	h := newHarness(t)
	tp := &testPlugin{}
	h.plug = func(string) sdk.Plugin { return tp }
	key := newKey(t)
	pkg := testPackage(t, key, func(m *sdk.Manifest) {
		m.Schema.Fields = append(m.Schema.Fields, sdk.Field{Name: "password", Type: sdk.FieldSecret, Label: "Пароль"})
		if mod != nil {
			mod(m)
		}
	})
	if j := h.install(pkg); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	h.waitConnected("demo")
	return h, tp, addSSHTarget(t, h, "web", "10.10.10.21"), addSSHTarget(t, h, "db", "10.10.10.22")
}

func wantFields(t *testing.T, err error, fields ...string) {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 422 {
		t.Fatalf("want 422, got %v", err)
	}
	got := map[string]bool{}
	for _, f := range pe.Fields {
		got[f.Field] = true
	}
	for _, f := range fields {
		if !got[f] {
			t.Fatalf("no error for %s in %+v", f, pe.Fields)
		}
	}
}

func applyPlan(t *testing.T, h *harness, pv *PlanView, confirm bool) store.Job {
	t.Helper()
	job, err := h.m.Apply(context.Background(), pv.PlanID, ApplyRequest{Hash: pv.Hash, ConfirmDanger: confirm})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return h.wait(job.ID)
}

func TestInstanceLifecycle(t *testing.T) {
	h, tp, web, db := setupInstances(t, nil)
	ctx := context.Background()
	// The plugin reads the form secret and logs it: Hestia must mask it.
	tp.applyHook = func(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
		return job.Run("Секрет", func(ctx context.Context) error {
			v, ok, err := job.Host().SecretGet(ctx, req.Instance.ID, "password")
			if err != nil || !ok {
				return fmt.Errorf("secret: %v %v", ok, err)
			}
			job.Logf("password is %s", v)
			return nil
		})
	}

	pv, err := h.m.CreatePlan(ctx, "demo", "", map[string]any{"target": web, "password": "pw-one"})
	if err != nil {
		t.Fatal(err)
	}
	if pv.Action != "create" || pv.Instance.ID == 0 || pv.Instance.Name != "Demo 1" || len(pv.Hash) != 64 || pv.Danger {
		t.Fatalf("%+v", pv)
	}
	// A draft is invisible.
	if l, _ := h.m.Instances(ctx, "demo"); len(l) != 0 {
		t.Fatalf("draft listed: %+v", l)
	}
	if _, err := h.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: "bad"}); err == nil {
		t.Fatal("wrong hash accepted")
	}
	j := applyPlan(t, h, pv, false)
	if j.Status != store.JobDone {
		t.Fatalf("%s", jobLog(j))
	}
	log := jobLog(j)
	if strings.Contains(log, "pw-one") || !strings.Contains(log, "password is ***") {
		t.Fatalf("secret not masked:\n%s", log)
	}
	iid := pv.Instance.ID
	v, err := h.m.Instance(ctx, iid, true)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "ok" || len(v.Endpoints) != 1 || v.Endpoints[0].URL != "http://10.10.10.21:8080" ||
		len(v.Targets) != 1 || v.Targets[0] != web || v.Config["message"] != "hi" {
		t.Fatalf("%+v", v)
	}
	if ref, _ := v.Config["password"].(map[string]any); ref["set"] != true || ref["secret"] != "password" {
		t.Fatalf("password %+v", v.Config["password"])
	}
	inst, _ := h.st.GetInstance(ctx, iid)
	if strings.Contains(inst.Config, "pw-one") {
		t.Fatal("secret value in the config")
	}

	// Update: another target and message, the password is kept.
	pv, err = h.m.ChangePlan(ctx, iid, "update", map[string]any{"target": db, "message": "hey"})
	if err != nil {
		t.Fatal(err)
	}
	if j := applyPlan(t, h, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	gs, _ := h.st.Grants(ctx, iid)
	if len(gs) != 1 || gs[0].Ref != db {
		t.Fatalf("grants %+v", gs)
	}
	v, _ = h.m.Instance(ctx, iid, false)
	if v.Config["message"] != "hey" || v.Config["password"].(map[string]any)["set"] != true {
		t.Fatalf("%+v", v.Config)
	}

	// Remove: the instance and its secrets go.
	pv, err = h.m.ChangePlan(ctx, iid, "remove", nil)
	if err != nil {
		t.Fatal(err)
	}
	if j := applyPlan(t, h, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if _, err := h.st.GetInstance(ctx, iid); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("instance kept")
	}
	if ids, _ := h.st.SecretIDsByPrefix(ctx, instancePrefix("demo", iid)); len(ids) != 0 {
		t.Fatal("secrets kept")
	}
}

func TestPlanValidation(t *testing.T) {
	h, tp, web, _ := setupInstances(t, func(m *sdk.Manifest) {
		m.Schema.Fields[0].Filter = map[string]any{"docker_capable": true}
	})
	ctx := context.Background()
	_, err := h.m.CreatePlan(ctx, "demo", "x", map[string]any{"message": strings.Repeat("a", 30), "bogus": 1})
	wantFields(t, err, "target", "message", "bogus")
	_, err = h.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": "ssh:999"})
	wantFields(t, err, "target")
	// docker_capable: the SSH target has no known OS.
	_, err = h.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": web})
	wantFields(t, err, "target")
	_, err = h.m.CreatePlan(ctx, "demo", "a\nb", map[string]any{})
	wantFields(t, err, "name")

	// The plugin's own validation.
	h2, tp2, web2, _ := setupInstances(t, nil)
	tp2.validate = []sdk.FieldError{{Field: "message", Msg: "не нравится"}}
	_, err = h2.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": web2})
	wantFields(t, err, "message")
	_ = tp
	if l, _ := h2.st.ListInstances(ctx, "demo", true); len(l) != 0 {
		t.Fatal("a refused plan left a draft")
	}
}

func TestPlanStaleAndDanger(t *testing.T) {
	h, tp, web, _ := setupInstances(t, nil)
	ctx := context.Background()
	pv, err := h.m.CreatePlan(ctx, "demo", "one", map[string]any{"target": web})
	if err != nil {
		t.Fatal(err)
	}
	tp.mu.Lock()
	tp.planNonce = "changed"
	tp.mu.Unlock()
	_, err = h.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: pv.Hash})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 409 || !strings.Contains(pe.Msg, "Состояние изменилось") {
		t.Fatalf("%v", err)
	}
	if l, _ := h.st.ListInstances(ctx, "demo", true); len(l) != 0 {
		t.Fatal("draft of a stale plan kept")
	}
	// The plan is gone after the mismatch.
	if _, err := h.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: pv.Hash}); !errors.As(err, &pe) || pe.Status != 410 {
		t.Fatalf("%v", err)
	}

	tp.mu.Lock()
	tp.danger = true
	tp.mu.Unlock()
	pv, err = h.m.CreatePlan(ctx, "demo", "two", map[string]any{"target": web})
	if err != nil || !pv.Danger {
		t.Fatalf("%+v %v", pv, err)
	}
	if _, err := h.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: pv.Hash}); !errors.As(err, &pe) || pe.Status != 400 {
		t.Fatalf("danger without confirmation: %v", err)
	}
	if j := applyPlan(t, h, pv, true); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	// Expired plans are refused (and their drafts dropped).
	pv, _ = h.m.CreatePlan(ctx, "demo", "three", map[string]any{"target": web})
	h.m.Now = func() time.Time { return time.Now().Add(planTTL + time.Minute) }
	if _, err := h.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: pv.Hash, ConfirmDanger: true}); !errors.As(err, &pe) || pe.Status != 410 {
		t.Fatalf("%v", err)
	}
	if _, err := h.st.GetInstance(ctx, pv.Instance.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("draft of an expired plan kept")
	}
}

func TestApplyInterruptedByRestart(t *testing.T) {
	h, tp, web, _ := setupInstances(t, nil)
	ctx := context.Background()
	started := make(chan struct{})
	tp.applyHook = func(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
		_ = job.Step("Долгий шаг")
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	pv, err := h.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": web, "password": "pw"})
	if err != nil {
		t.Fatal(err)
	}
	job, err := h.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: pv.Hash})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	h.stopProc("demo") // the plugin process dies
	j := h.wait(job.ID)
	if j.Status != store.JobFailed || j.Error != msgRestarted {
		t.Fatalf("%s %q\n%s", j.Status, j.Error, jobLog(j))
	}
	if _, err := h.st.GetInstance(ctx, pv.Instance.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed create kept the instance")
	}
	if ids, _ := h.st.SecretIDsByPrefix(ctx, instancePrefix("demo", pv.Instance.ID)); len(ids) != 0 {
		t.Fatal("failed create kept secrets")
	}
	for _, s := range j.Steps {
		if s.Status == store.StepRunning {
			t.Fatalf("step left running: %+v", s)
		}
	}
}

// During an update plan the plugin may already reach the new target; the
// grant becomes permanent only after the apply.
func TestUpdatePlanSeesNewTarget(t *testing.T) {
	h, tp, web, db := setupInstances(t, nil)
	ctx := context.Background()
	pv, _ := h.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": web})
	if j := applyPlan(t, h, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	iid := pv.Instance.ID
	probe := &probePlugin{testPlugin: tp}
	h.plug = func(string) sdk.Plugin { return probe }
	h.stopProc("demo")
	h.waitDisconnected("demo")
	h.startProc("demo")
	h.waitConnected("demo")
	pv, err := h.m.ChangePlan(ctx, iid, "update", map[string]any{"target": db})
	if err != nil {
		t.Fatal(err)
	}
	if probe.err != nil {
		t.Fatalf("exec on the new target during plan: %v", probe.err)
	}
	// Outside a plan or apply the new target is not granted.
	if ok, _ := h.m.granted(ctx, iid, db); !ok {
		t.Fatal("live plan must extend grants")
	}
	h.m.mu.Lock()
	delete(h.m.plans, pv.PlanID)
	h.m.mu.Unlock()
	if ok, _ := h.m.granted(ctx, iid, db); ok {
		t.Fatal("grant leaked beyond the plan")
	}
}

type probePlugin struct {
	*testPlugin
	err error
}

func (p *probePlugin) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	if req.Action == sdk.ActionUpdate {
		_, p.err = sdk.HostFrom(ctx).Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Config.String("target"), Cmd: "echo x"})
	}
	return p.testPlugin.Plan(ctx, req)
}

func TestSingleInstance(t *testing.T) {
	h, _, web, _ := setupInstances(t, func(m *sdk.Manifest) { m.MultiInstance = false })
	ctx := context.Background()
	pv, _ := h.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": web})
	if j := applyPlan(t, h, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	_, err := h.m.CreatePlan(ctx, "demo", "y", map[string]any{"target": web})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 409 {
		t.Fatal(err)
	}
	// Plans need a connected, enabled plugin.
	h.stopProc("demo")
	h.waitDisconnected("demo")
	if _, err := h.m.ChangePlan(ctx, pv.Instance.ID, "remove", nil); !errors.As(err, &pe) || pe.Status != 409 {
		t.Fatal(err)
	}
}

func TestPeriodicStatus(t *testing.T) {
	h, _, web, _ := setupInstances(t, nil)
	ctx := context.Background()
	pv, _ := h.m.CreatePlan(ctx, "demo", "x", map[string]any{"target": web})
	if j := applyPlan(t, h, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	_ = h.st.SetInstanceStatus(ctx, pv.Instance.ID, "down", "", "[]", time.Now())
	h.m.refreshAll(ctx)
	in, _ := h.st.GetInstance(ctx, pv.Instance.ID)
	if in.Status != "ok" || in.CheckedAt == nil {
		t.Fatalf("%+v", in)
	}
}
