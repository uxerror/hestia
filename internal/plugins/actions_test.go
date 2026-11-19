package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// actPlugin has actions; it logs its secret parameter (Hestia must mask it).
type actPlugin struct {
	testPlugin
	mu       sync.Mutex
	got      sdk.ActionRequest
	big      bool
	disabled bool
}

func (p *actPlugin) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := sdk.Status{State: sdk.StateOK, Endpoints: []sdk.Endpoint{}}
	if p.disabled {
		st.ActionsEnabled = []string{"other"}
	}
	return st, nil
}

func (p *actPlugin) Action(ctx context.Context, req sdk.ActionRequest, job *sdk.Job) (sdk.ActionResult, error) {
	p.mu.Lock()
	p.got = req
	big := p.big
	p.mu.Unlock()
	job.Logf("получен пароль %s", req.Params.String("passphrase"))
	if req.Action == "fail" {
		return sdk.ActionResult{}, errors.New("не вышло: " + req.Params.String("passphrase"))
	}
	data := []byte("backup-bytes")
	if big {
		data = make([]byte, sdk.MaxDownload+1)
	}
	return sdk.ActionResult{Message: "готово", Download: &sdk.Download{Name: "backup.json", MIME: "application/json", Data: data}}, nil
}

func TestInstanceActions(t *testing.T) {
	h := newHarness(t)
	ap := &actPlugin{}
	plain := &testPlugin{}
	h.plug = func(id string) sdk.Plugin {
		if id == "plain" {
			return plain
		}
		return ap
	}
	key := newKey(t)
	fields := []sdk.Field{{Name: "passphrase", Type: sdk.FieldSecret, Label: "Пароль", Required: true, MinLen: 12}}
	for _, id := range []string{"demo", "plain"} {
		id := id
		if j := h.install(testPackage(t, key, func(m *sdk.Manifest) {
			m.ID = id
			m.Actions = []sdk.ActionDef{{Name: "backup", Label: "Резервная копия", Confirm: sdk.ConfirmPassword, Fields: fields},
				{Name: "fail", Label: "Сбой", Fields: fields}, {Name: "other", Label: "Другое"}}
		})); j.Status != store.JobDone {
			t.Fatal(jobLog(j))
		}
		h.waitConnected(id)
	}
	web := addSSHTarget(t, h, "web", "10.10.10.21")
	le := &linkEnv{harness: h, rec: &recorder{}}
	iid := le.create("demo", "A", map[string]any{"target": web})
	pid := le.create("plain", "P", map[string]any{"target": web})
	ctx := context.Background()
	secret := "very-secret-passphrase-42"

	if _, def, err := h.m.ActionDef(ctx, iid, "backup"); err != nil || def.Confirm != sdk.ConfirmPassword {
		t.Fatalf("def %+v %v", def, err)
	}
	if _, _, err := h.m.ActionDef(ctx, iid, "nosuch"); err == nil || err.(*Error).Status != http.StatusNotFound {
		t.Fatalf("unknown action: %v", err)
	}
	// Fields are checked: unknown, missing, too short.
	for _, in := range []map[string]any{{"x": 1, "passphrase": secret}, {}, {"passphrase": "short"}} {
		if _, err := h.m.RunAction(ctx, iid, "backup", in); err == nil || err.(*Error).Status != http.StatusUnprocessableEntity {
			t.Fatalf("%v: %v", in, err)
		}
	}
	res, err := h.m.RunAction(ctx, iid, "backup", map[string]any{"passphrase": secret})
	if err != nil || res.Download == nil || string(res.Download.Data) != "backup-bytes" || res.Message != "готово" {
		t.Fatalf("run %+v %v", res, err)
	}
	ap.mu.Lock()
	got := ap.got
	ap.mu.Unlock()
	if got.Params.String("passphrase") != secret || got.Instance.ID != iid {
		t.Fatalf("plugin got %+v", got)
	}
	// A failure with the secret in its message: masked.
	_, err = h.m.RunAction(ctx, iid, "fail", map[string]any{"passphrase": secret})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("fail: %v", err)
	}
	// The parameters are nowhere: jobs, logs, the database.
	jobsList, _ := h.st.ListJobs(ctx, 100)
	found := 0
	for _, j := range jobsList {
		if j.Kind != JobAction {
			continue
		}
		found++
		full, _ := h.st.GetJob(ctx, j.ID)
		b, _ := json.Marshal(full)
		if strings.Contains(string(b), secret) {
			t.Fatalf("job %s has the secret: %s", j.ID, b)
		}
	}
	if found != 2 {
		t.Fatalf("action jobs: %d", found)
	}
	files, _ := filepath.Glob(filepath.Join(h.m.DataDir, "*"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), secret) {
			t.Fatalf("%s has the secret", f)
		}
	}
	// More than 1 MB: refused.
	ap.mu.Lock()
	ap.big = true
	ap.mu.Unlock()
	if _, err := h.m.RunAction(ctx, iid, "backup", map[string]any{"passphrase": secret}); err == nil || !strings.Contains(err.Error(), "1 МБ") {
		t.Fatalf("big: %v", err)
	}
	// Not enabled by the status: 409.
	ap.mu.Lock()
	ap.disabled = true
	ap.mu.Unlock()
	if err := h.m.RefreshInstance(ctx, iid); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.RunAction(ctx, iid, "backup", map[string]any{"passphrase": secret}); err == nil || err.(*Error).Status != http.StatusConflict {
		t.Fatalf("disabled: %v", err)
	}
	if h.m.ActionsEnabled(iid) == nil {
		t.Fatal("actions_enabled not recorded")
	}
	// A plugin without instance.action: 501.
	if _, err := h.m.RunAction(ctx, pid, "other", nil); err == nil || err.(*Error).Status != http.StatusNotImplemented {
		t.Fatalf("no actions: %v", err)
	}
}

func TestManifestActionsAndImages(t *testing.T) {
	base := func() sdk.Manifest {
		var m sdk.Manifest
		_ = json.Unmarshal(testManifest(newKey(t), nil), &m)
		return m
	}
	cases := []struct {
		mod  func(*sdk.Manifest)
		want string
	}{
		{func(m *sdk.Manifest) { m.Actions = []sdk.ActionDef{{Name: "Bad", Label: "x"}} }, "неверное имя действия"},
		{func(m *sdk.Manifest) { m.Actions = []sdk.ActionDef{{Name: "a", Label: "x"}, {Name: "a", Label: "y"}} }, "дважды"},
		{func(m *sdk.Manifest) { m.Actions = []sdk.ActionDef{{Name: "a", Label: ""}} }, "label"},
		{func(m *sdk.Manifest) { m.Actions = []sdk.ActionDef{{Name: "a", Label: "x", Confirm: "yes"}} }, "confirm"},
		{func(m *sdk.Manifest) {
			m.Actions = []sdk.ActionDef{{Name: "a", Label: "x", Fields: []sdk.Field{{Name: "t", Type: sdk.FieldTarget, Label: "T"}}}}
		}, "недопустим в действии"},
		{func(m *sdk.Manifest) {
			m.Images = []sdk.Image{{Name: "Bad", File: "image-Bad"}}
			m.Permissions = append(m.Permissions, sdk.PermDeployDocker)
		}, "неверное имя образа"},
		{func(m *sdk.Manifest) { m.ID = "hestia" }, "зарезервирован"},
	}
	for i, c := range cases {
		m := base()
		c.mod(&m)
		if err := ValidateManifest(m); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("case %d: want %q, got %v", i, c.want, err)
		}
	}
	_ = types.TLSCertType
}
