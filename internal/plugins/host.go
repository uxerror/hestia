package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// Limits of host calls.
const (
	maxSecret      = 64 << 10
	maxPutFile     = 4 << 20
	maxLogLine     = 4 << 10
	defaultExecS   = 60
	maxExecS       = 3600
	maxStdin       = 4 << 20
	maxCmd         = 64 << 10
	secretPurposeP = "plugin:"
)

var reSecretName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// denied is the error for a missing permission or grant.
func denied(what string, data map[string]any) error {
	e := rpc.Errorf(rpc.CodePermission, "permission denied: %s", what)
	if data != nil {
		e.Data, _ = json.Marshal(data)
	}
	return e
}

func badParams(format string, args ...any) error {
	return rpc.Errorf(rpc.CodeInvalidParams, format, args...)
}

// SecretPurpose is the secrets namespace of a plugin instance.
func SecretPurpose(pluginID string, instance int64, name string) string {
	return fmt.Sprintf("%s%s:%d:%s", secretPurposeP, pluginID, instance, name)
}

func instancePrefix(pluginID string, instance int64) string {
	return fmt.Sprintf("%s%s:%d:", secretPurposeP, pluginID, instance)
}

func pluginPrefix(pluginID string) string { return secretPurposeP + pluginID + ":" }

func (m *Manager) hostCall(ctx context.Context, s *session, method string, params json.RawMessage) (any, error) {
	pid := s.id()
	switch method {
	case sdk.MethodJobStep, sdk.MethodJobStepDone, sdk.MethodJobLog:
		return m.jobCall(pid, method, params)
	case sdk.MethodLog:
		var p sdk.LogLine
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры log")
		}
		lvl := slog.LevelInfo
		switch p.Level {
		case "warn":
			lvl = slog.LevelWarn
		case "error":
			lvl = slog.LevelError
		}
		slog.Log(ctx, lvl, "plugin "+pid+": "+truncate(p.Line, maxLogLine))
		return struct{}{}, nil
	case sdk.MethodSecretPut, sdk.MethodSecretGet, sdk.MethodSecretDelete:
		return m.secretCall(ctx, pid, method, params)
	case sdk.MethodTargetList:
		var p sdk.InstanceRef
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры target.list")
		}
		if !s.can(sdk.PermTargetsRead) {
			return nil, denied(sdk.PermTargetsRead, map[string]any{"permission": sdk.PermTargetsRead})
		}
		if err := m.ownInstance(ctx, pid, p.Instance); err != nil {
			return nil, err
		}
		return m.grantedTargets(ctx, p.Instance)
	case sdk.MethodTargetExec:
		var p sdk.ExecRequest
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры target.exec")
		}
		if err := m.checkTarget(ctx, s, p.Instance, p.Target); err != nil {
			return nil, err
		}
		return m.targetExec(ctx, pid, p)
	case sdk.MethodTargetPut:
		var p sdk.PutFileRequest
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры target.put_file")
		}
		if err := m.checkTarget(ctx, s, p.Instance, p.Target); err != nil {
			return nil, err
		}
		return m.targetPut(ctx, p)
	case sdk.MethodInventoryGet:
		if !s.can(sdk.PermInventoryRead) {
			return nil, denied(sdk.PermInventoryRead, map[string]any{"permission": sdk.PermInventoryRead})
		}
		return m.inventoryView(ctx)
	case sdk.MethodDeployPlan, sdk.MethodDeployUp, sdk.MethodDeployDown, sdk.MethodDeployStatus:
		return m.deployCall(ctx, s, method, params)
	}
	return nil, rpc.Errorf(rpc.CodeMethodNotFound, "метод %s не поддерживается", method)
}

// ownInstance checks that the instance belongs to the calling plugin.
func (m *Manager) ownInstance(ctx context.Context, pid string, iid int64) error {
	in, err := m.Store.GetInstance(ctx, iid)
	if errors.Is(err, store.ErrNotFound) {
		return denied(fmt.Sprintf("экземпляр %d не найден", iid), map[string]any{"instance": iid})
	}
	if err != nil {
		return err
	}
	if in.PluginID != pid {
		return denied(fmt.Sprintf("экземпляр %d принадлежит другому плагину", iid), map[string]any{"instance": iid})
	}
	return nil
}

// checkTarget enforces targets.exec, ownership of the instance and the grant
// of the target to the instance.
func (m *Manager) checkTarget(ctx context.Context, s *session, iid int64, ref string) error {
	return m.checkGrant(ctx, s, sdk.PermTargetsExec, iid, ref)
}

// checkGrant enforces a permission, ownership of the instance and the grant
// of the target to the instance.
func (m *Manager) checkGrant(ctx context.Context, s *session, perm string, iid int64, ref string) error {
	if !s.can(perm) {
		return denied(perm, map[string]any{"permission": perm})
	}
	if err := m.ownInstance(ctx, s.id(), iid); err != nil {
		return err
	}
	ok, err := m.granted(ctx, iid, ref)
	if err != nil {
		return err
	}
	if !ok {
		return denied(fmt.Sprintf("цель %s не выдана экземпляру %d", ref, iid), map[string]any{"instance": iid, "target": ref})
	}
	return nil
}

// granted: the database grants plus the targets of a plan or apply of this
// instance in progress (an update may move the instance to another target).
func (m *Manager) granted(ctx context.Context, iid int64, ref string) (bool, error) {
	if ref == "" {
		return false, nil
	}
	ok, err := m.Store.HasGrant(ctx, iid, ref)
	if err != nil || ok {
		return ok, err
	}
	// The device of a link: only within a link.* call of that link and
	// while the link (and its via_link grant) exists.
	m.mu.Lock()
	var calls []linkCall
	for _, lc := range m.linkCalls {
		if lc.instanceID == iid && lc.device == ref {
			calls = append(calls, lc)
		}
	}
	m.mu.Unlock()
	for _, lc := range calls {
		ok, err := m.Store.HasLinkGrant(ctx, iid, ref, lc.linkID)
		if err != nil || ok {
			return ok, err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Now()
	for _, p := range m.plans {
		if p.instanceID == iid && now.Before(p.expires) && hasRef(p.grants, ref) {
			return true, nil
		}
	}
	for _, a := range m.applying {
		if a.instanceID == iid && hasRef(a.grants, ref) {
			return true, nil
		}
	}
	for _, g := range m.planning {
		if g.instanceID == iid && hasRef(g.grants, ref) {
			return true, nil
		}
	}
	return false, nil
}

// planGrant extends the grants of an instance while the plugin plans a new
// configuration (an update may name a target the instance has not got yet).
type planGrant struct {
	instanceID int64
	grants     []store.PluginGrant
}

func (m *Manager) withPlanGrants(iid int64, gs []store.PluginGrant) func() {
	if len(gs) == 0 {
		return func() {}
	}
	id := randID()
	m.mu.Lock()
	m.planning[id] = planGrant{instanceID: iid, grants: gs}
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		delete(m.planning, id)
		m.mu.Unlock()
	}
}

func hasRef(gs []store.PluginGrant, ref string) bool {
	for _, g := range gs {
		if g.Ref == ref {
			return true
		}
	}
	return false
}

// grantedTargets lists the targets of an instance: its grants plus the
// targets of a plan or apply in progress (as granted() allows them).
func (m *Manager) grantedTargets(ctx context.Context, iid int64) ([]sdk.TargetInfo, error) {
	gs, err := m.Store.Grants(ctx, iid)
	if err != nil {
		return nil, err
	}
	refs := []string{}
	add := func(list []store.PluginGrant) {
		for _, g := range list {
			if !slices.Contains(refs, g.Ref) {
				refs = append(refs, g.Ref)
			}
		}
	}
	add(gs)
	m.mu.Lock()
	now := m.Now()
	for _, p := range m.plans {
		if p.instanceID == iid && now.Before(p.expires) {
			add(p.grants)
		}
	}
	for _, a := range m.applying {
		if a.instanceID == iid {
			add(a.grants)
		}
	}
	for _, g := range m.planning {
		if g.instanceID == iid {
			add(g.grants)
		}
	}
	m.mu.Unlock()
	cands, err := m.Candidates(ctx)
	if err != nil {
		return nil, err
	}
	out := []sdk.TargetInfo{}
	for _, ref := range refs {
		for _, c := range cands {
			if c.ID == ref {
				out = append(out, c.TargetInfo)
			}
		}
	}
	return out, nil
}

func (m *Manager) targetExec(ctx context.Context, pid string, p sdk.ExecRequest) (sdk.ExecResult, error) {
	if strings.TrimSpace(p.Cmd) == "" || len(p.Cmd) > maxCmd || strings.ContainsRune(p.Cmd, 0) {
		return sdk.ExecResult{}, badParams("пустая или слишком длинная команда")
	}
	if len(p.Stdin) > maxStdin {
		return sdk.ExecResult{}, badParams("stdin больше 4 МБ")
	}
	t := p.TimeoutS
	if t <= 0 {
		t = defaultExecS
	}
	if t > maxExecS {
		t = maxExecS
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t)*time.Second)
	defer cancel()
	var stdin []byte
	if p.Stdin != "" {
		stdin = []byte(p.Stdin)
	}
	res, err := m.Targets.Exec(ctx, p.Target, p.Cmd, stdin)
	var ee *sshx.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res = ee.Result
	default:
		return sdk.ExecResult{}, rpc.Errorf(rpc.CodeInternal, "цель %s: %v", p.Target, err)
	}
	return sdk.ExecResult{Code: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr}, nil
}

var reMode = regexp.MustCompile(`^0?[0-7]{3,4}$`)

func (m *Manager) targetPut(ctx context.Context, p sdk.PutFileRequest) (any, error) {
	if !strings.HasPrefix(p.Path, "/") || path.Clean(p.Path) != p.Path || strings.ContainsAny(p.Path, "\x00\n") || p.Path == "/" {
		return nil, badParams("путь должен быть абсолютным и без .. и //")
	}
	if p.Mode == "" {
		p.Mode = "0644"
	}
	if !reMode.MatchString(p.Mode) {
		return nil, badParams("неверный mode %q (ожидается восьмеричное число, например 0644)", p.Mode)
	}
	mode, _ := strconv.ParseUint(p.Mode, 8, 32)
	data, err := base64.StdEncoding.DecodeString(p.DataB64)
	if err != nil {
		return nil, badParams("data_b64: неверный base64")
	}
	if len(data) > maxPutFile {
		return nil, badParams("файл больше 4 МБ")
	}
	q := target.Quote(p.Path)
	cmd := fmt.Sprintf("umask 077 && cat > %s && chmod %04o %s", q, mode, q)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if _, err := m.Targets.Exec(ctx, p.Target, cmd, data); err != nil {
		return nil, rpc.Errorf(rpc.CodeInternal, "запись %s на %s: %v", p.Path, p.Target, err)
	}
	return struct{}{}, nil
}

func (m *Manager) secretCall(ctx context.Context, pid, method string, params json.RawMessage) (any, error) {
	var p sdk.SecretRequest
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, badParams("неверные параметры %s", method)
	}
	if strings.HasPrefix(p.Name, linkSecretP) {
		return m.linkSecretGet(ctx, pid, method, p)
	}
	if !reSecretName.MatchString(p.Name) {
		return nil, badParams("неверное имя секрета %q", p.Name)
	}
	if err := m.ownInstance(ctx, pid, p.Instance); err != nil {
		return nil, err
	}
	purpose := SecretPurpose(pid, p.Instance, p.Name)
	switch method {
	case sdk.MethodSecretPut:
		if len(p.Value) > maxSecret {
			return nil, badParams("секрет больше 64 КБ")
		}
		if err := m.putSecret(ctx, purpose, p.Value); err != nil {
			return nil, err
		}
		m.rememberSecret(pid, p.Instance, p.Value)
		return struct{}{}, nil
	case sdk.MethodSecretDelete:
		return struct{}{}, m.Store.DeleteSecretsByPurpose(ctx, purpose)
	}
	row, err := m.Store.GetSecretByPurpose(ctx, purpose)
	if errors.Is(err, store.ErrNotFound) {
		return sdk.SecretValue{}, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := m.Secrets.Get(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	return sdk.SecretValue{Value: string(v), Exists: true}, nil
}

// putSecret replaces the secret with this purpose.
func (m *Manager) putSecret(ctx context.Context, purpose, value string) error {
	if err := m.Store.DeleteSecretsByPurpose(ctx, purpose); err != nil {
		return err
	}
	_, err := m.Secrets.Put(ctx, purpose, []byte(value))
	return err
}

// instanceSecrets decrypts every secret of an instance (for masking logs).
func (m *Manager) instanceSecrets(ctx context.Context, pid string, iid int64) []string {
	ids, err := m.Store.SecretIDsByPrefix(ctx, instancePrefix(pid, iid))
	if err != nil {
		return nil
	}
	var out []string
	for _, id := range ids {
		if v, err := m.Secrets.Get(ctx, id); err == nil && len(v) > 0 {
			out = append(out, string(v))
		}
	}
	return out
}

// rememberSecret adds a value stored during an apply to the job's masks.
func (m *Manager) rememberSecret(pid string, iid int64, v string) {
	if v == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.applying {
		if a.pluginID == pid && a.instanceID == iid {
			a.addMask(v)
		}
	}
}

func (m *Manager) jobCall(pid, method string, params json.RawMessage) (any, error) {
	var p struct {
		JobID string `json:"job_id"`
		Title string `json:"title"`
		Error string `json:"error"`
		Level string `json:"level"`
		Line  string `json:"line"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, badParams("неверные параметры %s", method)
	}
	m.mu.Lock()
	a := m.applying[p.JobID]
	m.mu.Unlock()
	if a == nil || a.pluginID != pid {
		return nil, badParams("задача %s не найдена или уже завершена", p.JobID)
	}
	switch method {
	case sdk.MethodJobStep:
		a.step(truncate(a.mask(p.Title), 200))
	case sdk.MethodJobStepDone:
		var err error
		if p.Error != "" {
			err = errors.New(truncate(a.mask(p.Error), 2000))
		}
		a.stepDone(err)
	case sdk.MethodJobLog:
		lvl := p.Level
		if lvl != "warn" && lvl != "error" {
			lvl = "info"
		}
		a.run.Log(lvl, truncate(a.mask(p.Line), maxLogLine))
	}
	return struct{}{}, nil
}

// inventoryView is what inventory.get returns: the inventory of targets and
// the network map (as the API serves them).
func (m *Manager) inventoryView(ctx context.Context) (any, error) {
	out := map[string]any{"targets": []any{}, "network": nil}
	if m.Inventory != nil {
		list, err := m.Inventory.List(ctx)
		if err != nil {
			return nil, err
		}
		out["targets"] = list
	}
	if m.Netscan != nil {
		v, err := m.Netscan.View(ctx)
		if err != nil {
			return nil, err
		}
		out["network"] = v
	}
	return out, nil
}
