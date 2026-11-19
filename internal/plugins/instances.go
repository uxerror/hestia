package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// PlanView is a plan shown to the user.
type PlanView struct {
	PlanID   string       `json:"plan_id"`
	Hash     string       `json:"hash"`
	Action   string       `json:"action"`
	Instance InstanceRefV `json:"instance"`
	Plan     PlanBody     `json:"plan"`
	Danger   bool         `json:"danger"`
	// Steps of a composite plan (link, compose, removal with links); Plan
	// then holds the actions of all steps.
	Steps []StepView `json:"steps,omitempty"`
}

// InstanceRefV names the instance of a plan.
type InstanceRefV struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// PlanBody is the visible part of a plugin plan (data stays on the server).
type PlanBody struct {
	Actions  []sdk.Action `json:"actions"`
	Warnings []string     `json:"warnings"`
}

type planState struct {
	id         string
	hash       string
	pluginID   string
	instanceID int64
	name       string
	action     string
	config     sdk.Config        // new configuration (references instead of secrets)
	secrets    map[string]string // secret field → new value (applied with the plan)
	grants     []store.PluginGrant
	req        sdk.PlanRequest
	plan       sdk.Plan
	expires    time.Time
}

// applyJob is a running plugin-apply.
type applyJob struct {
	pluginID   string
	instanceID int64
	grants     []store.PluginGrant
	run        *jobs.Run
	// confirmed: the plan had a "danger" action and the user confirmed it
	// (deploy.up may then change container features).
	confirmed bool

	mu    sync.Mutex
	masks []string
	done  func(error)
}

func (a *applyJob) addMask(v string) {
	a.mu.Lock()
	a.masks = append(a.masks, v)
	a.mu.Unlock()
}

func (a *applyJob) mask(s string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return secrets.Mask(s, a.masks...)
}

func (a *applyJob) step(title string) {
	a.mu.Lock()
	prev := a.done
	a.done = nil
	a.mu.Unlock()
	if prev != nil {
		prev(nil)
	}
	d := a.run.BeginStep(title)
	a.mu.Lock()
	a.done = d
	a.mu.Unlock()
}

func (a *applyJob) stepDone(err error) {
	a.mu.Lock()
	d := a.done
	a.done = nil
	a.mu.Unlock()
	if d != nil {
		d(err)
	}
}

// pluginForInstances loads an enabled, connected plugin and its manifest.
func (m *Manager) pluginForInstances(ctx context.Context, id string) (store.Plugin, sdk.Manifest, error) {
	p, err := m.Store.GetPlugin(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return p, sdk.Manifest{}, newErr(http.StatusNotFound, "плагин не найден")
	}
	if err != nil {
		return p, sdk.Manifest{}, err
	}
	man, err := storedManifest(p.Manifest)
	if err != nil {
		return p, man, err
	}
	if !p.Enabled {
		return p, man, newErr(http.StatusConflict, "плагин отключён")
	}
	if m.conn(id) == nil {
		return p, man, newErr(http.StatusConflict, "плагин %s не подключён", id)
	}
	return p, man, nil
}

// normalize checks the submitted values against the schema and returns the
// configuration to store (secrets replaced by references), the new secret
// values and the target grants. prev is the stored configuration (update).
func (m *Manager) normalize(ctx context.Context, schema sdk.Schema, in map[string]any, prev sdk.Config, secretSet func(string) bool) (sdk.Config, map[string]string, []store.PluginGrant, error) {
	cfg := sdk.Config{}
	secs := map[string]string{}
	var grants []store.PluginGrant
	var errs []sdk.FieldError
	known := map[string]bool{}
	var cands []Candidate
	for _, f := range schema.Fields {
		known[f.Name] = true
		v, given := in[f.Name]
		if v == nil {
			given = false
		}
		switch f.Type {
		case sdk.FieldSecret:
			s, isStr := v.(string)
			switch {
			case given && !isStr:
				errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "ожидается строка"})
			case given && s != "":
				if len(s) > maxSecret {
					errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "слишком длинное значение"})
				}
				secs[f.Name] = s
				cfg[f.Name] = map[string]any{"secret": f.Name}
			case secretSet != nil && secretSet(f.Name):
				cfg[f.Name] = map[string]any{"secret": f.Name}
			case f.Required:
				errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "обязательное поле"})
			}
			continue
		case sdk.FieldTarget:
			s, _ := v.(string)
			if !given || s == "" {
				if f.Required {
					errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "выберите цель"})
				}
				continue
			}
			if cands == nil {
				var err error
				if cands, err = m.Candidates(ctx); err != nil {
					return nil, nil, nil, err
				}
			}
			ref, err := ParseRef(s)
			var c *Candidate
			for i := range cands {
				if cands[i].ID == s {
					c = &cands[i]
				}
			}
			kept := prev != nil && prev.String(f.Name) == s
			switch {
			case err != nil || c == nil:
				errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "цель не найдена"})
				continue
			case !c.Available && !kept:
				errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "цель недоступна: " + c.Reason})
				continue
			case wantsDocker(f) && !c.DockerCapable:
				errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "нужен Debian/Ubuntu с root или sudo"})
				continue
			}
			cfg[f.Name] = s
			grants = append(grants, store.PluginGrant{Kind: ref.Kind, Ref: s})
			continue
		}
		if !given {
			if f.Default != nil {
				v = f.Default
			} else {
				if f.Required {
					errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "обязательное поле"})
				}
				continue
			}
		}
		if f.Type == sdk.FieldInt {
			if n, ok := toInt(v); ok {
				v = n
			}
		}
		if s, ok := v.(string); ok && f.Required && strings.TrimSpace(s) == "" {
			errs = append(errs, sdk.FieldError{Field: f.Name, Msg: "обязательное поле"})
			continue
		}
		if msg := checkValue(f, v); msg != "" {
			errs = append(errs, sdk.FieldError{Field: f.Name, Msg: msg})
			continue
		}
		cfg[f.Name] = v
	}
	for k := range in {
		if !known[k] {
			errs = append(errs, sdk.FieldError{Field: k, Msg: "неизвестное поле"})
		}
	}
	if len(errs) > 0 {
		return nil, nil, nil, &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте поля формы", Fields: errs}
	}
	return cfg, secs, grants, nil
}

func wantsDocker(f sdk.Field) bool {
	b, _ := f.Filter["docker_capable"].(bool)
	return b
}

// validate asks the plugin about the configuration.
func (m *Manager) validate(ctx context.Context, pid string, cfg sdk.Config) error {
	var errs []sdk.FieldError
	if err := m.call(ctx, pid, sdk.MethodValidate, map[string]any{"config": cfg}, &errs); err != nil {
		return err
	}
	if len(errs) > 0 {
		for i := range errs {
			errs[i].Msg = truncate(errs[i].Msg, 300)
		}
		return &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте поля формы", Fields: errs}
	}
	return nil
}

// CreatePlan plans a new instance. The instance is recorded as a draft so
// that it has an id (and grants) while the plugin plans; drafts disappear
// with their plan.
func (m *Manager) CreatePlan(ctx context.Context, pid, name string, in map[string]any) (*PlanView, error) {
	if _, _, err := m.pluginForInstances(ctx, pid); err != nil {
		return nil, err
	}
	st, err := m.prepareCreate(ctx, pid, name, in, nil, nil)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.purgeLocked()
	m.plans[st.id] = st
	m.mu.Unlock()
	return st.view(), nil
}

// prepareCreate checks the form, records the draft instance and asks the
// plugin for its plan; the plan is not registered. own are the names of
// other new instances of the same composite plan (plugin id → names);
// links are the providers the instance will be linked to right after.
func (m *Manager) prepareCreate(ctx context.Context, pid, name string, in map[string]any, own map[string][]string, links []sdk.PlannedLink) (*planState, error) {
	_, man, err := m.pluginForInstances(ctx, pid)
	if err != nil {
		return nil, err
	}
	existing, err := m.Store.ListInstances(ctx, pid, false)
	if err != nil {
		return nil, err
	}
	taken := slices.Clone(existing)
	for _, n := range own[pid] {
		taken = append(taken, store.PluginInstance{Name: n})
	}
	if !man.MultiInstance && len(taken) > 0 {
		return nil, newErr(http.StatusConflict, "у плагина «%s» может быть только один экземпляр", man.Name)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultName(man.Name, taken)
	}
	if len([]rune(name)) > 100 || strings.ContainsAny(name, "\n\r") {
		return nil, &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте поля формы",
			Fields: []sdk.FieldError{{Field: "name", Msg: "одна строка, не длиннее 100 символов"}}}
	}
	for _, e := range taken {
		if e.Name == name {
			return nil, &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте поля формы",
				Fields: []sdk.FieldError{{Field: "name", Msg: "экземпляр с таким именем уже есть"}}}
		}
	}
	cfg, secs, grants, err := m.normalize(ctx, man.Schema, in, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := m.validate(ctx, pid, cfg); err != nil {
		return nil, err
	}
	m.dropPlansFor(pid, name)
	m.dropCompositesFor(pid, name)
	if err := m.Store.DeleteDrafts(ctx, pid, name); err != nil {
		return nil, err
	}
	cfgJSON, _ := json.Marshal(cfg)
	inst := &store.PluginInstance{PluginID: pid, Name: name, Config: string(cfgJSON), Status: store.InstanceDraft}
	if err := m.Store.CreateInstance(ctx, inst, grants); errors.Is(err, store.ErrDuplicate) {
		return nil, &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте поля формы",
			Fields: []sdk.FieldError{{Field: "name", Msg: "экземпляр с таким именем уже есть"}}}
	} else if err != nil {
		return nil, err
	}
	req := sdk.PlanRequest{Instance: sdk.Instance{ID: inst.ID, Name: name, Config: cfg}, Config: cfg, Action: sdk.ActionCreate, Links: links}
	st, err := m.buildPlan(ctx, pid, inst.ID, name, req, secs, grants)
	if err != nil {
		_ = m.Store.DeleteInstance(context.WithoutCancel(ctx), inst.ID)
		return nil, err
	}
	return st, nil
}

func defaultName(base string, existing []store.PluginInstance) string {
	for n := len(existing) + 1; ; n++ {
		name := fmt.Sprintf("%s %d", base, n)
		if !slices.ContainsFunc(existing, func(e store.PluginInstance) bool { return e.Name == name }) {
			return name
		}
	}
}

// ChangePlan plans an update (new configuration) or the removal of an
// instance.
func (m *Manager) ChangePlan(ctx context.Context, iid int64, action string, in map[string]any) (*PlanView, error) {
	inst, err := m.Store.GetInstance(ctx, iid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && inst.Status == store.InstanceDraft) {
		return nil, newErr(http.StatusNotFound, "экземпляр не найден")
	}
	if err != nil {
		return nil, err
	}
	_, man, err := m.pluginForInstances(ctx, inst.PluginID)
	if err != nil {
		return nil, err
	}
	cur := sdkInstance(inst)
	var (
		cfg    sdk.Config
		secs   map[string]string
		grants []store.PluginGrant
	)
	switch action {
	case sdk.ActionUpdate:
		cfg, secs, grants, err = m.normalize(ctx, man.Schema, in, cur.Config, func(name string) bool {
			_, err := m.Store.GetSecretByPurpose(ctx, SecretPurpose(inst.PluginID, iid, name))
			return err == nil
		})
		if err != nil {
			return nil, err
		}
		if err := m.validate(ctx, inst.PluginID, cfg); err != nil {
			return nil, err
		}
	case sdk.ActionRemove:
		cfg = cur.Config
		links, err := m.Store.LinksOfInstance(ctx, iid)
		if err != nil {
			return nil, err
		}
		if len(links) > 0 {
			// Its links go first, in the same plan.
			return m.removalPlan(ctx, inst, links)
		}
	default:
		return nil, newErr(http.StatusBadRequest, "action: update или remove")
	}
	req := sdk.PlanRequest{Instance: cur, Config: cfg, Action: action}
	return m.makePlan(ctx, inst.PluginID, iid, inst.Name, req, secs, grants)
}

func (m *Manager) makePlan(ctx context.Context, pid string, iid int64, name string, req sdk.PlanRequest, secs map[string]string, grants []store.PluginGrant) (*PlanView, error) {
	st, err := m.buildPlan(ctx, pid, iid, name, req, secs, grants)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.purgeLocked()
	m.plans[st.id] = st
	m.mu.Unlock()
	return st.view(), nil
}

// buildPlan asks the plugin for the plan of an instance change.
func (m *Manager) buildPlan(ctx context.Context, pid string, iid int64, name string, req sdk.PlanRequest, secs map[string]string, grants []store.PluginGrant) (*planState, error) {
	done := m.withPlanGrants(iid, grants)
	pl, err := m.requestPlan(ctx, pid, req)
	done()
	if err != nil {
		return nil, err
	}
	hash, err := planHash(pl, req.Config)
	if err != nil {
		return nil, err
	}
	return &planState{
		id: randID(), hash: hash, pluginID: pid, instanceID: iid, name: name, action: req.Action,
		config: req.Config, secrets: secs, grants: grants, req: req, plan: pl, expires: m.Now().Add(planTTL),
	}, nil
}

// replan asks the plugin for the plan again (before an apply) and returns
// it with its hash.
func (m *Manager) replan(ctx context.Context, st *planState) (sdk.Plan, string, error) {
	done := m.withPlanGrants(st.instanceID, st.grants)
	fresh, err := m.requestPlan(ctx, st.pluginID, st.req)
	done()
	if err != nil {
		return fresh, "", err
	}
	hash, err := planHash(fresh, st.config)
	return fresh, hash, err
}

func (st *planState) view() *PlanView {
	v := &PlanView{
		PlanID: st.id, Hash: st.hash, Action: st.action, Instance: InstanceRefV{ID: st.instanceID, Name: st.name},
		Plan: PlanBody{Actions: st.plan.Actions, Warnings: st.plan.Warnings},
	}
	for _, a := range st.plan.Actions {
		if a.Risk == sdk.RiskDanger {
			v.Danger = true
		}
	}
	return v
}

// requestPlan asks the plugin for a plan and sanitises it.
func (m *Manager) requestPlan(ctx context.Context, pid string, req sdk.PlanRequest) (sdk.Plan, error) {
	var pl sdk.Plan
	if err := m.call(ctx, pid, sdk.MethodPlan, req, &pl); err != nil {
		return pl, newErr(http.StatusBadGateway, "%v", err)
	}
	if len(pl.Actions) > 200 || len(pl.Warnings) > 50 || len(pl.Data) > 1<<20 {
		return pl, newErr(http.StatusBadGateway, "плагин вернул слишком большой план")
	}
	if pl.Actions == nil {
		pl.Actions = []sdk.Action{}
	}
	if pl.Warnings == nil {
		pl.Warnings = []string{}
	}
	for i := range pl.Actions {
		a := &pl.Actions[i]
		a.Title, a.Detail = truncate(a.Title, 300), truncate(a.Detail, 2000)
		switch a.Risk {
		case sdk.RiskInfo, sdk.RiskChange, sdk.RiskDanger:
		default:
			a.Risk = sdk.RiskChange
		}
	}
	for i := range pl.Warnings {
		pl.Warnings[i] = truncate(pl.Warnings[i], 1000)
	}
	return pl, nil
}

// planHash is sha256 of the canonical JSON of plan + config.
func planHash(pl sdk.Plan, cfg sdk.Config) (string, error) {
	b, err := json.Marshal(map[string]any{"plan": pl, "config": cfg})
	if err != nil {
		return "", err
	}
	c, err := canonical(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

func (m *Manager) dropPlansFor(pid, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.plans {
		if p.pluginID == pid && p.name == name && p.action == sdk.ActionCreate {
			delete(m.plans, id)
		}
	}
}

// ApplyRequest confirms a plan.
type ApplyRequest struct {
	Hash          string `json:"hash"`
	ConfirmDanger bool   `json:"confirm_danger"`
}

// Apply re-plans, compares the hash and starts the plugin-apply job.
func (m *Manager) Apply(ctx context.Context, planID string, req ApplyRequest) (store.Job, error) {
	m.mu.Lock()
	m.purgeLocked()
	st := m.plans[planID]
	cp := m.composites[planID]
	m.mu.Unlock()
	if cp != nil {
		return m.applyComposite(ctx, cp, req)
	}
	if st == nil {
		return store.Job{}, newErr(http.StatusGone, "План устарел или не найден — составьте его заново")
	}
	if st.hash != req.Hash {
		return store.Job{}, newErr(http.StatusBadRequest, "Подтверждён не тот план — составьте его заново")
	}
	if st.view().Danger && !req.ConfirmDanger {
		return store.Job{}, newErr(http.StatusBadRequest, "В плане есть опасные действия: подтвердите их отдельно")
	}
	if _, _, err := m.pluginForInstances(ctx, st.pluginID); err != nil {
		return store.Job{}, err
	}
	if m.instanceBusy(st.instanceID) {
		return store.Job{}, newErr(http.StatusConflict, "с этим экземпляром уже выполняется задача")
	}
	fresh, hash, err := m.replan(ctx, st)
	if err != nil {
		return store.Job{}, err
	}
	m.mu.Lock()
	if m.plans[planID] != st {
		m.mu.Unlock()
		return store.Job{}, newErr(http.StatusGone, "План устарел или не найден — составьте его заново")
	}
	if hash != st.hash {
		delete(m.plans, planID)
		m.mu.Unlock()
		if st.action == sdk.ActionCreate {
			_ = m.Store.DeleteInstance(context.WithoutCancel(ctx), st.instanceID)
		}
		return store.Job{}, newErr(http.StatusConflict, "Состояние изменилось, проверьте план ещё раз")
	}
	if m.instJobs[st.instanceID] {
		m.mu.Unlock()
		return store.Job{}, newErr(http.StatusConflict, "с этим экземпляром уже выполняется задача")
	}
	// The plan is used now: it no longer extends grants, the job does.
	delete(m.plans, planID)
	a := &applyJob{pluginID: st.pluginID, instanceID: st.instanceID, grants: st.grants,
		confirmed: st.view().Danger && req.ConfirmDanger}
	m.instJobs[st.instanceID] = true
	m.mu.Unlock()

	verb := map[string]string{sdk.ActionCreate: "создание", sdk.ActionUpdate: "изменение", sdk.ActionRemove: "удаление"}[st.action]
	title := fmt.Sprintf("%s: %s «%s»", st.pluginID, verb, st.name)
	job, err := m.Runner.Start(JobApply, title, func(ctx context.Context, run *jobs.Run) error {
		defer m.releaseInstances(st.instanceID)
		if err := m.runApply(ctx, run, st, fresh, a); err != nil {
			return err
		}
		if st.action == sdk.ActionUpdate {
			// The provider may give other data now (address, port).
			m.refreshProviderLinks(ctx, run, st.instanceID)
		}
		return nil
	})
	if err != nil {
		m.releaseInstances(st.instanceID)
		if st.action == sdk.ActionCreate {
			_ = m.Store.DeleteInstance(context.WithoutCancel(ctx), st.instanceID)
		}
	}
	return job, err
}

func (m *Manager) runApply(ctx context.Context, run *jobs.Run, st *planState, pl sdk.Plan, a *applyJob) (err error) {
	bg := context.WithoutCancel(ctx)
	a.run = run
	pid, iid := st.pluginID, st.instanceID
	for _, v := range m.instanceSecrets(ctx, pid, iid) {
		a.addMask(v)
	}
	for _, v := range st.secrets {
		a.addMask(v)
	}
	m.mu.Lock()
	m.applying[run.ID()] = a
	m.mu.Unlock()
	defer func() {
		a.stepDone(err)
		m.mu.Lock()
		delete(m.applying, run.ID())
		m.mu.Unlock()
	}()

	// Secrets from the form are stored before the plugin runs (it reads them
	// with secret.get); the old values come back if the apply fails.
	old := map[string]string{}
	err = run.Step("Сохранение секретов", func(ctx context.Context) error {
		for name, v := range st.secrets {
			purpose := SecretPurpose(pid, iid, name)
			if row, err := m.Store.GetSecretByPurpose(ctx, purpose); err == nil {
				if b, err := m.Secrets.Get(ctx, row.ID); err == nil {
					old[name] = string(b)
				}
			}
			if err := m.putSecret(ctx, purpose, v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	restoreSecrets := func() {
		for name := range st.secrets {
			purpose := SecretPurpose(pid, iid, name)
			if v, ok := old[name]; ok {
				_ = m.putSecret(bg, purpose, v)
			} else {
				_ = m.Store.DeleteSecretsByPurpose(bg, purpose)
			}
		}
	}

	s := m.conn(pid)
	if s == nil {
		restoreSecrets()
		m.failCreate(bg, run, st)
		return errors.New("плагин не подключён")
	}
	cur, gerr := m.Store.GetInstance(ctx, iid)
	if gerr != nil {
		return gerr
	}
	areq := sdk.ApplyRequest{JobID: run.ID(), Instance: sdkInstance(cur), Config: st.config, Action: st.action, Plan: pl, Links: st.req.Links}
	areq.Instance.Name = st.name
	if st.action == sdk.ActionCreate {
		areq.Instance.Config = st.config
	}
	callErr := s.conn.CallNoTimeout(ctx, sdk.MethodApply, areq, nil)
	a.stepDone(callErr)
	if callErr != nil {
		restoreSecrets()
		m.failCreate(bg, run, st)
		var re *rpc.Error
		switch {
		case errors.Is(callErr, rpc.ErrClosed):
			return errors.New(msgRestarted)
		case errors.As(callErr, &re):
			return errors.New(truncate(a.mask(re.Message), 2000))
		}
		return callErr
	}

	return run.Step("Запись в базу", func(ctx context.Context) error {
		cfgJSON, _ := json.Marshal(st.config)
		switch st.action {
		case sdk.ActionCreate:
			if err := m.Store.UpdateInstanceConfig(ctx, iid, string(cfgJSON), "unknown", st.grants); err != nil {
				return err
			}
		case sdk.ActionUpdate:
			status := cur.Status
			if err := m.Store.UpdateInstanceConfig(ctx, iid, string(cfgJSON), status, st.grants); err != nil {
				return err
			}
			// Secrets of fields that are no longer set are not removed: the
			// plugin may still use them; they go with the instance.
		case sdk.ActionRemove:
			if err := m.Store.DeleteSecretsByPrefix(ctx, instancePrefix(pid, iid)); err != nil {
				return err
			}
			return m.Store.DeleteInstance(ctx, iid)
		}
		go m.refreshInstance(m.ctx, iid)
		return nil
	})
}

// failCreate removes the draft of a failed create.
func (m *Manager) failCreate(ctx context.Context, run *jobs.Run, st *planState) {
	if st.action != sdk.ActionCreate {
		return
	}
	_ = m.Store.DeleteSecretsByPrefix(ctx, instancePrefix(st.pluginID, st.instanceID))
	_ = m.Store.DeleteInstance(ctx, st.instanceID)
	run.Log("warn", "Экземпляр не создан. Плагин мог оставить изменения на цели — проверьте лог выше.")
}

// ---- status ----

// instanceStatus asks the plugin and records the answer.
func (m *Manager) instanceStatus(ctx context.Context, pid string, inst store.PluginInstance) (sdk.Status, error) {
	var st sdk.Status
	if err := m.call(ctx, pid, sdk.MethodStatus, map[string]any{"instance": sdkInstance(inst)}, &st); err != nil {
		return st, err
	}
	switch st.State {
	case sdk.StateOK, sdk.StateDegraded, sdk.StateDown, sdk.StateUnknown:
	default:
		st.State = sdk.StateUnknown
	}
	st.Detail = truncate(st.Detail, 1000)
	st.Endpoints = safeEndpoints(st.Endpoints)
	eps, _ := json.Marshal(st.Endpoints)
	if err := m.Store.SetInstanceStatus(ctx, inst.ID, st.State, st.Detail, string(eps), m.Now().UTC()); err != nil {
		return st, err
	}
	return st, nil
}

// safeEndpoints keeps only http(s) links (the UI renders them).
func safeEndpoints(in []sdk.Endpoint) []sdk.Endpoint {
	out := []sdk.Endpoint{}
	for _, e := range in {
		u, err := url.Parse(e.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			continue
		}
		out = append(out, sdk.Endpoint{Name: truncate(e.Name, 100), URL: u.String()})
		if len(out) == 20 {
			break
		}
	}
	return out
}

// RefreshInstance asks the plugin for the status of one instance now.
func (m *Manager) RefreshInstance(ctx context.Context, iid int64) error {
	inst, err := m.Store.GetInstance(ctx, iid)
	if err != nil {
		return err
	}
	_, err = m.instanceStatus(ctx, inst.PluginID, inst)
	return err
}

func (m *Manager) refreshInstance(ctx context.Context, iid int64) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_ = m.RefreshInstance(cctx, iid)
}

// refreshPlugin updates the status of every instance of a plugin.
func (m *Manager) refreshPlugin(ctx context.Context, pid string) {
	list, err := m.Store.ListInstances(ctx, pid, false)
	if err != nil {
		return
	}
	for _, in := range list {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, _ = m.instanceStatus(cctx, pid, in)
		cancel()
	}
}

// refreshAll is the periodic check of enabled, connected plugins (RPC only).
func (m *Manager) refreshAll(ctx context.Context) {
	ps, err := m.Store.ListPlugins(ctx)
	if err != nil {
		return
	}
	for _, p := range ps {
		if p.Enabled && m.conn(p.ID) != nil {
			m.refreshPlugin(ctx, p.ID)
		}
	}
}
