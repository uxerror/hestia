package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

// Job kinds of links and composite plans.
const (
	JobLink    = "plugin-link"
	JobCompose = "plugin-compose"
)

// Kinds of composite plans.
const (
	compLink    = "link"    // create or remove one link
	compRemove  = "remove"  // remove an instance with its links
	compCompose = "compose" // new providers → instance → links
)

// MaxComposeDepth bounds the nesting of new providers in a composite plan.
const MaxComposeDepth = 3

// StepView is a step of a composite plan as the user sees it.
type StepView struct {
	Kind     string   `json:"kind"` // instance | link
	Action   string   `json:"action"`
	Title    string   `json:"title"`
	Plan     PlanBody `json:"plan"`
	Rollback string   `json:"rollback,omitempty"`
}

// compStep is one step: an instance change or a link change.
type compStep struct {
	inst *planState
	link *linkStep
	// forget: an orphaned link whose record only is removed.
	forget bool
}

func (s *compStep) hash() (string, error) {
	if s.link != nil {
		h, err := s.link.hash()
		if s.forget {
			h = "forget:" + h
		}
		return h, err
	}
	return fmt.Sprintf("%s:%d:%s", s.inst.action, s.inst.instanceID, s.inst.hash), nil
}

func (s *compStep) view(kind string) StepView {
	if s.link != nil {
		v := StepView{Kind: "link", Action: s.link.action, Title: linkVerb(s.link.action) + " связь " + s.link.title()}
		if s.forget {
			v.Title = "Удалить запись о связи " + s.link.title()
			v.Plan = PlanBody{Actions: []sdk.Action{{Title: "Удалить запись о связи (стороны не вызываются)", Risk: sdk.RiskChange}}, Warnings: []string{
				"Плагины могли оставить настройки этой связи — проверьте их вручную."}}
			return v
		}
		v.Plan = PlanBody{Actions: []sdk.Action{}, Warnings: []string{}}
		for _, side := range s.link.sides() {
			pl := s.link.planOf(side)
			for _, a := range pl.Actions {
				a.Title = side.inst.Name + ": " + a.Title
				v.Plan.Actions = append(v.Plan.Actions, a)
			}
			for _, w := range pl.Warnings {
				v.Plan.Warnings = append(v.Plan.Warnings, side.inst.Name+": "+w)
			}
		}
		if kind == compCompose {
			v.Rollback = "при ошибке позже связь будет удалена"
		}
		return v
	}
	verb := map[string]string{sdk.ActionCreate: "Создать", sdk.ActionUpdate: "Изменить", sdk.ActionRemove: "Удалить"}[s.inst.action]
	v := StepView{Kind: "instance", Action: s.inst.action, Title: fmt.Sprintf("%s экземпляр «%s» (%s)", verb, s.inst.name, s.inst.pluginID),
		Plan: PlanBody{Actions: s.inst.plan.Actions, Warnings: s.inst.plan.Warnings}}
	if kind == compCompose && s.inst.action == sdk.ActionCreate {
		v.Rollback = "при ошибке позже экземпляр будет удалён (instance remove)"
	}
	return v
}

func linkVerb(action string) string {
	switch action {
	case sdk.ActionRemove:
		return "Удалить"
	case actionReissue:
		return "Перевыпустить"
	}
	return "Создать"
}

// instances lists the instances the step works on.
func (s *compStep) instances() []int64 {
	if s.link != nil {
		ids := []int64{s.link.provider.inst.ID}
		if s.link.consumer != nil {
			ids = append(ids, s.link.consumer.inst.ID)
		}
		return ids
	}
	return []int64{s.inst.instanceID}
}

// compositePlan is a plan of several steps applied by one job.
type compositePlan struct {
	id      string
	hash    string
	kind    string
	title   string
	root    InstanceRefV
	steps   []*compStep
	expires time.Time
	// drafts and draftLinks were created by the plan and go with it if it
	// is not applied.
	drafts     []int64
	draftLinks []int64
}

func (cp *compositePlan) computeHash() error {
	sum := sha256.New()
	sum.Write([]byte(cp.kind + "\n"))
	for _, s := range cp.steps {
		h, err := s.hash()
		if err != nil {
			return err
		}
		sum.Write([]byte(h + "\n"))
	}
	cp.hash = hex.EncodeToString(sum.Sum(nil))
	return nil
}

func (cp *compositePlan) view() *PlanView {
	v := &PlanView{PlanID: cp.id, Hash: cp.hash, Action: cp.kind, Instance: cp.root,
		Plan: PlanBody{Actions: []sdk.Action{}, Warnings: []string{}}, Steps: []StepView{}}
	for _, s := range cp.steps {
		sv := s.view(cp.kind)
		v.Steps = append(v.Steps, sv)
		for _, a := range sv.Plan.Actions {
			if s.inst != nil {
				a.Title = s.inst.name + ": " + a.Title
			}
			if a.Risk == sdk.RiskDanger {
				v.Danger = true
			}
			v.Plan.Actions = append(v.Plan.Actions, a)
		}
		v.Plan.Warnings = append(v.Plan.Warnings, sv.Plan.Warnings...)
	}
	return v
}

func (cp *compositePlan) instances() []int64 {
	var out []int64
	for _, s := range cp.steps {
		for _, id := range s.instances() {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// register stores the plan (until planTTL).
func (m *Manager) register(cp *compositePlan) (*PlanView, error) {
	cp.id = randID()
	cp.expires = m.Now().Add(planTTL)
	if err := cp.computeHash(); err != nil {
		m.dropDrafts(context.Background(), cp)
		return nil, err
	}
	m.mu.Lock()
	m.purgeLocked()
	m.composites[cp.id] = cp
	m.mu.Unlock()
	return cp.view(), nil
}

// dropDrafts removes what a plan created and was not applied.
func (m *Manager) dropDrafts(ctx context.Context, cp *compositePlan) {
	ctx = context.WithoutCancel(ctx)
	for _, id := range cp.draftLinks {
		if l, err := m.Store.GetLink(ctx, id); err == nil && l.Status == store.LinkDraft {
			_ = m.Store.DeleteLink(ctx, id)
		}
	}
	for i := len(cp.drafts) - 1; i >= 0; i-- {
		if in, err := m.Store.GetInstance(ctx, cp.drafts[i]); err == nil && in.Status == store.InstanceDraft {
			_ = m.Store.DeleteSecretsByPrefix(ctx, instancePrefix(in.PluginID, in.ID))
			_ = m.Store.DeleteInstance(ctx, in.ID)
		}
	}
}

// purgeCompositesLocked drops expired composite plans (m.mu held).
func (m *Manager) purgeCompositesLocked() {
	now := m.Now()
	for id, cp := range m.composites {
		if now.After(cp.expires) {
			delete(m.composites, id)
			go m.dropDrafts(context.Background(), cp)
		}
	}
}

// dropPlansWithLink drops the composite plans holding a draft link.
func (m *Manager) dropPlansWithLink(link int64) {
	m.mu.Lock()
	var gone []*compositePlan
	for id, cp := range m.composites {
		if slices.Contains(cp.draftLinks, link) {
			delete(m.composites, id)
			gone = append(gone, cp)
		}
	}
	m.mu.Unlock()
	for _, cp := range gone {
		m.dropDrafts(context.Background(), cp)
	}
}

// dropCompositesFor drops the composite plans creating an instance with
// this plugin and name (a new plan with the same name replaces them).
func (m *Manager) dropCompositesFor(pid, name string) {
	m.mu.Lock()
	var gone []*compositePlan
	for id, cp := range m.composites {
		for _, s := range cp.steps {
			if s.inst != nil && s.inst.action == sdk.ActionCreate && s.inst.pluginID == pid && s.inst.name == name {
				delete(m.composites, id)
				gone = append(gone, cp)
				break
			}
		}
	}
	m.mu.Unlock()
	for _, cp := range gone {
		m.dropDrafts(context.Background(), cp)
	}
}

// instanceBusy reports whether a job works on the instance.
func (m *Manager) instanceBusy(iid int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instJobs[iid] {
		return true
	}
	for _, a := range m.applying {
		if a.instanceID == iid {
			return true
		}
	}
	return false
}

func (m *Manager) releaseInstances(ids ...int64) {
	m.mu.Lock()
	for _, id := range ids {
		delete(m.instJobs, id)
	}
	m.mu.Unlock()
}

// ---- link plans ----

// LinkPlan plans a new link (both sides).
func (m *Manager) LinkPlan(ctx context.Context, req LinkPlanRequest) (*PlanView, error) {
	ls, err := m.newLinkStep(ctx, req, false)
	if err != nil {
		return nil, err
	}
	cp := &compositePlan{kind: compLink, title: "связь " + ls.title(), root: InstanceRefV{ID: ls.provider.inst.ID, Name: ls.provider.inst.Name},
		steps: []*compStep{{link: ls}}, draftLinks: []int64{ls.link.ID}}
	if err := m.planSides(ctx, ls); err != nil {
		m.dropDrafts(ctx, cp)
		return nil, err
	}
	return m.register(cp)
}

// LinkChangePlan plans the removal of a link ("remove"); an orphaned link
// loses its record only.
func (m *Manager) LinkChangePlan(ctx context.Context, id int64, action string) (*PlanView, error) {
	if action != sdk.ActionRemove && action != actionReissue {
		return nil, newErr(http.StatusBadRequest, "action: remove или reissue")
	}
	l, err := m.Store.GetLink(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && l.Status == store.LinkDraft) {
		return nil, newErr(http.StatusNotFound, "связь не найдена")
	}
	if err != nil {
		return nil, err
	}
	if l.Status == store.LinkApplying || l.Status == store.LinkRemoving {
		return nil, newErr(http.StatusConflict, "со связью уже выполняется задача")
	}
	if action == actionReissue {
		if l.Status == store.LinkOrphaned {
			return nil, newErr(http.StatusConflict, "связь осиротела — её можно только удалить")
		}
		return m.reissuePlan(ctx, l)
	}
	step, err := m.linkRemovalStep(ctx, l)
	if err != nil {
		return nil, err
	}
	cp := &compositePlan{kind: compLink, title: "удаление связи " + step.link.title(),
		root: InstanceRefV{ID: step.link.provider.inst.ID, Name: step.link.provider.inst.Name}, steps: []*compStep{step}}
	return m.register(cp)
}

// linkRemovalStep builds the removal of an existing link with both plans.
func (m *Manager) linkRemovalStep(ctx context.Context, l store.PluginLink) (*compStep, error) {
	ls, err := m.existingLinkStep(ctx, l)
	if err != nil {
		if l.Status != store.LinkOrphaned {
			return nil, err
		}
		// A side is gone or not connected: only the record can go.
		ls = &linkStep{action: sdk.ActionRemove, link: l, config: sdk.Config{},
			provider: linkSide{role: sdk.RoleProvider, inst: store.PluginInstance{ID: l.ProviderInstance, Name: fmt.Sprintf("экземпляр %d", l.ProviderInstance)}}}
		if l.Kind == store.LinkKindService {
			ls.consumer = &linkSide{role: sdk.RoleConsumer, inst: store.PluginInstance{ID: l.ConsumerInstance, Name: fmt.Sprintf("экземпляр %d", l.ConsumerInstance)}}
		}
		return &compStep{link: ls, forget: true}, nil
	}
	if l.Status == store.LinkOrphaned {
		return &compStep{link: ls, forget: true}, nil
	}
	if err := m.planSides(ctx, ls); err != nil {
		return nil, err
	}
	return &compStep{link: ls}, nil
}

// removalPlan removes an instance with its links: the links first.
func (m *Manager) removalPlan(ctx context.Context, inst store.PluginInstance, links []store.PluginLink) (*PlanView, error) {
	cp := &compositePlan{kind: compRemove, title: fmt.Sprintf("удаление «%s» со связями", inst.Name), root: InstanceRefV{ID: inst.ID, Name: inst.Name}}
	for _, l := range links {
		if l.Status == store.LinkApplying || l.Status == store.LinkRemoving {
			return nil, newErr(http.StatusConflict, "со связью %d уже выполняется задача", l.ID)
		}
		step, err := m.linkRemovalStep(ctx, l)
		if err != nil {
			return nil, err
		}
		cp.steps = append(cp.steps, step)
	}
	req := sdk.PlanRequest{Instance: sdkInstance(inst), Config: sdkInstance(inst).Config, Action: sdk.ActionRemove}
	st, err := m.buildPlan(ctx, inst.PluginID, inst.ID, inst.Name, req, nil, nil)
	if err != nil {
		return nil, err
	}
	cp.steps = append(cp.steps, &compStep{inst: st})
	return m.register(cp)
}

// ---- compose ----

// ComposeRequest is POST /plugins/compose/plan: a new instance (root) with
// its dependencies, each an existing provider or a new one (nested).
type ComposeRequest struct {
	Root ComposeNode  `json:"root"`
	Deps []ComposeDep `json:"deps"`
}

// ComposeNode is a new instance of a composite plan. Port (for a new
// provider) is its provides port to link; it may be omitted when exactly
// one port fits.
type ComposeNode struct {
	PluginID string         `json:"plugin_id"`
	Name     string         `json:"name"`
	Config   map[string]any `json:"config"`
	Port     string         `json:"port,omitempty"`
	Deps     []ComposeDep   `json:"deps,omitempty"`
}

// ComposeDep closes a requires port of its node.
type ComposeDep struct {
	Port     string       `json:"port"`
	Existing *LinkEnd     `json:"existing,omitempty"`
	New      *ComposeNode `json:"new,omitempty"`
}

// composer builds a composite plan.
type composer struct {
	m     *Manager
	cp    *compositePlan
	own   map[string][]string // plugin id → names of the new instances
	links []*linkStep
}

// prefixFields puts the path of a nested node in front of field names.
func prefixFields(err error, path string) error {
	var pe *Error
	if path == "" || !errors.As(err, &pe) {
		return err
	}
	out := *pe
	out.Fields = nil
	for _, f := range pe.Fields {
		out.Fields = append(out.Fields, sdk.FieldError{Field: path + f.Field, Msg: f.Msg})
	}
	if len(pe.Fields) > 0 {
		var parts []string
		for _, f := range pe.Fields {
			parts = append(parts, f.Field+" — "+f.Msg)
		}
		out.Msg = pe.Msg + ": " + strings.Join(parts, "; ")
	}
	return &out
}

func depErr(field, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте зависимости: " + msg, Fields: []sdk.FieldError{{Field: field, Msg: msg}}}
}

// ComposePlan plans a new instance with its dependencies.
func (m *Manager) ComposePlan(ctx context.Context, req ComposeRequest) (*PlanView, error) {
	root := req.Root
	root.Deps = append(slices.Clone(req.Deps), root.Deps...)
	if root.PluginID == "" {
		return nil, depErr("root.plugin_id", "укажите плагин")
	}
	c := &composer{m: m, cp: &compositePlan{kind: compCompose}, own: map[string][]string{}}
	// The tree is checked before anything is recorded.
	if err := c.check(ctx, &root, "", nil); err != nil {
		return nil, err
	}
	rootID, err := c.build(ctx, &root, "")
	if err != nil {
		m.dropDrafts(ctx, c.cp)
		return nil, err
	}
	for _, ls := range c.links {
		if err := m.planSides(ctx, ls); err != nil {
			m.dropDrafts(ctx, c.cp)
			return nil, err
		}
		c.cp.steps = append(c.cp.steps, &compStep{link: ls})
	}
	for _, s := range c.cp.steps {
		if s.inst != nil && s.inst.instanceID == rootID {
			c.cp.root = InstanceRefV{ID: rootID, Name: s.inst.name}
		}
	}
	c.cp.title = fmt.Sprintf("создание «%s» с зависимостями", c.cp.root.Name)
	return m.register(c.cp)
}

// check validates a node and its subtree: plugins, ports, depth and cycles
// (chain holds the plugins from the root).
func (c *composer) check(ctx context.Context, n *ComposeNode, path string, chain []string) error {
	if len(chain) > MaxComposeDepth {
		return depErr(strings.TrimSuffix(path, "."), "слишком глубокая вложенность новых поставщиков (не больше %d)", MaxComposeDepth)
	}
	if slices.Contains(chain, n.PluginID) {
		return depErr(strings.TrimSuffix(path, "."), "цикл: плагин %s уже есть в цепочке зависимостей", n.PluginID)
	}
	_, man, err := c.m.pluginForInstances(ctx, n.PluginID)
	if err != nil {
		return prefixFields(err, path)
	}
	chain = append(slices.Clone(chain), n.PluginID)
	used := map[string]int{}
	for i, d := range n.Deps {
		dp := fmt.Sprintf("%sdeps[%d].", path, i)
		port, ok := findPort(man.Requires, d.Port)
		if !ok {
			return depErr(dp+"port", "у плагина %s нет порта requires %q", n.PluginID, d.Port)
		}
		used[port.PortName()]++
		if used[port.PortName()] > 1 && !port.IsMulti(false) {
			return depErr(dp+"port", "к порту %s подключается только один поставщик", portLabel(port))
		}
		switch {
		case (d.Existing == nil) == (d.New == nil):
			return depErr(dp+"port", "укажите существующего поставщика (existing) или нового (new)")
		case d.Existing != nil:
			inst, pman, _, err := c.m.linkInstance(ctx, d.Existing.Instance, false)
			if err != nil {
				return prefixFields(err, dp+"existing.")
			}
			pp, ok := findPort(pman.Provides, d.Existing.Port)
			if !ok {
				return depErr(dp+"existing.port", "у «%s» нет порта provides %q", inst.Name, d.Existing.Port)
			}
			if pp.Type != port.Type {
				return depErr(dp+"existing.port", "несовместимые типы: %s и %s", pp.Type, port.Type)
			}
		default:
			if err := c.check(ctx, d.New, dp+"new.", chain); err != nil {
				return err
			}
			_, nman, err := c.m.pluginForInstances(ctx, d.New.PluginID)
			if err != nil {
				return prefixFields(err, dp+"new.")
			}
			if _, err := providerPort(nman, d.New.Port, port.Type); err != nil {
				return depErr(dp+"new.port", "%s", err.Error())
			}
		}
	}
	for _, r := range man.Requires {
		if !r.Optional && used[r.PortName()] == 0 {
			return depErr(strings.TrimSuffix(path+"deps", "."), "не выбран поставщик для %s (%s)", portLabel(r), r.Type)
		}
	}
	return nil
}

// providerPort picks the provides port of a new provider for a type.
func providerPort(man sdk.Manifest, name, typ string) (sdk.Port, error) {
	if name != "" {
		p, ok := findPort(man.Provides, name)
		if !ok {
			return p, fmt.Errorf("у плагина %s нет порта provides %q", man.ID, name)
		}
		if p.Type != typ {
			return p, fmt.Errorf("несовместимые типы: %s и %s", p.Type, typ)
		}
		return p, nil
	}
	var found []sdk.Port
	for _, p := range man.Provides {
		if p.Type == typ {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 0:
		return sdk.Port{}, fmt.Errorf("плагин %s не предоставляет %s", man.ID, typ)
	case 1:
		return found[0], nil
	}
	return sdk.Port{}, fmt.Errorf("у плагина %s несколько портов %s — укажите port", man.ID, typ)
}

// build records the drafts of a subtree (post-order: providers first) and
// returns the id of the node's instance.
func (c *composer) build(ctx context.Context, n *ComposeNode, path string) (int64, error) {
	type pending struct {
		port     string
		provider LinkEnd
	}
	var planned []sdk.PlannedLink
	var links []pending
	for i, d := range n.Deps {
		dp := fmt.Sprintf("%sdeps[%d].", path, i)
		var end LinkEnd
		if d.Existing != nil {
			end = *d.Existing
		} else {
			id, err := c.build(ctx, d.New, dp+"new.")
			if err != nil {
				return 0, err
			}
			_, nman, err := c.m.pluginForInstances(ctx, d.New.PluginID)
			if err != nil {
				return 0, err
			}
			_, cman, err := c.m.pluginForInstances(ctx, n.PluginID)
			if err != nil {
				return 0, err
			}
			cport, _ := findPort(cman.Requires, d.Port)
			pp, err := providerPort(nman, d.New.Port, cport.Type)
			if err != nil {
				return 0, depErr(dp+"new.port", "%s", err.Error())
			}
			end = LinkEnd{Instance: id, Port: pp.PortName()}
		}
		peer, err := c.m.Store.GetInstance(ctx, end.Instance)
		if err != nil {
			return 0, err
		}
		_, cman, _ := c.m.pluginForInstances(ctx, n.PluginID)
		cport, _ := findPort(cman.Requires, d.Port)
		planned = append(planned, sdk.PlannedLink{Port: cport.PortName(),
			Peer: sdk.LinkPeer{Plugin: peer.PluginID, Instance: peer.ID, Name: peer.Name, Port: end.Port}})
		links = append(links, pending{port: cport.PortName(), provider: end})
	}
	st, err := c.m.prepareCreate(ctx, n.PluginID, n.Name, n.Config, c.own, planned)
	if err != nil {
		return 0, prefixFields(err, path)
	}
	c.own[n.PluginID] = append(c.own[n.PluginID], st.name)
	c.cp.drafts = append(c.cp.drafts, st.instanceID)
	c.cp.steps = append(c.cp.steps, &compStep{inst: st})
	for _, l := range links {
		ls, err := c.m.newLinkStep(ctx, LinkPlanRequest{Kind: sdk.LinkService, Provider: l.provider,
			Consumer: &LinkEnd{Instance: st.instanceID, Port: l.port}}, true)
		if err != nil {
			return 0, prefixFields(err, path)
		}
		c.cp.draftLinks = append(c.cp.draftLinks, ls.link.ID)
		c.links = append(c.links, ls)
	}
	return st.instanceID, nil
}

// ---- apply ----

// applyComposite re-plans every step, compares the hash and starts the job.
func (m *Manager) applyComposite(ctx context.Context, cp *compositePlan, req ApplyRequest) (store.Job, error) {
	if cp.hash != req.Hash {
		return store.Job{}, newErr(http.StatusBadRequest, "Подтверждён не тот план — составьте его заново")
	}
	if cp.view().Danger && !req.ConfirmDanger {
		return store.Job{}, newErr(http.StatusBadRequest, "В плане есть опасные действия: подтвердите их отдельно")
	}
	ids := cp.instances()
	for _, id := range ids {
		if m.instanceBusy(id) {
			return store.Job{}, newErr(http.StatusConflict, "с экземпляром %d уже выполняется задача", id)
		}
	}
	// Fresh plans of every step (the state may have changed).
	fresh := &compositePlan{kind: cp.kind}
	for _, s := range cp.steps {
		ns := &compStep{forget: s.forget}
		switch {
		case s.inst != nil:
			pl, hash, err := m.replan(ctx, s.inst)
			if err != nil {
				return store.Job{}, err
			}
			st := *s.inst
			st.plan, st.hash = pl, hash
			ns.inst = &st
		case s.forget:
			ns.link = s.link
		default:
			ls := *s.link
			ls.provPlan, ls.consPlan = sdk.Plan{}, sdk.Plan{}
			if err := m.planSides(ctx, &ls); err != nil {
				return store.Job{}, err
			}
			ns.link = &ls
		}
		fresh.steps = append(fresh.steps, ns)
	}
	if err := fresh.computeHash(); err != nil {
		return store.Job{}, err
	}
	m.mu.Lock()
	if m.composites[cp.id] != cp {
		m.mu.Unlock()
		return store.Job{}, newErr(http.StatusGone, "План устарел или не найден — составьте его заново")
	}
	if fresh.hash != cp.hash {
		delete(m.composites, cp.id)
		m.mu.Unlock()
		m.dropDrafts(ctx, cp)
		return store.Job{}, newErr(http.StatusConflict, "Состояние изменилось, проверьте план ещё раз")
	}
	for _, id := range ids {
		if m.instJobs[id] {
			m.mu.Unlock()
			return store.Job{}, newErr(http.StatusConflict, "с экземпляром %d уже выполняется задача", id)
		}
	}
	delete(m.composites, cp.id)
	for _, id := range ids {
		m.instJobs[id] = true
	}
	m.mu.Unlock()
	fresh.drafts, fresh.draftLinks, fresh.root, fresh.title = cp.drafts, cp.draftLinks, cp.root, cp.title
	kind := JobCompose
	if cp.kind == compLink {
		kind = JobLink
	}
	confirmed := cp.view().Danger && req.ConfirmDanger
	job, err := m.Runner.Start(kind, "Hestia: "+fresh.title, func(ctx context.Context, run *jobs.Run) error {
		defer m.releaseInstances(ids...)
		return m.runComposite(ctx, run, fresh, confirmed)
	})
	if err != nil {
		m.releaseInstances(ids...)
		m.dropDrafts(ctx, cp)
	}
	return job, err
}

// runComposite applies the steps in order; in a compose plan a failure
// rolls back the applied steps in reverse order.
func (m *Manager) runComposite(ctx context.Context, run *jobs.Run, cp *compositePlan, confirmed bool) error {
	bg := context.WithoutCancel(ctx)
	var applied []*compStep
	for _, s := range cp.steps {
		err := m.runStep(ctx, run, s, confirmed)
		if err == nil {
			applied = append(applied, s)
			continue
		}
		if cp.kind == compCompose && len(applied) > 0 {
			run.Log("warn", "Откат уже выполненных шагов")
			for i := len(applied) - 1; i >= 0; i-- {
				if uerr := m.undoStep(bg, run, applied[i]); uerr != nil {
					run.Log("error", "Откат не удался: "+truncate(uerr.Error(), 1000))
				}
			}
		}
		if cp.kind == compRemove {
			run.Log("warn", "Экземпляр не удалён: сначала должны быть удалены его связи.")
		}
		m.dropDrafts(bg, cp)
		return err
	}
	return nil
}

func (m *Manager) runStep(ctx context.Context, run *jobs.Run, s *compStep, confirmed bool) error {
	switch {
	case s.forget:
		return run.Step("Удаление записи о связи "+s.link.title(), func(ctx context.Context) error {
			if err := m.Store.DeleteSecretsByPrefix(ctx, linkSecretPrefix(s.link.link.ID)); err != nil {
				return err
			}
			return m.Store.DeleteLink(ctx, s.link.link.ID)
		})
	case s.link != nil:
		return m.applyLink(ctx, run, s.link)
	}
	st := s.inst
	a := &applyJob{pluginID: st.pluginID, instanceID: st.instanceID, grants: st.grants, confirmed: confirmed}
	return m.runApply(ctx, run, st, st.plan, a)
}

// undoStep reverses an applied step of a compose plan.
func (m *Manager) undoStep(ctx context.Context, run *jobs.Run, s *compStep) error {
	if s.link != nil {
		l, err := m.Store.GetLink(ctx, s.link.link.ID)
		if err != nil {
			return err
		}
		ls, err := m.existingLinkStep(ctx, l)
		if err != nil {
			return err
		}
		if err := m.planSides(ctx, ls); err != nil {
			return err
		}
		run.Log("info", "Откат: удаление связи "+ls.title())
		return m.removeLink(ctx, run, ls)
	}
	inst, err := m.Store.GetInstance(ctx, s.inst.instanceID)
	if err != nil {
		return err
	}
	run.Log("info", fmt.Sprintf("Откат: удаление экземпляра «%s»", inst.Name))
	req := sdk.PlanRequest{Instance: sdkInstance(inst), Config: sdkInstance(inst).Config, Action: sdk.ActionRemove}
	st, err := m.buildPlan(ctx, inst.PluginID, inst.ID, inst.Name, req, nil, nil)
	if err != nil {
		return err
	}
	a := &applyJob{pluginID: st.pluginID, instanceID: st.instanceID}
	return m.runApply(ctx, run, st, st.plan, a)
}
