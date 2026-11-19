package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
	"github.com/uxerror/hestia/sdk/types"
)

// Link secrets live under "link:<id>:<field>"; the consumer gets this name
// as the reference {"secret": "link:<id>:<field>"}.
const linkSecretP = "link:"

var reLinkSecret = regexp.MustCompile(`^link:([0-9]{1,18}):([A-Za-z0-9_.-]{1,64})$`)

func linkSecretName(link int64, field string) string {
	return fmt.Sprintf("%s%d:%s", linkSecretP, link, field)
}

func linkSecretPrefix(link int64) string { return fmt.Sprintf("%s%d:", linkSecretP, link) }

// Messages.
const msgNoLinks = "плагин «%s» не поддерживает связи"

// LinkEnd addresses a port of an instance in API requests.
type LinkEnd struct {
	Instance int64  `json:"instance"`
	Port     string `json:"port"`
}

// LinkPlanRequest is POST /plugins/links/plan.
type LinkPlanRequest struct {
	Kind     string         `json:"kind"`
	Provider LinkEnd        `json:"provider"`
	Consumer *LinkEnd       `json:"consumer"`
	Device   *DeviceRef     `json:"device"`
	Config   map[string]any `json:"config"`
}

// DeviceRef names a device (a target of Hestia) in API requests.
type DeviceRef struct {
	Ref string `json:"ref"`
}

// linkSide is one plugin taking part in a link.
type linkSide struct {
	role       string
	pluginID   string
	pluginName string
	inst       store.PluginInstance
	port       sdk.Port
}

func (s linkSide) peer() *sdk.LinkPeer {
	return &sdk.LinkPeer{Plugin: s.pluginID, Instance: s.inst.ID, Name: s.inst.Name, Port: s.port.PortName()}
}

// linkStep is the creation or removal of one link (a step of a composite
// plan).
type linkStep struct {
	action   string // create | remove
	link     store.PluginLink
	typ      string
	config   sdk.Config
	provider linkSide
	consumer *linkSide       // service links
	device   *sdk.TargetInfo // device links
	provPlan sdk.Plan
	consPlan sdk.Plan
}

// actionReissue is a link step that asks for a new certificate with
// (possibly) new names from the same provider (types with a request).
const actionReissue = "reissue"

// hasRequest reports whether the type of the link has a request (the
// consumer is asked with link.prepare before the provider).
func (ls *linkStep) hasRequest() bool {
	t, ok := types.Lookup(ls.typ)
	return ok && len(t.Request) > 0 && ls.consumer != nil
}

func (ls *linkStep) request(side *linkSide, action string) sdk.LinkRequest {
	reason := ""
	if action == actionReissue {
		action, reason = sdk.ActionUpdate, sdk.ReasonReissue
	}
	req := sdk.LinkRequest{Link: ls.link.ID, Kind: ls.link.Kind, Role: side.role, Action: action, Instance: sdkInstance(side.inst),
		Port: side.port.PortName(), Type: ls.typ, Config: ls.config, Reason: reason}
	if req.Config == nil {
		req.Config = sdk.Config{}
	}
	switch {
	case ls.consumer != nil && side.role == sdk.RoleProvider:
		req.Peer = ls.consumer.peer()
	case ls.consumer != nil:
		req.Peer = ls.provider.peer()
	case ls.device != nil:
		d := *ls.device
		req.Device = &d
	}
	return req
}

// title names the link for plans and logs.
func (ls *linkStep) title() string {
	if ls.consumer != nil {
		return fmt.Sprintf("«%s» → «%s» (%s)", ls.provider.inst.Name, ls.consumer.inst.Name, ls.typ)
	}
	name := ls.link.DeviceRef
	if ls.device != nil && ls.device.Name != "" {
		name = ls.device.Name
	}
	return fmt.Sprintf("«%s» → устройство %s (%s)", ls.provider.inst.Name, name, ls.typ)
}

func (ls *linkStep) sides() []*linkSide {
	if ls.consumer != nil {
		// Consumer first on removal: it stops using what the provider gives.
		if ls.action == sdk.ActionRemove {
			return []*linkSide{ls.consumer, &ls.provider}
		}
		return []*linkSide{&ls.provider, ls.consumer}
	}
	return []*linkSide{&ls.provider}
}

func (ls *linkStep) planOf(side *linkSide) sdk.Plan {
	if side.role == sdk.RoleConsumer {
		return ls.consPlan
	}
	return ls.provPlan
}

func (ls *linkStep) setPlan(side *linkSide, pl sdk.Plan) {
	if side.role == sdk.RoleConsumer {
		ls.consPlan = pl
	} else {
		ls.provPlan = pl
	}
}

// hash covers what the user confirms: the ends, the configuration and both
// plans (with their data).
func (ls *linkStep) hash() (string, error) {
	b, err := json.Marshal(map[string]any{
		"action": ls.action, "kind": ls.link.Kind, "type": ls.typ, "provider": []any{ls.link.ProviderInstance, ls.link.ProviderPort},
		"consumer": []any{ls.link.ConsumerInstance, ls.link.ConsumerPort}, "device": ls.link.DeviceRef, "config": ls.config,
		"provider_plan": ls.provPlan, "consumer_plan": ls.consPlan,
	})
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

// ---- calls ----

// linkCall is a link.* call in flight: during it the provider may use the
// device of that link (its via_link grant).
type linkCall struct {
	pluginID   string
	instanceID int64
	linkID     int64
	device     string
}

func (m *Manager) withLinkCall(lc linkCall) func() {
	id := randID()
	m.mu.Lock()
	m.linkCalls[id] = lc
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		delete(m.linkCalls, id)
		m.mu.Unlock()
	}
}

// callLink invokes a link.* method of one side. Without a job the default
// timeout applies.
func (m *Manager) callLink(ctx context.Context, ls *linkStep, side *linkSide, method string, req sdk.LinkRequest, out any, run *jobs.Run, masks []string) error {
	s := m.conn(side.pluginID)
	if s == nil {
		return fmt.Errorf("плагин %s не подключён", side.pluginID)
	}
	if method != sdk.MethodLinkPlan {
		defer m.withLinkCall(linkCall{pluginID: side.pluginID, instanceID: side.inst.ID, linkID: ls.link.ID, device: ls.link.DeviceRef})()
	}
	var a *applyJob
	if run != nil {
		req.JobID = run.ID()
		a = &applyJob{pluginID: side.pluginID, instanceID: side.inst.ID, run: run}
		for _, v := range masks {
			a.addMask(v)
		}
		m.mu.Lock()
		m.applying[run.ID()] = a
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			if m.applying[run.ID()] == a {
				delete(m.applying, run.ID())
			}
			m.mu.Unlock()
		}()
	}
	var err error
	if run != nil {
		err = s.conn.CallNoTimeout(ctx, method, req, out)
		a.stepDone(err)
	} else {
		err = s.conn.Call(ctx, method, req, out)
	}
	if err == nil {
		return nil
	}
	var re *rpc.Error
	switch {
	case errors.As(err, &re) && re.Code == rpc.CodeMethodNotFound && method == sdk.MethodLinkPrepare:
		return fmt.Errorf("плагин «%s» не умеет запрашивать сертификаты (link.prepare): связь %s недоступна", side.pluginName, ls.typ)
	case errors.As(err, &re) && re.Code == rpc.CodeMethodNotFound:
		return fmt.Errorf(msgNoLinks, side.pluginName)
	case errors.As(err, &re):
		msg := re.Message
		if a != nil {
			msg = a.mask(msg)
		}
		return fmt.Errorf("«%s»: %s", side.inst.Name, truncate(msg, 1000))
	}
	return fmt.Errorf("«%s»: %w", side.inst.Name, pluginErr(err))
}

// planSides asks every side for its plan of the action. For a type with a
// request the consumer plans first: its preview of the request goes to the
// provider's plan (and into the hash of the plan).
func (m *Manager) planSides(ctx context.Context, ls *linkStep) error {
	sides := ls.sides()
	withReq := ls.hasRequest() && ls.action != sdk.ActionRemove
	if withReq {
		sides = []*linkSide{ls.consumer, &ls.provider}
	}
	for _, side := range sides {
		var pl sdk.Plan
		req := ls.request(side, ls.action)
		if withReq && side.role == sdk.RoleProvider {
			req.Request = ls.consPlan.Request
		}
		if err := m.callLink(ctx, ls, side, sdk.MethodLinkPlan, req, &pl, nil, nil); err != nil {
			return newErr(http.StatusBadGateway, "%v", err)
		}
		pl, err := sanitizePlan(pl)
		if err != nil {
			return err
		}
		if withReq && side.role == sdk.RoleConsumer {
			if len(pl.Request) == 0 || string(pl.Request) == "null" {
				return newErr(http.StatusUnprocessableEntity, "плагин «%s» не умеет запрашивать сертификаты: связь %s недоступна", side.pluginName, ls.typ)
			}
			if _, err := types.ValidateRequest(ls.typ, pl.Request, true); err != nil {
				return newErr(http.StatusBadGateway, "«%s»: предпросмотр запроса: %v", side.inst.Name, err)
			}
			c, err := canonical(pl.Request)
			if err != nil {
				return err
			}
			pl.Request = c
		} else {
			// Only the consumer's preview counts; a request from the
			// provider is ignored.
			pl.Request = nil
		}
		ls.setPlan(side, pl)
	}
	return nil
}

// sanitizePlan bounds and normalises a plan from a plugin.
func sanitizePlan(pl sdk.Plan) (sdk.Plan, error) {
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

// ---- building link steps ----

// linkPlugin loads the plugin of an instance (enabled, connected) and its
// manifest.
func (m *Manager) linkInstance(ctx context.Context, iid int64, allowDraft bool) (store.PluginInstance, sdk.Manifest, string, error) {
	inst, err := m.Store.GetInstance(ctx, iid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && inst.Status == store.InstanceDraft && !allowDraft) {
		return inst, sdk.Manifest{}, "", newErr(http.StatusNotFound, "экземпляр %d не найден", iid)
	}
	if err != nil {
		return inst, sdk.Manifest{}, "", err
	}
	_, man, err := m.pluginForInstances(ctx, inst.PluginID)
	if err != nil {
		return inst, man, "", err
	}
	name := man.Name
	if name == "" {
		name = inst.PluginID
	}
	return inst, man, name, nil
}

func fieldErr(field, msg string) error {
	return &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте связь: " + msg, Fields: []sdk.FieldError{{Field: field, Msg: msg}}}
}

// newLinkStep checks a new link and records it as a draft (so that it has
// an id the plugins plan with). Drafts of the instances of a composite plan
// are allowed (allowDraft).
func (m *Manager) newLinkStep(ctx context.Context, req LinkPlanRequest, allowDraft bool) (*linkStep, error) {
	ls := &linkStep{action: sdk.ActionCreate}
	pinst, pman, pname, err := m.linkInstance(ctx, req.Provider.Instance, allowDraft)
	if err != nil {
		return nil, err
	}
	pport, ok := findPort(pman.Provides, req.Provider.Port)
	if !ok {
		return nil, fieldErr("provider.port", fmt.Sprintf("у «%s» нет порта provides %q", pinst.Name, req.Provider.Port))
	}
	ls.provider = linkSide{role: sdk.RoleProvider, pluginID: pinst.PluginID, pluginName: pname, inst: pinst, port: pport}
	ls.typ = pport.Type
	ls.link = store.PluginLink{ProviderInstance: pinst.ID, ProviderPort: pport.PortName(), Status: store.LinkDraft}
	switch req.Kind {
	case sdk.LinkService:
		if req.Consumer == nil {
			return nil, fieldErr("consumer", "укажите потребителя")
		}
		cinst, cman, cname, err := m.linkInstance(ctx, req.Consumer.Instance, allowDraft)
		if err != nil {
			return nil, err
		}
		cport, ok := findPort(cman.Requires, req.Consumer.Port)
		switch {
		case !ok:
			return nil, fieldErr("consumer.port", fmt.Sprintf("у «%s» нет порта requires %q", cinst.Name, req.Consumer.Port))
		case cinst.ID == pinst.ID:
			return nil, fieldErr("consumer", "экземпляр не связывается сам с собой")
		case cport.Type != pport.Type:
			return nil, fieldErr("consumer.port", fmt.Sprintf("несовместимые типы: %s и %s", pport.Type, cport.Type))
		}
		ls.consumer = &linkSide{role: sdk.RoleConsumer, pluginID: cinst.PluginID, pluginName: cname, inst: cinst, port: cport}
		ls.link.Kind, ls.link.ConsumerInstance, ls.link.ConsumerPort = store.LinkKindService, cinst.ID, cport.PortName()
		if !cport.IsMulti(false) {
			n, err := m.Store.CountPortLinks(ctx, cinst.ID, cport.PortName(), false)
			if err != nil {
				return nil, err
			}
			if n > 0 {
				return nil, fieldErr("consumer.port", fmt.Sprintf("«%s» уже подключён к поставщику %s", cinst.Name, portLabel(cport)))
			}
		}
		ls.provider.role = sdk.RoleProvider
	case sdk.LinkDevice:
		if req.Device == nil || req.Device.Ref == "" {
			return nil, fieldErr("device", "выберите устройство")
		}
		if !pport.Client {
			return nil, fieldErr("provider.port", fmt.Sprintf("порт %s не умеет связь с устройством", portLabel(pport)))
		}
		if !slices.Contains(pman.Permissions, sdk.PermLinksClient) {
			return nil, fieldErr("provider.port", "у плагина нет права "+sdk.PermLinksClient)
		}
		cands, err := m.Candidates(ctx)
		if err != nil {
			return nil, err
		}
		var dev *sdk.TargetInfo
		for _, c := range cands {
			if c.ID == req.Device.Ref {
				if !c.Available {
					return nil, fieldErr("device", "устройство недоступно: "+c.Reason)
				}
				ti := c.TargetInfo
				dev = &ti
			}
		}
		if dev == nil {
			return nil, fieldErr("device", "устройство не найдено среди целей Hestia")
		}
		ls.device = dev
		ls.provider.role = sdk.RoleClient
		ls.link.Kind, ls.link.DeviceRef = store.LinkKindDevice, dev.ID
	default:
		return nil, newErr(http.StatusBadRequest, "kind: service или device")
	}
	if !pport.IsMulti(true) {
		n, err := m.Store.CountPortLinks(ctx, pinst.ID, pport.PortName(), true)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, fieldErr("provider.port", fmt.Sprintf("порт %s «%s» уже занят (одна связь)", portLabel(pport), pinst.Name))
		}
	}
	schema := sdk.Schema{}
	if pport.LinkSchema != nil {
		schema = *pport.LinkSchema
	}
	cfg, _, _, err := m.normalize(ctx, schema, req.Config, nil, nil)
	if err != nil {
		return nil, err
	}
	ls.config = cfg
	cfgJSON, _ := json.Marshal(cfg)
	ls.link.Config = string(cfgJSON)
	if dup, err := m.Store.DuplicateLink(ctx, ls.link); err == nil {
		if dup.Status != store.LinkDraft {
			return nil, fieldErr("provider", "такая связь уже есть")
		}
		// A draft of an earlier plan: the new plan replaces it.
		m.dropPlansWithLink(dup.ID)
		_ = m.Store.DeleteLink(ctx, dup.ID)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err := m.Store.CreateLink(ctx, &ls.link); errors.Is(err, store.ErrDuplicate) {
		return nil, fieldErr("provider", "такая связь уже есть")
	} else if err != nil {
		return nil, err
	}
	return ls, nil
}

func portLabel(p sdk.Port) string {
	if p.Label != "" {
		return "«" + p.Label + "»"
	}
	return p.PortName()
}

// existingLinkStep loads a link for its removal.
func (m *Manager) existingLinkStep(ctx context.Context, l store.PluginLink) (*linkStep, error) {
	ls := &linkStep{action: sdk.ActionRemove, link: l, config: sdk.Config{}}
	_ = json.Unmarshal([]byte(l.Config), &ls.config)
	pinst, pman, pname, err := m.linkInstance(ctx, l.ProviderInstance, false)
	if err != nil {
		return nil, err
	}
	pport, _ := findPort(pman.Provides, l.ProviderPort)
	if pport.Type == "" {
		pport = sdk.Port{Name: l.ProviderPort}
	}
	ls.typ = pport.Type
	ls.provider = linkSide{role: sdk.RoleProvider, pluginID: pinst.PluginID, pluginName: pname, inst: pinst, port: pport}
	if l.Kind == store.LinkKindService {
		cinst, cman, cname, err := m.linkInstance(ctx, l.ConsumerInstance, false)
		if err != nil {
			return nil, err
		}
		cport, _ := findPort(cman.Requires, l.ConsumerPort)
		if cport.Type == "" {
			cport = sdk.Port{Name: l.ConsumerPort, Type: pport.Type}
		}
		ls.consumer = &linkSide{role: sdk.RoleConsumer, pluginID: cinst.PluginID, pluginName: cname, inst: cinst, port: cport}
	} else {
		ls.provider.role = sdk.RoleClient
		ls.device = m.deviceInfo(ctx, l.DeviceRef)
	}
	return ls, nil
}

// deviceInfo describes a device by its reference (a removed target keeps
// only the reference).
func (m *Manager) deviceInfo(ctx context.Context, ref string) *sdk.TargetInfo {
	if cands, err := m.Candidates(ctx); err == nil {
		for _, c := range cands {
			if c.ID == ref {
				ti := c.TargetInfo
				return &ti
			}
		}
	}
	r, _ := ParseRef(ref)
	return &sdk.TargetInfo{ID: ref, Kind: r.Kind, Name: ref}
}

// ---- binding ----

// processBinding validates the provider's binding against the type and
// separates the secret values: the binding to store has references
// {"secret": "link:<id>:<field>"}. A device link may come without one.
func processBinding(link int64, typ string, raw json.RawMessage, required bool) (string, map[string]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		if required {
			return "", nil, errors.New("поставщик не вернул данные связи (binding)")
		}
		return "{}", map[string]string{}, nil
	}
	secs := map[string]string{}
	var obj map[string]any
	if t, ok := types.Lookup(typ); ok {
		m, err := types.Validate(typ, raw, false)
		if err != nil {
			return "", nil, fmt.Errorf("данные связи не по контракту типа: %v", err)
		}
		for _, f := range t.SecretFields() {
			if v, ok := m[f].(string); ok {
				secs[f] = v
				m[f] = map[string]any{"secret": linkSecretName(link, f)}
			}
		}
		obj = m
	} else {
		m, err := types.Decode(raw)
		if err != nil {
			return "", nil, fmt.Errorf("данные связи: %v", err)
		}
		obj = m
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return "", nil, err
	}
	c, err := canonical(b)
	if err != nil {
		return "", nil, err
	}
	return string(c), secs, nil
}

func secretValues(secs map[string]string) []string {
	var out []string
	for _, v := range secs {
		out = append(out, v)
	}
	return out
}

// linkSecrets reads the stored secret values of a link (field → value).
func (m *Manager) linkSecrets(ctx context.Context, link int64) map[string]string {
	out := map[string]string{}
	ids, err := m.Store.SecretIDsByPrefix(ctx, linkSecretPrefix(link))
	if err != nil {
		return out
	}
	for _, id := range ids {
		row, err := m.Store.GetSecret(ctx, id)
		if err != nil {
			continue
		}
		if v, err := m.Secrets.Get(ctx, id); err == nil {
			out[strings.TrimPrefix(row.Purpose, linkSecretPrefix(link))] = string(v)
		}
	}
	return out
}

func (m *Manager) storeLinkSecrets(ctx context.Context, link int64, secs map[string]string) error {
	for f, v := range secs {
		if err := m.putSecret(ctx, linkSecretName(link, f), v); err != nil {
			return err
		}
	}
	return nil
}

// ---- apply ----

// applyLink carries out a link step within a job; masks are values to hide
// in the log.
func (m *Manager) applyLink(ctx context.Context, run *jobs.Run, ls *linkStep) error {
	switch ls.action {
	case sdk.ActionRemove:
		return m.removeLink(ctx, run, ls)
	case actionReissue:
		if err := m.rotateLink(ctx, run, ls, sdk.ReasonReissue); err != nil {
			return err
		}
		go m.refreshLink(m.ctx, ls.link.ID)
		return nil
	}
	bg := context.WithoutCancel(ctx)
	id := ls.link.ID
	err := run.Step("Связь "+ls.title()+": подготовка", func(ctx context.Context) error {
		if ls.consumer != nil && !ls.consumer.port.IsMulti(false) {
			if n, err := m.Store.CountPortLinks(ctx, ls.consumer.inst.ID, ls.consumer.port.PortName(), false); err != nil || n > 0 {
				return errors.Join(err, errors.New("потребитель уже подключён к другому поставщику"))
			}
		}
		if !ls.provider.port.IsMulti(true) {
			if n, err := m.Store.CountPortLinks(ctx, ls.provider.inst.ID, ls.provider.port.PortName(), true); err != nil || n > 0 {
				return errors.Join(err, errors.New("порт поставщика уже занят"))
			}
		}
		kind := ""
		if ls.device != nil {
			kind = ls.device.Kind
		}
		if err := m.Store.ActivateLink(ctx, id, kind); errors.Is(err, store.ErrNotFound) {
			return errors.New("план связи устарел — составьте его заново")
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Refresh the instances: a composite plan has just created them.
	m.reloadSides(ctx, ls)
	fail := func(err error) error {
		// The link failed: its record goes (the job keeps the reason).
		_ = m.Store.DeleteSecretsByPrefix(bg, linkSecretPrefix(id))
		_ = m.Store.DeleteLink(bg, id)
		run.Log("warn", "Связь не создана: "+truncate(err.Error(), 1000))
		return err
	}
	undoProvider := func() {
		req := ls.request(&ls.provider, sdk.ActionRemove)
		req.Plan = &ls.provPlan
		if err := m.callLink(bg, ls, &ls.provider, sdk.MethodLinkRemove, req, nil, run, nil); err != nil {
			run.Log("error", "Откат у поставщика не удался: "+err.Error())
		} else {
			run.Log("info", "Откат у поставщика выполнен")
		}
	}

	withReq := ls.hasRequest()
	undoConsumer := func() {
		if !withReq {
			return
		}
		req := ls.request(ls.consumer, sdk.ActionRemove)
		req.Plan = &ls.consPlan
		if err := m.callLink(bg, ls, ls.consumer, sdk.MethodLinkRemove, req, nil, run, nil); err != nil {
			run.Log("error", "Откат у потребителя не удался: "+err.Error())
		} else {
			run.Log("info", "Откат у потребителя выполнен")
		}
	}
	var full json.RawMessage
	if withReq {
		var err error
		if full, err = m.prepareRequest(ctx, run, ls, sdk.ReasonCreate); err != nil {
			undoConsumer()
			return fail(err)
		}
		if err := m.Store.SetLinkRequest(ctx, id, string(full)); err != nil {
			undoConsumer()
			return fail(err)
		}
	}

	run.Log("info", fmt.Sprintf("«%s»: настройка связи (%s)", ls.provider.inst.Name, ls.provider.role))
	var res sdk.LinkResult
	req := ls.request(&ls.provider, sdk.ActionCreate)
	req.Plan = &ls.provPlan
	req.Request = full
	if err := m.callLink(ctx, ls, &ls.provider, sdk.MethodLinkApply, req, &res, run, nil); err != nil {
		if ls.device != nil {
			undoProvider()
		}
		undoConsumer()
		return fail(err)
	}
	binding, secs, err := processBinding(id, ls.typ, res.Binding, ls.consumer != nil)
	if err == nil && withReq {
		err = checkRequestBinding(ls.typ, res.Binding, full, m.providerRoot(ctx, ls.provider.inst.ID, id), m.Now())
	}
	if err != nil {
		undoProvider()
		undoConsumer()
		return fail(err)
	}
	masks := secretValues(secs)
	err = run.Step("Связь "+ls.title()+": данные связи", func(ctx context.Context) error {
		if err := m.storeLinkSecrets(ctx, id, secs); err != nil {
			return err
		}
		return m.Store.SetLinkBinding(ctx, id, binding)
	})
	if err != nil {
		undoProvider()
		return fail(err)
	}
	if ls.consumer != nil {
		run.Log("info", fmt.Sprintf("«%s»: подключение к «%s»", ls.consumer.inst.Name, ls.provider.inst.Name))
		creq := ls.request(ls.consumer, sdk.ActionCreate)
		creq.Binding = json.RawMessage(binding)
		creq.Plan = &ls.consPlan
		creq.Request = full
		if err := m.callLink(ctx, ls, ls.consumer, sdk.MethodLinkApply, creq, nil, run, masks); err != nil {
			undoProvider()
			undoConsumer()
			return fail(err)
		}
	}
	if err := m.recordRenewal(bg, id, ls.typ, binding); err != nil {
		run.Log("warn", "Срок действия связи: "+err.Error())
	}
	now := m.Now().UTC()
	if err := m.Store.SetLinkStatus(bg, id, sdk.StateUnknown, "", &now); err != nil {
		return err
	}
	ls.link.Status, ls.link.Binding = sdk.StateUnknown, binding
	run.Log("info", "Связь создана: "+ls.title())
	go m.refreshLink(m.ctx, id)
	return nil
}

// reloadSides re-reads the instances of a link (their configuration may
// have been written by an earlier step).
func (m *Manager) reloadSides(ctx context.Context, ls *linkStep) {
	if in, err := m.Store.GetInstance(ctx, ls.provider.inst.ID); err == nil {
		ls.provider.inst = in
	}
	if ls.consumer != nil {
		if in, err := m.Store.GetInstance(ctx, ls.consumer.inst.ID); err == nil {
			ls.consumer.inst = in
		}
	}
}

// removeLink removes a link: the consumer side, then the provider side. A
// side that fails leaves the link "orphaned" (only its record can go).
func (m *Manager) removeLink(ctx context.Context, run *jobs.Run, ls *linkStep) error {
	bg := context.WithoutCancel(ctx)
	id := ls.link.ID
	if err := m.Store.SetLinkStatus(ctx, id, store.LinkRemoving, "", nil); err != nil {
		return err
	}
	var errs []string
	for _, side := range ls.sides() {
		run.Log("info", fmt.Sprintf("«%s»: удаление связи (%s)", side.inst.Name, side.role))
		req := ls.request(side, sdk.ActionRemove)
		pl := ls.planOf(side)
		req.Plan = &pl
		if err := m.callLink(ctx, ls, side, sdk.MethodLinkRemove, req, nil, run, nil); err != nil {
			errs = append(errs, err.Error())
			run.Log("error", err.Error())
		}
	}
	// The consumer no longer may read them in any case.
	_ = m.Store.DeleteSecretsByPrefix(bg, linkSecretPrefix(id))
	if len(errs) > 0 {
		detail := truncate("Не удалось удалить: "+strings.Join(errs, "; "), 1000)
		_ = m.Store.SetLinkStatus(bg, id, store.LinkOrphaned, detail, nil)
		return fmt.Errorf("связь %s не удалена полностью — она отмечена как «осиротевшая»: %s", ls.title(), strings.Join(errs, "; "))
	}
	if err := m.Store.DeleteLink(bg, id); err != nil {
		return err
	}
	run.Log("info", "Связь удалена: "+ls.title())
	return nil
}

// ---- status ----

var stateRank = map[string]int{sdk.StateOK: 0, sdk.StateUnknown: 1, sdk.StateDegraded: 2, sdk.StateDown: 3}

// LinkHealth asks both sides of an active link and records the worst state.
func (m *Manager) LinkHealth(ctx context.Context, id int64) (store.PluginLink, error) {
	l, err := m.Store.GetLink(ctx, id)
	if err != nil {
		return l, err
	}
	if !l.Active() || l.Status == store.LinkApplying {
		return l, nil
	}
	ls, err := m.existingLinkStep(ctx, l)
	if err != nil {
		now := m.Now().UTC()
		_ = m.Store.SetLinkHealth(ctx, id, sdk.StateUnknown, truncate(errText(err), 1000), now)
		return m.Store.GetLink(ctx, id)
	}
	state, details := sdk.StateOK, []string{}
	for _, side := range ls.sides() {
		var st sdk.LinkStatus
		req := ls.request(side, "")
		if side.role == sdk.RoleConsumer {
			req.Binding = json.RawMessage(l.Binding)
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.callLink(cctx, ls, side, sdk.MethodLinkStatus, req, &st, nil, nil)
		cancel()
		if err != nil {
			st = sdk.LinkStatus{State: sdk.StateUnknown, Detail: err.Error()}
		}
		if _, ok := stateRank[st.State]; !ok {
			st.State = sdk.StateUnknown
		}
		if stateRank[st.State] > stateRank[state] {
			state = st.State
		}
		if st.Detail != "" {
			details = append(details, fmt.Sprintf("%s: %s", side.inst.Name, truncate(st.Detail, 400)))
		}
	}
	now := m.Now().UTC()
	if st, d := renewalState(l, now); st != "" {
		if stateRank[st] > stateRank[state] {
			state = st
		}
		details = append([]string{d}, details...)
	}
	if err := m.Store.SetLinkHealth(ctx, id, state, truncate(strings.Join(details, "; "), 1000), now); err != nil {
		return l, err
	}
	return m.Store.GetLink(ctx, id)
}

func errText(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Msg
	}
	return err.Error()
}

func (m *Manager) refreshLink(ctx context.Context, id int64) {
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	_, _ = m.LinkHealth(cctx, id)
}

// refreshLinks checks every active link (periodically and when the map
// opens).
func (m *Manager) refreshLinks(ctx context.Context) {
	m.mu.Lock()
	m.linksCheckedAt = m.Now()
	m.mu.Unlock()
	list, err := m.Store.ListLinks(ctx)
	if err != nil {
		return
	}
	for _, l := range list {
		if ctx.Err() != nil {
			return
		}
		if l.Active() && l.Status != store.LinkApplying {
			m.refreshLink(ctx, l.ID)
		}
	}
}

// ---- refresh after an update of the provider ----

// refreshProviderLinks asks the provider for the bindings of its links
// after its instance was changed; a changed binding is applied again on
// the consumer (service) or on the device (client). Failures are logged
// and degrade the link, the update itself stays.
func (m *Manager) refreshProviderLinks(ctx context.Context, run *jobs.Run, iid int64) {
	links, err := m.Store.LinksOfInstance(ctx, iid)
	if err != nil {
		run.Log("warn", "Связи: "+err.Error())
		return
	}
	for _, l := range links {
		if l.ProviderInstance != iid || !l.Active() || l.Status == store.LinkApplying {
			continue
		}
		ls, err := m.existingLinkStep(ctx, l)
		if err != nil {
			run.Log("warn", fmt.Sprintf("Связь %d: %s", l.ID, errText(err)))
			continue
		}
		if ls.hasRequest() {
			// A new binding means a new certificate: renewal and reissue
			// handle that, a change of the provider does not.
			continue
		}
		if err := m.refreshOne(ctx, run, ls); err != nil {
			run.Log("warn", fmt.Sprintf("Связь %s: %s", ls.title(), err.Error()))
			_ = m.Store.SetLinkHealth(context.WithoutCancel(ctx), l.ID, sdk.StateDegraded, truncate("Обновление связи: "+err.Error(), 1000), m.Now().UTC())
		}
	}
}

func (m *Manager) refreshOne(ctx context.Context, run *jobs.Run, ls *linkStep) error {
	id := ls.link.ID
	var res sdk.LinkResult
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := m.callLink(cctx, ls, &ls.provider, sdk.MethodLinkRefresh, ls.request(&ls.provider, ""), &res, nil, nil)
	cancel()
	if err != nil {
		return err
	}
	if ls.device != nil && (len(res.Binding) == 0 || string(res.Binding) == "null") {
		return nil // nothing to compare
	}
	binding, secs, err := processBinding(id, ls.typ, res.Binding, true)
	if err != nil {
		return err
	}
	old := m.linkSecrets(ctx, id)
	same := binding == ls.link.Binding && len(old) == len(secs)
	for k, v := range secs {
		if old[k] != v {
			same = false
		}
	}
	if same {
		run.Log("info", "Связь "+ls.title()+": данные не изменились")
		return nil
	}
	run.Log("info", "Связь "+ls.title()+": данные изменились, применяю заново")
	if err := m.Store.DeleteSecretsByPrefix(ctx, linkSecretPrefix(id)); err != nil {
		return err
	}
	if err := m.storeLinkSecrets(ctx, id, secs); err != nil {
		return err
	}
	if err := m.Store.SetLinkBinding(ctx, id, binding); err != nil {
		return err
	}
	side := ls.consumer
	if side == nil {
		side = &ls.provider // the client side on the device
	}
	req := ls.request(side, sdk.ActionUpdate)
	req.Binding = json.RawMessage(binding)
	if err := m.callLink(ctx, ls, side, sdk.MethodLinkApply, req, nil, run, secretValues(secs)); err != nil {
		return err
	}
	go m.refreshLink(m.ctx, id)
	return nil
}

// ---- secrets of links ----

// linkSecretGet serves secret.get of "link:<id>:<field>": only the consumer
// instance of an active service link may read it. Nobody writes or
// deletes them through the API: the provider hands them over in binding.
func (m *Manager) linkSecretGet(ctx context.Context, pid, method string, p sdk.SecretRequest) (any, error) {
	if method != sdk.MethodSecretGet {
		return nil, denied("секреты связи пишет только Hestia (из binding поставщика)", map[string]any{"secret": p.Name})
	}
	mm := reLinkSecret.FindStringSubmatch(p.Name)
	if mm == nil {
		return nil, badParams("неверное имя секрета связи %q", p.Name)
	}
	if err := m.ownInstance(ctx, pid, p.Instance); err != nil {
		return nil, err
	}
	lid, _ := strconv.ParseInt(mm[1], 10, 64)
	l, err := m.Store.GetLink(ctx, lid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, denied(fmt.Sprintf("связь %d не найдена", lid), map[string]any{"link": lid})
	}
	if err != nil {
		return nil, err
	}
	if l.Kind != store.LinkKindService || l.ConsumerInstance != p.Instance {
		return nil, denied(fmt.Sprintf("экземпляр %d не потребитель связи %d", p.Instance, lid), map[string]any{"link": lid, "instance": p.Instance})
	}
	if !l.Active() {
		return nil, denied(fmt.Sprintf("связь %d не активна", lid), map[string]any{"link": lid})
	}
	row, err := m.Store.GetSecretByPurpose(ctx, p.Name)
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
	m.rememberSecret(pid, p.Instance, string(v))
	return sdk.SecretValue{Value: string(v), Exists: true}, nil
}

// welcomeLinks are the active links of a plugin's instances (hello).
func (m *Manager) welcomeLinks(ctx context.Context, pid string) []sdk.LinkInfo {
	out := []sdk.LinkInfo{}
	list, err := m.Store.ListLinks(ctx)
	if err != nil {
		return out
	}
	insts, err := m.Store.ListInstances(ctx, "", false)
	if err != nil {
		return out
	}
	byID := map[int64]store.PluginInstance{}
	for _, in := range insts {
		byID[in.ID] = in
	}
	for _, l := range list {
		if !l.Active() || l.Status == store.LinkApplying {
			continue
		}
		prov, cons := byID[l.ProviderInstance], byID[l.ConsumerInstance]
		if prov.PluginID == pid {
			li := sdk.LinkInfo{Link: l.ID, Kind: l.Kind, Role: sdk.RoleProvider, Instance: prov.ID, Port: l.ProviderPort, Device: l.DeviceRef}
			if l.Kind == store.LinkKindDevice {
				li.Role = sdk.RoleClient
			} else {
				li.Peer = &sdk.LinkPeer{Plugin: cons.PluginID, Instance: cons.ID, Name: cons.Name, Port: l.ConsumerPort}
			}
			out = append(out, li)
		}
		if l.Kind == store.LinkKindService && cons.PluginID == pid {
			out = append(out, sdk.LinkInfo{Link: l.ID, Kind: l.Kind, Role: sdk.RoleConsumer, Instance: cons.ID, Port: l.ConsumerPort,
				Peer:    &sdk.LinkPeer{Plugin: prov.PluginID, Instance: prov.ID, Name: prov.Name, Port: l.ProviderPort},
				Binding: json.RawMessage(l.Binding)})
		}
	}
	return out
}
