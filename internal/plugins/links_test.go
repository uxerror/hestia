package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// recorder is the shared log of the link test plugins (in call order).
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(format string, args ...any) {
	r.mu.Lock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.lines = nil
	r.mu.Unlock()
}

func (r *recorder) has(s string) bool {
	for _, l := range r.list() {
		if l == s {
			return true
		}
	}
	return false
}

// linkPlugin is a scriptable plugin with links.
type linkPlugin struct {
	testPlugin
	id  string
	rec *recorder

	lmu        sync.Mutex
	failInst   map[string]error // instance action → error
	failApply  map[string]error // role → error of link.apply
	failRemove map[string]error // role → error of link.remove
	onApply    func(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error
	host       *sdk.Host
	planNonceL string
	pass       string // the password in postgres.db bindings
}

func newLinkPlugin(id string, rec *recorder) *linkPlugin {
	return &linkPlugin{id: id, rec: rec, failInst: map[string]error{}, failApply: map[string]error{}, failRemove: map[string]error{}, pass: "pg-secret-1"}
}

func (p *linkPlugin) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	p.rec.add("%s instance %s %s", p.id, req.Action, req.Instance.Name)
	for _, l := range req.Links {
		p.rec.add("%s planned link %s ← %s/%s", p.id, l.Port, l.Peer.Name, l.Peer.Port)
	}
	p.lmu.Lock()
	err := p.failInst[req.Action]
	p.lmu.Unlock()
	return err
}

func (p *linkPlugin) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	p.lmu.Lock()
	nonce := p.planNonceL
	p.lmu.Unlock()
	data, _ := json.Marshal(map[string]any{"nonce": nonce})
	return sdk.Plan{Actions: []sdk.Action{{Title: req.Role + " " + req.Action + " " + req.Port, Risk: sdk.RiskChange}}, Data: data}, nil
}

func (p *linkPlugin) binding(req sdk.LinkRequest) json.RawMessage {
	if req.Type == types.PostgresDBType {
		p.lmu.Lock()
		pass := p.pass
		p.lmu.Unlock()
		b, _ := types.Marshal(types.PostgresDB{Host: "10.10.10.21", Port: 5432, Database: "app", User: "app", Password: types.Secret{Value: pass}})
		return b
	}
	msg := req.Instance.Config.String("message")
	b, _ := types.Marshal(types.HTTPService{URL: "http://10.10.10.21:8080/" + msg, Host: "10.10.10.21", Port: 8080, Scheme: "http"})
	return b
}

func (p *linkPlugin) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	p.rec.add("%s link.apply %s %d %s", p.id, req.Role, req.Link, req.Action)
	p.lmu.Lock()
	p.host = job.Host()
	err := p.failApply[req.Role]
	hook := p.onApply
	p.lmu.Unlock()
	if err != nil {
		return nil, err
	}
	if hook != nil {
		if err := hook(ctx, req, job); err != nil {
			return nil, err
		}
	}
	if req.Role == sdk.RoleConsumer {
		return nil, nil
	}
	return p.binding(req), nil
}

func (p *linkPlugin) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	p.rec.add("%s link.remove %s %d", p.id, req.Role, req.Link)
	p.lmu.Lock()
	defer p.lmu.Unlock()
	return p.failRemove[req.Role]
}

func (p *linkPlugin) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	if req.Role == sdk.RoleConsumer {
		return sdk.LinkStatus{State: sdk.StateDegraded, Detail: "медленно"}, nil
	}
	return sdk.LinkStatus{State: sdk.StateOK}, nil
}

func (p *linkPlugin) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	p.rec.add("%s link.refresh %d", p.id, req.Link)
	return p.binding(req), nil
}

func (p *linkPlugin) setHook(fn func(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error) {
	p.lmu.Lock()
	p.onApply = fn
	p.lmu.Unlock()
}

func (p *linkPlugin) sdkHost() *sdk.Host {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	return p.host
}

// linkEnv: plugins "prov" (provides web: http.service with client, db:
// postgres.db), "cons" (requires target: http.service, db: postgres.db
// optional), "nolink" (provides http.service, no link.*), and targets web
// and db.
type linkEnv struct {
	*harness
	rec     *recorder
	plugs   map[string]sdk.Plugin
	web, db string
}

func provManifest(m *sdk.Manifest) {
	m.ID, m.Name = "prov", "Prov"
	m.Permissions = []string{sdk.PermTargetsRead, sdk.PermTargetsExec, sdk.PermLinksClient}
	m.Provides = []sdk.Port{
		{Name: "web", Type: types.HTTPServiceType, Label: "Веб", Client: true, LinkSchema: &sdk.Schema{Fields: []sdk.Field{
			{Name: "hostname", Type: sdk.FieldString, Label: "Имя", Default: "x.home", Pattern: "^[a-z.]+$"}}}},
		{Name: "db", Type: types.PostgresDBType, Label: "База"},
	}
}

func consManifest(id string) func(*sdk.Manifest) {
	return func(m *sdk.Manifest) {
		m.ID, m.Name = id, strings.ToUpper(id[:1])+id[1:]
		m.Permissions = []string{sdk.PermTargetsRead}
		m.Provides = nil
		m.Requires = []sdk.Port{
			{Name: "target", Type: types.HTTPServiceType, Label: "Что проверять"},
			{Name: "db", Type: types.PostgresDBType, Optional: true},
		}
		m.Schema = sdk.Schema{Fields: []sdk.Field{{Name: "message", Type: sdk.FieldString, Label: "Текст", Default: "hi"}}}
	}
}

func newLinkEnv(t *testing.T) *linkEnv {
	h := newHarness(t)
	e := &linkEnv{harness: h, rec: &recorder{}, plugs: map[string]sdk.Plugin{}}
	e.plugs["prov"] = newLinkPlugin("prov", e.rec)
	e.plugs["cons"] = newLinkPlugin("cons", e.rec)
	e.plugs["nolink"] = &testPlugin{}
	// startProc calls plug with h.mu held.
	h.plug = func(id string) sdk.Plugin { return e.plugs[id] }
	key := newKey(t)
	e.installPkg(testPackage(t, key, provManifest), "prov")
	e.installPkg(testPackage(t, key, consManifest("cons")), "cons")
	e.installPkg(testPackage(t, key, func(m *sdk.Manifest) {
		m.ID, m.Name = "nolink", "NoLink"
		m.Provides = []sdk.Port{{Type: types.HTTPServiceType}}
	}), "nolink")
	e.web = addSSHTarget(t, h, "web", "10.10.10.21")
	e.db = addSSHTarget(t, h, "db", "10.10.10.22")
	return e
}

func (e *linkEnv) installPkg(pkg []byte, id string) {
	e.t.Helper()
	if j := e.install(pkg); j.Status != store.JobDone {
		e.t.Fatal(jobLog(j))
	}
	e.waitConnected(id)
}

func (e *linkEnv) lp(id string) *linkPlugin { return e.plugs[id].(*linkPlugin) }

func (e *linkEnv) create(pid, name string, cfg map[string]any) int64 {
	e.t.Helper()
	pv, err := e.m.CreatePlan(context.Background(), pid, name, cfg)
	if err != nil {
		e.t.Fatalf("plan %s: %v", pid, err)
	}
	if j := applyPlan(e.t, e.harness, pv, false); j.Status != store.JobDone {
		e.t.Fatalf("create %s: %s", pid, jobLog(j))
	}
	return pv.Instance.ID
}

func (e *linkEnv) apply(pv *PlanView) store.Job {
	e.t.Helper()
	return applyPlan(e.t, e.harness, pv, false)
}

func (e *linkEnv) links() []store.PluginLink {
	l, err := e.st.ListLinks(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		var pe *Error
		if errors.As(err, &pe) && len(pe.Fields) > 0 && strings.Contains(pe.Fields[0].Msg, sub) {
			return
		}
		t.Fatalf("want %q, got %v", sub, err)
	}
}

func TestManifestPorts(t *testing.T) {
	base := func() sdk.Manifest {
		var m sdk.Manifest
		_ = json.Unmarshal(testManifest(newKey(t), nil), &m)
		return m
	}
	ok := base()
	ok.Provides = []sdk.Port{{Type: "http.service"}, {Type: "demo.thing"}} // 02h: no names
	ok.Requires = []sdk.Port{{Name: "db", Type: "postgres.db", Optional: true}}
	if err := ValidateManifest(ok); err != nil {
		t.Fatal(err)
	}
	if ok.Provides[0].PortName() != "http_service" || !ok.Provides[0].IsMulti(true) || ok.Requires[0].IsMulti(false) {
		t.Fatalf("%+v", ok.Provides)
	}
	cases := []struct {
		mod  func(*sdk.Manifest)
		want string
	}{
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Type: "nosuch.type"}} }, "префикс другого плагина"},
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Type: "smtp"}} }, "неизвестный официальный тип"},
		{func(m *sdk.Manifest) { m.Requires = []sdk.Port{{Type: "other.thing"}} }, "префикс другого плагина"},
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Type: "http.service", Client: true}} }, "links.client"},
		{func(m *sdk.Manifest) {
			m.Provides = []sdk.Port{{Name: "a", Type: "http.service"}, {Name: "a", Type: "postgres.db"}}
		}, "дважды"},
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Type: "http.service"}, {Type: "http.service"}} }, "дважды"},
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Name: "Bad", Type: "http.service"}} }, "неверное имя порта"},
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Type: "http.service", Optional: true}} }, "только в requires"},
		{func(m *sdk.Manifest) { m.Requires = []sdk.Port{{Type: "http.service", Client: true}} }, "только в provides"},
		{func(m *sdk.Manifest) {
			m.Provides = []sdk.Port{{Type: "http.service", LinkSchema: &sdk.Schema{Fields: []sdk.Field{{Name: "t", Type: sdk.FieldTarget, Label: "T"}}}}}
		}, "в форме связи нет полей"},
	}
	for i, c := range cases {
		m := base()
		c.mod(&m)
		if err := ValidateManifest(m); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("case %d: want %q, got %v", i, c.want, err)
		}
	}
	// links.client makes client ports valid.
	m := base()
	m.Permissions = append(m.Permissions, sdk.PermLinksClient)
	m.Provides = []sdk.Port{{Type: "http.service", Client: true}}
	if err := ValidateManifest(m); err != nil {
		t.Fatal(err)
	}
	// Official prefixes are reserved ids.
	m.ID = "http"
	if err := ValidateManifest(m); err == nil {
		t.Fatal("id http accepted")
	}
}

func TestTypesBinding(t *testing.T) {
	good := map[string]string{
		types.HTTPServiceType: `{"url":"http://10.10.10.21:8080/","host":"10.10.10.21","port":8080,"scheme":"http"}`,
		types.CAIssuerType:    `{"ca_pem":"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n","issue":"rpc"}`,
		types.PostgresDBType:  `{"host":"db.home","port":5432,"database":"app","user":"app","password":"pw"}`,
		types.SMBShareType:    `{"host":"10.10.10.30","share":"media","user":"u","password":"pw","vers":"3.0"}`,
		types.FSMediaType:     `{"path":"/srv/media"}`,
	}
	for typ, b := range good {
		if _, err := types.Validate(typ, json.RawMessage(b), false); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
	bad := map[string]string{
		`{"url":"ftp://x/","host":"x","port":21,"scheme":"http"}`:           "http(s)",
		`{"url":"http://x/","host":"x","port":0,"scheme":"http"}`:           "порт",
		`{"url":"https://x/","host":"x","port":1,"scheme":"http"}`:          "схемой",
		`{"url":"http://x/","host":"x","port":1,"scheme":"http","extra":1}`: "контракт",
		`{"url":"http://x/","host":"bad host","port":1,"scheme":"http"}`:    "имя хоста",
		`[1]`:                                   "объектом",
		`{"host":"x","port":1,"scheme":"http"}`: "обязательное",
	}
	for b, want := range bad {
		if _, err := types.Validate(types.HTTPServiceType, json.RawMessage(b), false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", b, want, err)
		}
	}
	// Secret fields become references; the consumer side checks them.
	out, secs, err := processBinding(7, types.PostgresDBType, json.RawMessage(good[types.PostgresDBType]), true)
	if err != nil || secs["password"] != "pw" || strings.Contains(out, `"pw"`) || !strings.Contains(out, `{"secret":"link:7:password"}`) {
		t.Fatalf("%s %v %v", out, secs, err)
	}
	if _, err := types.Validate(types.PostgresDBType, json.RawMessage(out), true); err != nil {
		t.Fatal(err)
	}
	if _, err := types.Validate(types.PostgresDBType, json.RawMessage(good[types.PostgresDBType]), true); err == nil {
		t.Fatal("plain secret accepted as a reference")
	}
	if _, _, err := processBinding(7, types.PostgresDBType, json.RawMessage(`{"host":"x"}`), true); err == nil {
		t.Fatal("incomplete binding accepted")
	}
	if _, _, err := processBinding(7, types.HTTPServiceType, nil, true); err == nil {
		t.Fatal("no binding accepted")
	}
	// The Go structures round-trip.
	var pg types.PostgresDB
	if err := json.Unmarshal([]byte(out), &pg); err != nil || pg.Password.Ref != "link:7:password" || pg.Port != 5432 {
		t.Fatalf("%+v %v", pg, err)
	}
}

func TestServiceLink(t *testing.T) {
	e := newLinkEnv(t)
	ctx := context.Background()
	prov := e.create("prov", "P1", map[string]any{"target": e.web, "message": "a"})
	cons := e.create("cons", "C1", nil)
	cp := e.lp("cons")

	// The consumer reads the database password through the link and logs
	// it: Hestia masks it in the job log.
	var got string
	cp.setHook(func(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
		if req.Type != types.PostgresDBType {
			return nil
		}
		var b types.PostgresDB
		if err := json.Unmarshal(req.Binding, &b); err != nil {
			return err
		}
		v, ok, err := job.Host().SecretGet(ctx, req.Instance.ID, b.Password.Ref)
		if err != nil || !ok {
			return fmt.Errorf("secret %q: %v %v", b.Password.Ref, ok, err)
		}
		got = v
		job.Logf("password is %s", v)
		return nil
	})

	// Errors: unknown ports, incompatible types, self, no link.* support.
	_, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "nope"}, Consumer: &LinkEnd{cons, "target"}})
	wantErr(t, err, "нет порта provides")
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "db"}, Consumer: &LinkEnd{cons, "target"}})
	wantErr(t, err, "несовместимые типы")
	nl := e.create("nolink", "N1", map[string]any{"target": e.web})
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{nl, "http_service"}, Consumer: &LinkEnd{cons, "target"}})
	wantErr(t, err, "не поддерживает связи")
	if l := e.links(); len(l) != 0 {
		t.Fatalf("drafts listed: %+v", l)
	}

	// Plan of both sides, then apply.
	pv, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "db"}, Consumer: &LinkEnd{cons, "db"}})
	if err != nil {
		t.Fatal(err)
	}
	if pv.Action != "link" || len(pv.Steps) != 1 || len(pv.Plan.Actions) != 2 || pv.Plan.Actions[0].Title != "P1: provider create db" ||
		pv.Plan.Actions[1].Title != "C1: consumer create db" || len(pv.Hash) != 64 {
		t.Fatalf("%+v", pv)
	}
	j := e.apply(pv)
	if j.Status != store.JobDone || j.Kind != JobLink {
		t.Fatalf("%s", jobLog(j))
	}
	if got != "pg-secret-1" || strings.Contains(jobLog(j), "pg-secret-1") || !strings.Contains(jobLog(j), "password is ***") {
		t.Fatalf("secret %q, log:\n%s", got, jobLog(j))
	}
	links := e.links()
	if len(links) != 1 {
		t.Fatalf("%+v", links)
	}
	l := links[0]
	if strings.Contains(l.Binding, "pg-secret") || !strings.Contains(l.Binding, fmt.Sprintf(`"password":{"secret":"link:%d:password"}`, l.ID)) {
		t.Fatalf("binding %s", l.Binding)
	}
	if !e.rec.has(fmt.Sprintf("prov link.apply provider %d create", l.ID)) || !e.rec.has(fmt.Sprintf("cons link.apply consumer %d create", l.ID)) {
		t.Fatal(e.rec.list())
	}
	// Status: the worst of both sides.
	v, err := e.m.Link(ctx, l.ID, true)
	if err != nil || v.Status != sdk.StateDegraded || !strings.Contains(v.Detail, "C1: медленно") || v.Type != types.PostgresDBType ||
		v.Consumer == nil || v.Consumer.Name != "C1" || strings.Contains(string(v.Binding), "pg-secret") {
		t.Fatalf("%+v %v", v, err)
	}

	// Secrets of the link: only the consumer reads them, only while the
	// link is active; nobody writes them through secret.put.
	ref := linkSecretName(l.ID, "password")
	ch := cp.sdkHost()
	if v, ok, err := ch.SecretGet(ctx, cons, ref); err != nil || !ok || v != "pg-secret-1" {
		t.Fatalf("consumer read: %q %v %v", v, ok, err)
	}
	ph := e.lp("prov").sdkHost()
	if _, _, err := ph.SecretGet(ctx, prov, ref); err == nil || !strings.Contains(err.Error(), "не потребитель") {
		t.Fatalf("provider read: %v", err)
	}
	if _, _, err := ch.SecretGet(ctx, prov, ref); err == nil || !strings.Contains(err.Error(), "другому плагину") {
		t.Fatalf("foreign instance: %v", err)
	}
	if err := ph.SecretPut(ctx, prov, ref, "forged"); err == nil || !strings.Contains(err.Error(), "пишет только Hestia") {
		t.Fatalf("provider put: %v", err)
	}
	if err := ch.SecretDelete(ctx, cons, ref); err == nil {
		t.Fatal("consumer deleted a link secret")
	}
	if _, _, err := ch.SecretGet(ctx, cons, "link:999:password"); err == nil || !strings.Contains(err.Error(), "не найдена") {
		t.Fatalf("foreign link: %v", err)
	}
	// An inactive (orphaned) link: no access.
	if err := e.st.SetLinkStatus(ctx, l.ID, store.LinkOrphaned, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ch.SecretGet(ctx, cons, ref); err == nil || !strings.Contains(err.Error(), "не активна") {
		t.Fatalf("inactive link: %v", err)
	}
	_ = e.st.SetLinkStatus(ctx, l.ID, sdk.StateOK, "", nil)

	// The same link again; a second provider on a single port.
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "db"}, Consumer: &LinkEnd{cons, "db"}})
	wantErr(t, err, "уже подключён")
	pv2, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "web"}, Consumer: &LinkEnd{cons, "target"}})
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(pv2); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	p2 := e.create("prov", "P2", map[string]any{"target": e.db})
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{p2, "web"}, Consumer: &LinkEnd{cons, "target"}})
	wantErr(t, err, "уже подключён")

	// Candidates: the occupied requires port is busy for other providers.
	c, err := e.m.LinkCandidates(ctx, cons, "target", "requires")
	if err != nil || len(c.Ports) != 3 || len(c.NewPlugin) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, p := range c.Ports {
		if p.Available {
			t.Fatalf("available while the port is taken: %+v", p)
		}
	}

	// Remove: consumer first, then provider; secrets go.
	e.rec.reset()
	rv, err := e.m.LinkChangePlan(ctx, l.ID, "remove")
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(rv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if r := e.rec.list(); len(r) != 2 || r[0] != fmt.Sprintf("cons link.remove consumer %d", l.ID) || r[1] != fmt.Sprintf("prov link.remove provider %d", l.ID) {
		t.Fatalf("%v", r)
	}
	if ids, _ := e.st.SecretIDsByPrefix(ctx, linkSecretPrefix(l.ID)); len(ids) != 0 {
		t.Fatal("link secrets kept")
	}
	if _, _, err := ch.SecretGet(ctx, cons, ref); err == nil {
		t.Fatal("secret of a removed link readable")
	}
	if len(e.links()) != 1 {
		t.Fatalf("%+v", e.links())
	}
}

func TestServiceLinkRollbackAndOrphan(t *testing.T) {
	e := newLinkEnv(t)
	ctx := context.Background()
	prov := e.create("prov", "P1", map[string]any{"target": e.web})
	cons := e.create("cons", "C1", nil)
	cp, pp := e.lp("cons"), e.lp("prov")

	// The consumer fails: the provider side is undone, the link is gone.
	cp.lmu.Lock()
	cp.failApply[sdk.RoleConsumer] = errors.New("consumer broke")
	cp.lmu.Unlock()
	pv, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "db"}, Consumer: &LinkEnd{cons, "db"}})
	if err != nil {
		t.Fatal(err)
	}
	j := e.apply(pv)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "consumer broke") {
		t.Fatal(jobLog(j))
	}
	id := pv.Steps[0].Title
	_ = id
	r := e.rec.list()
	if len(r) < 3 || !strings.HasPrefix(r[len(r)-1], "prov link.remove provider") {
		t.Fatalf("%v", r)
	}
	if len(e.links()) != 0 {
		t.Fatalf("%+v", e.links())
	}
	if ids, _ := e.st.SecretIDsByPrefix(ctx, linkSecretP); len(ids) != 0 {
		t.Fatal("secrets of the failed link kept")
	}

	// The provider fails on removal: the link is orphaned; only its record
	// can go.
	cp.lmu.Lock()
	delete(cp.failApply, sdk.RoleConsumer)
	cp.lmu.Unlock()
	pv, _ = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "db"}, Consumer: &LinkEnd{cons, "db"}})
	if j := e.apply(pv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	l := e.links()[0]
	pp.lmu.Lock()
	pp.failRemove[sdk.RoleProvider] = errors.New("provider stuck")
	pp.lmu.Unlock()
	rv, err := e.m.LinkChangePlan(ctx, l.ID, "remove")
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(rv); j.Status != store.JobFailed || !strings.Contains(j.Error, "осиротевшая") {
		t.Fatal(jobLog(j))
	}
	l, _ = e.st.GetLink(ctx, l.ID)
	if l.Status != store.LinkOrphaned || !strings.Contains(l.Detail, "provider stuck") {
		t.Fatalf("%+v", l)
	}
	if ids, _ := e.st.SecretIDsByPrefix(ctx, linkSecretPrefix(l.ID)); len(ids) != 0 {
		t.Fatal("secrets of an orphaned link kept")
	}
	e.rec.reset()
	fv, err := e.m.LinkChangePlan(ctx, l.ID, "remove")
	if err != nil || !strings.Contains(fv.Steps[0].Title, "Удалить запись") {
		t.Fatalf("%+v %v", fv, err)
	}
	if j := e.apply(fv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if len(e.rec.list()) != 0 || len(e.links()) != 0 {
		t.Fatalf("%v %+v", e.rec.list(), e.links())
	}

	// A changed plan of a side is refused at apply.
	pv, _ = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "db"}, Consumer: &LinkEnd{cons, "db"}})
	cp.lmu.Lock()
	cp.planNonceL = "changed"
	cp.lmu.Unlock()
	if _, err := e.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: pv.Hash}); err == nil || !strings.Contains(err.Error(), "Состояние изменилось") {
		t.Fatalf("%v", err)
	}
	if len(e.links()) != 0 {
		t.Fatal("draft became a link")
	}
	if l, _ := e.st.LinksOfInstance(ctx, prov); len(l) != 0 {
		t.Fatalf("%+v", l)
	}
}

func TestDeviceLinkGrants(t *testing.T) {
	e := newLinkEnv(t)
	ctx := context.Background()
	prov := e.create("prov", "P1", map[string]any{"target": e.web})
	pp := e.lp("prov")
	// During link.apply the provider may use the device of this link only.
	other := addSSHTarget(t, e.harness, "nas", "10.10.10.30")
	var during, foreign error
	pp.setHook(func(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
		if req.Role != sdk.RoleClient {
			return nil
		}
		_, during = job.Host().Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: "echo hosts"})
		_, foreign = job.Host().Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: other, Cmd: "echo nas"})
		return nil
	})
	// Bad requests first.
	_, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "db"}, Device: &DeviceRef{e.db}})
	wantErr(t, err, "не умеет связь с устройством")
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "web"}, Device: &DeviceRef{"ssh:999"}})
	wantErr(t, err, "не найдено")
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "web"}, Device: &DeviceRef{e.db}, Config: map[string]any{"hostname": "BAD!"}})
	if err == nil {
		t.Fatal("link form not validated")
	}

	// "other" is the device of another link of the same instance.
	hook := pp.onApply
	pp.setHook(nil)
	ov, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "web"}, Device: &DeviceRef{other}})
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(ov); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	pp.setHook(hook)
	pv, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "web"}, Device: &DeviceRef{e.db}})
	if err != nil {
		t.Fatal(err)
	}
	if len(pv.Plan.Actions) != 1 || pv.Plan.Actions[0].Title != "P1: client create web" {
		t.Fatalf("%+v", pv)
	}
	// Planning gives no access to the device.
	if _, err := pp.sdkHost(), error(nil); err != nil {
		t.Fatal(err)
	}
	if j := e.apply(pv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if during != nil {
		t.Fatalf("exec on the device during link.apply: %v", during)
	}
	if foreign == nil || !strings.Contains(foreign.Error(), "permission denied") {
		t.Fatalf("exec on the device of another link: %v", foreign)
	}
	l := e.links()[1]
	if l.Kind != store.LinkKindDevice || l.DeviceRef != e.db || !strings.Contains(l.Config, `"hostname":"x.home"`) {
		t.Fatalf("%+v", l)
	}
	if ok, _ := e.st.HasLinkGrant(ctx, prov, e.db, l.ID); !ok {
		t.Fatal("no via_link grant")
	}
	// The via_link grant is not a grant of its own: outside link.* calls
	// the device is closed, and the instance's targets do not list it.
	// Wait for the background link.status after apply (it legitimately
	// opens the device while it runs).
	for deadline := time.Now().Add(5 * time.Second); ; {
		if ls := e.links(); ls[1].Status != sdk.StateUnknown || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	host := pp.sdkHost()
	if _, err := host.Exec(ctx, sdk.ExecRequest{Instance: prov, Target: e.db, Cmd: "echo late"}); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("exec after link.apply: %v", err)
	}
	if ts, err := host.Targets(ctx, prov); err != nil || len(ts) != 1 || ts[0].ID != e.web {
		t.Fatalf("%+v %v", ts, err)
	}
	if v, _ := e.m.Instance(ctx, prov, false); len(v.Targets) != 1 {
		t.Fatalf("%+v", v.Targets)
	}
	// The device can be linked once per port.
	_, err = e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "web"}, Device: &DeviceRef{e.db}})
	wantErr(t, err, "уже есть")
	c, err := e.m.LinkCandidates(ctx, prov, "web", "provides")
	if err != nil || len(c.Devices) != 3 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, d := range c.Devices {
		if d.Device == e.db && d.Available {
			t.Fatalf("linked device available: %+v", d)
		}
	}

	// Removal: link.remove has the device again, then the grant goes.
	var removing error
	pp.setHook(nil)
	rv, err := e.m.LinkChangePlan(ctx, l.ID, "remove")
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(rv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	_ = removing
	if ok, _ := e.st.HasLinkGrant(ctx, prov, e.db, l.ID); ok {
		t.Fatal("via_link grant kept")
	}
	if !e.rec.has(fmt.Sprintf("prov link.remove client %d", l.ID)) {
		t.Fatal(e.rec.list())
	}
}

func TestRefreshAndRemoveWithLinks(t *testing.T) {
	e := newLinkEnv(t)
	ctx := context.Background()
	prov := e.create("prov", "P1", map[string]any{"target": e.web, "message": "a"})
	cons := e.create("cons", "C1", nil)
	pv, _ := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "web"}, Consumer: &LinkEnd{cons, "target"}})
	if j := e.apply(pv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	dv, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "device", Provider: LinkEnd{prov, "web"}, Device: &DeviceRef{e.db}})
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(dv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	links := e.links()
	svc, dev := links[0], links[1]

	// Same configuration: refresh, nothing applied again.
	e.rec.reset()
	up, err := e.m.ChangePlan(ctx, prov, "update", map[string]any{"target": e.web, "message": "a"})
	if err != nil {
		t.Fatal(err)
	}
	if j := e.apply(up); j.Status != store.JobDone || !strings.Contains(jobLog(j), "данные не изменились") {
		t.Fatal(jobLog(j))
	}
	if e.rec.has(fmt.Sprintf("cons link.apply consumer %d update", svc.ID)) {
		t.Fatal(e.rec.list())
	}
	// A new binding goes to the consumer and to the device.
	up, _ = e.m.ChangePlan(ctx, prov, "update", map[string]any{"target": e.web, "message": "b"})
	if j := e.apply(up); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if !e.rec.has(fmt.Sprintf("prov link.refresh %d", svc.ID)) || !e.rec.has(fmt.Sprintf("cons link.apply consumer %d update", svc.ID)) ||
		!e.rec.has(fmt.Sprintf("prov link.apply client %d update", dev.ID)) {
		t.Fatal(e.rec.list())
	}
	if l, _ := e.st.GetLink(ctx, svc.ID); !strings.Contains(l.Binding, "8080/b") {
		t.Fatal(l.Binding)
	}

	// Removing the provider removes both links first.
	e.rec.reset()
	rv, err := e.m.ChangePlan(ctx, prov, "remove", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rv.Action != "remove" || len(rv.Steps) != 3 || rv.Steps[2].Kind != "instance" {
		t.Fatalf("%+v", rv)
	}
	if j := e.apply(rv); j.Status != store.JobDone || j.Kind != JobCompose {
		t.Fatal(jobLog(j))
	}
	r := e.rec.list()
	if len(r) != 4 || r[3] != "prov instance remove P1" {
		t.Fatalf("%v", r)
	}
	if len(e.links()) != 0 {
		t.Fatal("links kept")
	}
	if _, err := e.st.GetInstance(ctx, prov); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("provider kept")
	}
	if ok, _ := e.st.HasLinkGrant(ctx, prov, e.db, dev.ID); ok {
		t.Fatal("grant kept")
	}
}

// composeEnv adds "mid" (requires and provides http.service) and m1…m4 for
// the depth limit.
func composeEnv(t *testing.T) *linkEnv {
	e := newLinkEnv(t)
	key := newKey(t)
	for _, id := range []string{"mid", "ma", "mb", "mc", "md"} {
		e.mu.Lock()
		e.plugs[id] = newLinkPlugin(id, e.rec)
		e.mu.Unlock()
		e.installPkg(testPackage(t, key, func(m *sdk.Manifest) {
			consManifest(id)(m)
			m.Requires = m.Requires[:1]
			m.Provides = []sdk.Port{{Name: "web", Type: types.HTTPServiceType}}
		}), id)
	}
	return e
}

func TestComposePlan(t *testing.T) {
	e := composeEnv(t)
	ctx := context.Background()
	newProv := func() *ComposeNode {
		return &ComposeNode{PluginID: "prov", Config: map[string]any{"target": e.web}}
	}

	// Validation: a missing provider, a missing target of a new one,
	// cycles, depth.
	_, err := e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "cons"}})
	wantErr(t, err, "не выбран поставщик")
	_, err = e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "cons"},
		Deps: []ComposeDep{{Port: "target", New: &ComposeNode{PluginID: "prov"}}}})
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != 422 || len(pe.Fields) != 1 || pe.Fields[0].Field != "deps[0].new.target" {
		t.Fatalf("%+v", err)
	}
	_, err = e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "mid"},
		Deps: []ComposeDep{{Port: "target", New: &ComposeNode{PluginID: "mid", Deps: []ComposeDep{{Port: "target", New: newProv()}}}}}})
	wantErr(t, err, "цикл")
	chain := func(ids ...string) ComposeRequest {
		leaf := newProv()
		for i := len(ids) - 1; i >= 1; i-- {
			leaf = &ComposeNode{PluginID: ids[i], Deps: []ComposeDep{{Port: "target", New: leaf}}}
		}
		return ComposeRequest{Root: ComposeNode{PluginID: ids[0]}, Deps: []ComposeDep{{Port: "target", New: leaf}}}
	}
	_, err = e.m.ComposePlan(ctx, chain("ma", "mb", "mc", "md"))
	wantErr(t, err, "вложенность")
	_, err = e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "cons"},
		Deps: []ComposeDep{{Port: "target", New: newProv()}, {Port: "target", New: newProv()}}})
	wantErr(t, err, "только один поставщик")
	if ins, _ := e.st.ListInstances(ctx, "", true); len(ins) != 0 {
		t.Fatalf("drafts left: %+v", ins)
	}

	// Level 0: an existing provider.
	p0 := e.create("prov", "P0", map[string]any{"target": e.web})
	pv, err := e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "cons", Name: "C0"},
		Deps: []ComposeDep{{Port: "target", Existing: &LinkEnd{p0, "web"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if pv.Action != "compose" || len(pv.Steps) != 2 || pv.Steps[0].Kind != "instance" || pv.Steps[1].Kind != "link" || pv.Instance.Name != "C0" {
		t.Fatalf("%+v", pv)
	}
	e.rec.reset()
	if j := e.apply(pv); j.Status != store.JobDone || j.Kind != JobCompose {
		t.Fatal(jobLog(j))
	}
	if r := e.rec.list(); len(r) < 4 || r[0] != "cons instance create C0" || r[1] != "cons planned link target ← P0/web" {
		t.Fatalf("%v", r)
	}
	if len(e.links()) != 1 {
		t.Fatal(e.links())
	}

	// Level 2: cons ← new mid ← new prov; the depth limit allows 3.
	pv, err = e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "cons", Name: "C2"},
		Deps: []ComposeDep{{Port: "target", New: &ComposeNode{PluginID: "mid", Deps: []ComposeDep{{Port: "target", New: newProv()}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, s := range pv.Steps {
		titles = append(titles, s.Kind+":"+s.Action)
		if s.Rollback == "" {
			t.Fatalf("no rollback shown: %+v", s)
		}
	}
	if strings.Join(titles, ",") != "instance:create,instance:create,instance:create,link:create,link:create" {
		t.Fatalf("%v", titles)
	}
	if !strings.Contains(pv.Steps[0].Title, "Prov 2") || !strings.Contains(pv.Steps[2].Title, "C2") {
		t.Fatalf("%+v", pv.Steps)
	}
	// A wrong hash, then the real one.
	if _, err := e.m.Apply(ctx, pv.PlanID, ApplyRequest{Hash: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("wrong hash")
	}
	if j := e.apply(pv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if len(e.links()) != 3 {
		t.Fatal(e.links())
	}
	if _, err := e.m.ComposePlan(ctx, chain("ma", "mb", "mc")); err != nil {
		t.Fatalf("depth 3: %v", err)
	}

	// Failures at every step roll back what was applied, in reverse.
	before := len(e.links())
	ins0, _ := e.st.ListInstances(ctx, "", false)
	for step := 0; step < 5; step++ {
		t.Run(fmt.Sprint("fail", step), func(t *testing.T) {
			pv, err := e.m.ComposePlan(ctx, ComposeRequest{Root: ComposeNode{PluginID: "cons", Name: fmt.Sprint("F", step)},
				Deps: []ComposeDep{{Port: "target", New: &ComposeNode{PluginID: "mid", Name: fmt.Sprint("FM", step),
					Deps: []ComposeDep{{Port: "target", New: &ComposeNode{PluginID: "prov", Name: fmt.Sprint("FP", step), Config: map[string]any{"target": e.web}}}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			// Steps: prov, mid, cons, link prov→mid, link mid→cons.
			fail := map[int]func(bool){
				0: func(on bool) { setFail(e.lp("prov").failInst, sdk.ActionCreate, on, e.lp("prov")) },
				1: func(on bool) { setFail(e.lp("mid").failInst, sdk.ActionCreate, on, e.lp("mid")) },
				2: func(on bool) { setFail(e.lp("cons").failInst, sdk.ActionCreate, on, e.lp("cons")) },
				3: func(on bool) { setFail(e.lp("mid").failApply, sdk.RoleConsumer, on, e.lp("mid")) },
				4: func(on bool) { setFail(e.lp("cons").failApply, sdk.RoleConsumer, on, e.lp("cons")) },
			}[step]
			fail(true)
			defer fail(false)
			e.rec.reset()
			j := e.apply(pv)
			if j.Status != store.JobFailed || !strings.Contains(j.Error, "injected") {
				t.Fatal(jobLog(j))
			}
			r := strings.Join(e.rec.list(), "\n")
			wantUndo := map[int][]string{
				0: nil,
				1: {"prov instance remove FP"},
				2: {"mid instance remove FM", "prov instance remove FP"},
				3: {"mid instance remove FM", "prov instance remove FP"},
				4: {"mid link.remove consumer", "cons instance remove F", "mid instance remove FM", "prov instance remove FP"},
			}[step]
			last := -1
			for _, w := range wantUndo {
				i := strings.Index(r, w)
				if i < 0 || i < last {
					t.Fatalf("undo %q missing or out of order:\n%s", w, r)
				}
				last = i
			}
			ins, _ := e.st.ListInstances(ctx, "", false)
			if len(ins) != len(ins0) || len(e.links()) != before {
				t.Fatalf("left behind: %d instances, %d links\n%s", len(ins), len(e.links()), jobLog(j))
			}
		})
	}
}

func setFail(m map[string]error, key string, on bool, p *linkPlugin) {
	p.lmu.Lock()
	defer p.lmu.Unlock()
	if on {
		m[key] = errors.New("injected " + key)
	} else {
		delete(m, key)
	}
}

func TestGraphAndPositions(t *testing.T) {
	e := newLinkEnv(t)
	ctx := context.Background()
	prov := e.create("prov", "P1", map[string]any{"target": e.web})
	cons := e.create("cons", "C1", nil)
	pv, _ := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: "service", Provider: LinkEnd{prov, "web"}, Consumer: &LinkEnd{cons, "target"}})
	if j := e.apply(pv); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	cs, _ := json.Marshal([]cachedProject{{Target: e.web, Project: "hestia-1-whoami", Containers: []sdk.DeployContainer{
		{Name: "hestia-1-whoami-whoami-1", Image: "traefik/whoami:v1.10", State: "running"}}}})
	_ = e.st.SetInstanceContainers(ctx, prov, string(cs))
	g, err := e.m.Graph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Instances) != 2 || len(g.Links) != 1 || g.Links[0].Kind != "service" || g.Links[0].Type != "http.service" {
		t.Fatalf("%+v", g)
	}
	p, c := g.Instances[0], g.Instances[1]
	if p.HostRef != e.web || p.HostIP != "10.10.10.21" || p.Controller || len(p.Containers) != 1 || p.Containers[0].Image != "traefik/whoami:v1.10" ||
		len(p.Provides) != 2 || p.Provides[0].Linked != 1 || !p.Provides[0].Client {
		t.Fatalf("%+v", p)
	}
	// No target: on the controller (its host is not on the map here).
	if c.HostRef != "" || !c.Controller || c.HostIP != "" || len(c.Requires) != 2 || c.Requires[0].Linked != 1 || c.Requires[1].Optional != true {
		t.Fatalf("%+v", c)
	}
	b, _ := json.Marshal(g)
	if !strings.Contains(string(b), `"positions":{}`) {
		t.Fatalf("%s", b)
	}
	if err := e.m.SavePositions(ctx, map[string]store.Position{"host:10.10.10.21": {X: 10, Y: -5.5}}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.SavePositions(ctx, map[string]store.Position{"": {X: 1}}); err == nil {
		t.Fatal("empty id saved")
	}
	g, _ = e.m.Graph(ctx)
	if g.Positions["host:10.10.10.21"] != (store.Position{X: 10, Y: -5.5}) {
		t.Fatalf("%+v", g.Positions)
	}
	if err := e.m.ClearPositions(ctx); err != nil {
		t.Fatal(err)
	}
	if g, _ = e.m.Graph(ctx); len(g.Positions) != 0 {
		t.Fatalf("%+v", g.Positions)
	}
}
