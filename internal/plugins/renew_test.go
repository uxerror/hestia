package plugins

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// testCA signs leaves for the tls.cert tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t testing.TB, cn string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

var serialN = struct {
	sync.Mutex
	n int64
}{n: 100}

// sign issues a leaf for pub with the names, valid from nb to na.
func (ca *testCA) sign(t testing.TB, pub any, dns, ips []string, nb, na time.Time) (string, string) {
	serialN.Lock()
	serialN.n++
	sn := serialN.n
	serialN.Unlock()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(sn), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: nb, NotAfter: na,
		DNSNames: dns, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), big.NewInt(sn).Text(16)
}

// caProv provides tls.cert; mode makes it misbehave.
type caProv struct {
	testPlugin
	t   testing.TB
	rec *recorder
	ca  *testCA

	mu       sync.Mutex
	mode     string // "" | other-key | extra-san | other-root | expired | fail
	life     time.Duration
	previews []string
	other    *testCA
	now      func() time.Time
}

func (p *caProv) setMode(m string) {
	p.mu.Lock()
	p.mode = m
	p.mu.Unlock()
}

func (p *caProv) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	p.mu.Lock()
	p.previews = append(p.previews, string(req.Request))
	p.mu.Unlock()
	if req.Action == sdk.ActionRemove {
		return sdk.Plan{Actions: []sdk.Action{{Title: "revoke", Risk: sdk.RiskChange}}}, nil
	}
	var r types.TLSRequest
	_ = json.Unmarshal(req.Request, &r)
	for _, n := range r.DNS {
		if !strings.HasSuffix(n, ".home") {
			return sdk.Plan{}, errors.New(n + ": вне зон CA (home)")
		}
	}
	return sdk.Plan{Actions: []sdk.Action{{Title: "issue " + strings.Join(r.Names(), ","), Risk: sdk.RiskChange}},
		Request: json.RawMessage(`{"dns":["evil.example"]}`)}, nil
}

func (p *caProv) issue(req sdk.LinkRequest) (json.RawMessage, error) {
	p.mu.Lock()
	mode, life := p.mode, p.life
	p.mu.Unlock()
	if mode == "fail" {
		return nil, errors.New("CA недоступен")
	}
	var r types.TLSRequest
	if err := json.Unmarshal(req.Request, &r); err != nil || r.CSRPEM == "" {
		return nil, errors.New("no csr")
	}
	csr, err := types.ParseCSR(r.CSRPEM)
	if err != nil {
		return nil, err
	}
	pub := csr.PublicKey
	dns, ips := r.DNS, r.IPs
	ca := p.ca
	if life == 0 {
		life = 90 * 24 * time.Hour
	}
	nb := p.now().Add(-5 * time.Minute).Truncate(time.Second)
	na := nb.Add(life)
	switch mode {
	case "other-key":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &k.PublicKey
	case "extra-san":
		dns = append(append([]string{}, dns...), "extra.home")
	case "other-root":
		ca = p.other
	case "expired":
		nb, na = nb.Add(-48*time.Hour), nb.Add(-24*time.Hour)
	}
	certPEM, serial := ca.sign(p.t, pub, dns, ips, nb, na)
	b, _ := json.Marshal(types.TLSCert{CertPEM: certPEM, CAPEM: ca.pem, CASHA256: types.CertSHA256(ca.cert.Raw), DNS: nonNilS(dns), IPs: nonNilS(ips),
		Serial: serial, NotBefore: nb.UTC(), NotAfter: na.UTC()})
	return b, nil
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (p *caProv) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	p.rec.add("ca link.apply %d", req.Link)
	return p.issue(req)
}

func (p *caProv) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	p.rec.add("ca link.refresh %d %s", req.Link, req.Reason)
	return p.issue(req)
}

func (p *caProv) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	p.rec.add("ca link.remove %d", req.Link)
	return nil
}

func (p *caProv) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	return sdk.LinkStatus{State: sdk.StateOK}, nil
}

// tlsCons consumes tls.cert: its key never leaves it.
type tlsCons struct {
	testPlugin
	rec *recorder

	mu        sync.Mutex
	names     []string // DNS names it asks for
	prepNames []string // if set: names of link.prepare (differ from the plan)
	keys      map[int64]*ecdsa.PrivateKey
	applied   []types.TLSCert
	failApply bool
	noPrep    bool
}

func (c *tlsCons) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pl := sdk.Plan{Actions: []sdk.Action{{Title: "use cert", Risk: sdk.RiskChange}}}
	if req.Action != sdk.ActionRemove && !c.noPrep {
		pl.Request, _ = json.Marshal(types.TLSRequest{DNS: c.names, IPs: []string{"10.10.10.30"}})
	}
	return pl, nil
}

func (c *tlsCons) LinkPrepare(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rec.add("cons link.prepare %d %s", req.Link, req.Reason)
	names := c.names
	if c.prepNames != nil {
		names = c.prepNames
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, k)
	if err != nil {
		return nil, err
	}
	if c.keys == nil {
		c.keys = map[int64]*ecdsa.PrivateKey{}
	}
	c.keys[req.Link] = k
	return json.Marshal(types.TLSRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		DNS: names, IPs: []string{"10.10.10.30"}})
}

func (c *tlsCons) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rec.add("cons link.apply %d %s", req.Link, req.Action)
	if c.failApply {
		return nil, errors.New("не удалось поставить сертификат")
	}
	var b types.TLSCert
	_ = json.Unmarshal(req.Binding, &b)
	c.applied = append(c.applied, b)
	return nil, nil
}

func (c *tlsCons) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	c.rec.add("cons link.remove %d", req.Link)
	return nil
}

func (c *tlsCons) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	return sdk.LinkStatus{State: sdk.StateOK}, nil
}

func (c *tlsCons) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	return nil, nil
}

func (c *tlsCons) lastApplied() types.TLSCert {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.applied) == 0 {
		return types.TLSCert{}
	}
	return c.applied[len(c.applied)-1]
}

// plainCons is a tls.cert consumer without link.prepare.
type plainCons struct{ tlsCons }

type noPreparer struct{ *plainCons }

func (n noPreparer) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	return sdk.Plan{Actions: []sdk.Action{{Title: "x", Risk: sdk.RiskChange}}}, nil
}
func (n noPreparer) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	return nil, nil
}
func (n noPreparer) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	return nil
}
func (n noPreparer) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	return sdk.LinkStatus{State: sdk.StateOK}, nil
}
func (n noPreparer) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	return nil, nil
}

type tlsEnv struct {
	*harness
	rec       *recorder
	prov      *caProv
	cons      *tlsCons
	provInst  int64
	consInst  int64
	consInst2 int64
	clock     *fakeClock
}

type fakeClock struct {
	mu sync.Mutex
	d  time.Duration
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.d)
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.d += d
	c.mu.Unlock()
}

func newTLSEnv(t *testing.T) *tlsEnv {
	h := newHarness(t)
	e := &tlsEnv{harness: h, rec: &recorder{}, clock: &fakeClock{}}
	h.m.Now = e.clock.now
	e.prov = &caProv{t: t, rec: e.rec, ca: newTestCA(t, "Test Root"), other: newTestCA(t, "Other Root"), now: e.clock.now}
	e.cons = &tlsCons{rec: e.rec, names: []string{"svc.home"}}
	plain := noPreparer{&plainCons{}}
	plugs := map[string]sdk.Plugin{"caprov": e.prov, "tcons": e.cons, "plain": plain}
	h.plug = func(id string) sdk.Plugin { return plugs[id] }
	key := newKey(t)
	for _, p := range []struct {
		id  string
		mod func(*sdk.Manifest)
	}{
		{"caprov", func(m *sdk.Manifest) {
			m.ID, m.Name = "caprov", "CA"
			m.Provides = []sdk.Port{{Name: "tls", Type: types.TLSCertType, Label: "Сертификаты"}}
		}},
		{"tcons", func(m *sdk.Manifest) {
			m.ID, m.Name = "tcons", "TLS consumer"
			m.Provides = nil
			m.Requires = []sdk.Port{{Name: "tls", Type: types.TLSCertType, Optional: true}}
		}},
		{"plain", func(m *sdk.Manifest) {
			m.ID, m.Name = "plain", "Plain"
			m.Provides = nil
			m.Requires = []sdk.Port{{Name: "tls", Type: types.TLSCertType, Optional: true}}
		}},
	} {
		if j := h.install(testPackage(t, key, p.mod)); j.Status != store.JobDone {
			t.Fatal(jobLog(j))
		}
		h.waitConnected(p.id)
	}
	web := addSSHTarget(t, h, "web", "10.10.10.21")
	le := &linkEnv{harness: h, rec: e.rec}
	e.provInst = le.create("caprov", "CA", map[string]any{"target": web})
	e.consInst = le.create("tcons", "Svc", map[string]any{"target": web})
	e.consInst2 = le.create("plain", "Plain", map[string]any{"target": web})
	return e
}

func (e *tlsEnv) linkPlan(cons int64) (*PlanView, error) {
	return e.m.LinkPlan(context.Background(), LinkPlanRequest{Kind: sdk.LinkService, Provider: LinkEnd{Instance: e.provInst, Port: "tls"},
		Consumer: &LinkEnd{Instance: cons, Port: "tls"}})
}

func (e *tlsEnv) mustLink() store.PluginLink {
	e.t.Helper()
	pv, err := e.linkPlan(e.consInst)
	if err != nil {
		e.t.Fatal(err)
	}
	if j := applyPlan(e.t, e.harness, pv, false); j.Status != store.JobDone {
		e.t.Fatal(jobLog(j))
	}
	l, err := e.m.BuiltinLinkOf(context.Background(), e.consInst, "tls")
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

func TestTLSLinkRequest(t *testing.T) {
	e := newTLSEnv(t)
	ctx := context.Background()

	// A consumer without link.prepare cannot take tls.cert.
	_, err := e.linkPlan(e.consInst2)
	wantErr(t, err, "не умеет запрашивать сертификаты")

	// Names outside the zones: the provider's plan fails.
	e.cons.mu.Lock()
	e.cons.names = []string{"svc.lan"}
	e.cons.mu.Unlock()
	_, err = e.linkPlan(e.consInst)
	wantErr(t, err, "вне зон CA")
	e.cons.mu.Lock()
	e.cons.names = []string{"svc.home"}
	e.cons.mu.Unlock()

	// The preview reaches the provider's plan; the provider's own "request"
	// is ignored.
	pv, err := e.linkPlan(e.consInst)
	if err != nil {
		t.Fatal(err)
	}
	e.prov.mu.Lock()
	last := e.prov.previews[len(e.prov.previews)-1]
	e.prov.mu.Unlock()
	if !strings.Contains(last, "svc.home") || strings.Contains(last, "csr_pem") {
		t.Fatalf("preview %s", last)
	}
	e.rec.reset()
	if j := applyPlan(t, e.harness, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	got := e.rec.list()
	if len(got) < 3 || !strings.HasPrefix(got[0], "cons link.prepare") || !strings.HasPrefix(got[1], "ca link.apply") || !strings.HasPrefix(got[2], "cons link.apply") {
		t.Fatalf("order %v", got)
	}
	l, err := e.m.BuiltinLinkOf(ctx, e.consInst, "tls")
	if err != nil {
		t.Fatal(err)
	}
	if l.ExpiresAt == nil || l.RenewAfter == nil || !strings.Contains(l.Request, "csr_pem") {
		t.Fatalf("link %+v", l)
	}
	life := l.ExpiresAt.Sub(*l.RenewAfter) * 3
	if d := life - 90*24*time.Hour; d < -time.Second || d > time.Second {
		t.Fatalf("renew_after is not at 2/3: life %s", life)
	}
	if v, _ := e.m.Link(ctx, l.ID, false); strings.Contains(string(v.Request), "csr_pem") || !strings.Contains(string(v.Request), "svc.home") {
		t.Fatalf("view request %s", v.Request)
	}
}

func TestTLSLinkBadCertificates(t *testing.T) {
	e := newTLSEnv(t)
	for _, mode := range []string{"other-key", "extra-san", "expired"} {
		e.prov.setMode(mode)
		pv, err := e.linkPlan(e.consInst)
		if err != nil {
			t.Fatal(err)
		}
		e.rec.reset()
		j := applyPlan(t, e.harness, pv, false)
		if j.Status != store.JobFailed || !strings.Contains(jobLog(j), "сертификат от поставщика отклонён") {
			t.Fatalf("%s: %s", mode, jobLog(j))
		}
		if e.rec.has("cons link.apply 0 create") || len(e.cons.applied) > 0 {
			t.Fatalf("%s: consumer got the binding", mode)
		}
		// Rolled back on both sides (revoke and the pending key).
		if !strings.Contains(strings.Join(e.rec.list(), "\n"), "ca link.remove") || !strings.Contains(strings.Join(e.rec.list(), "\n"), "cons link.remove") {
			t.Fatalf("%s: no rollback %v", mode, e.rec.list())
		}
		if ls, _ := e.st.ListLinks(context.Background()); len(ls) != 0 {
			t.Fatalf("%s: link left", mode)
		}
	}
	// The names of link.prepare differ from the confirmed plan: refused
	// before the provider.
	e.prov.setMode("")
	e.cons.mu.Lock()
	e.cons.prepNames = []string{"other.home"}
	e.cons.mu.Unlock()
	pv, _ := e.linkPlan(e.consInst)
	e.rec.reset()
	j := applyPlan(t, e.harness, pv, false)
	if j.Status != store.JobFailed || !strings.Contains(jobLog(j), "другие имена") || e.rec.has("ca link.apply 0") {
		t.Fatalf("%s %v", jobLog(j), e.rec.list())
	}
	for _, l := range e.rec.list() {
		if strings.HasPrefix(l, "ca link.apply") {
			t.Fatalf("provider called: %v", e.rec.list())
		}
	}
	e.cons.mu.Lock()
	e.cons.prepNames = nil
	e.cons.failApply = true
	e.cons.mu.Unlock()
	// The consumer fails: the provider revokes, the pending key goes.
	pv, _ = e.linkPlan(e.consInst)
	e.rec.reset()
	if j := applyPlan(t, e.harness, pv, false); j.Status != store.JobFailed {
		t.Fatal(jobLog(j))
	}
	if !strings.Contains(strings.Join(e.rec.list(), "\n"), "ca link.remove") || !strings.Contains(strings.Join(e.rec.list(), "\n"), "cons link.remove") {
		t.Fatalf("rollback %v", e.rec.list())
	}
}

func TestTLSLinkOtherRoot(t *testing.T) {
	e := newTLSEnv(t)
	l := e.mustLink()
	// A renewal signed by another root is refused: a new root needs a new link.
	e.prov.setMode("other-root")
	before := e.cons.lastApplied().Serial
	job, err := e.m.RenewLink(context.Background(), l.ID)
	if err != nil {
		t.Fatal(err)
	}
	j := e.wait(job.ID)
	if j.Status != store.JobFailed || !strings.Contains(jobLog(j), "другим CA") {
		t.Fatal(jobLog(j))
	}
	if e.cons.lastApplied().Serial != before {
		t.Fatal("consumer got a certificate of another root")
	}
}

func TestTLSRenewal(t *testing.T) {
	e := newTLSEnv(t)
	ctx := context.Background()
	e.prov.mu.Lock()
	e.prov.life = 30 * 24 * time.Hour
	e.prov.mu.Unlock()
	l := e.mustLink()
	first := e.cons.lastApplied()

	// Not due yet: nothing happens.
	e.m.renewDue(ctx)
	waitIdle(t, e.harness)
	if e.cons.lastApplied().Serial != first.Serial {
		t.Fatal("renewed too early")
	}
	// At 2/3 of the lifetime the renewal runs: prepare → refresh → apply.
	e.clock.add(21 * 24 * time.Hour)
	e.rec.reset()
	e.m.renewDue(ctx)
	waitIdle(t, e.harness)
	got := e.rec.list()
	if len(got) < 3 || got[0] != "cons link.prepare "+strconv.FormatInt(l.ID, 10)+" renew" || got[1] != "ca link.refresh "+strconv.FormatInt(l.ID, 10)+" renew" ||
		got[2] != "cons link.apply "+strconv.FormatInt(l.ID, 10)+" update" {
		t.Fatalf("renewal %v", got)
	}
	second := e.cons.lastApplied()
	if second.Serial == first.Serial {
		t.Fatal("same certificate")
	}
	l2, _ := e.st.GetLink(ctx, l.ID)
	if !l2.ExpiresAt.After(*l.ExpiresAt) || l2.RenewError != "" {
		t.Fatalf("after renewal %+v", l2)
	}
	// The job is not duplicated while one runs; the manual one is 409 then.
	e.m.mu.Lock()
	e.m.instJobs[e.consInst] = true
	e.m.mu.Unlock()
	if _, err := e.m.RenewLink(ctx, l.ID); err == nil || err.(*Error).Status != http.StatusConflict {
		t.Fatalf("busy: %v", err)
	}
	e.m.releaseInstances(e.consInst)

	// A failure keeps the old certificate and backs off 5, 15, 60 minutes.
	e.prov.setMode("fail")
	e.clock.add(21 * 24 * time.Hour)
	for i, want := range []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour} {
		e.m.renewDue(ctx)
		waitIdle(t, e.harness)
		l3, _ := e.st.GetLink(ctx, l.ID)
		if l3.RenewError == "" || l3.RenewRetryAt == nil {
			t.Fatalf("try %d: %+v", i, l3)
		}
		if d := l3.RenewRetryAt.Sub(e.clock.now()) - want; d < -5*time.Second || d > 5*time.Second {
			t.Fatalf("try %d: retry in %s, want %s", i, l3.RenewRetryAt.Sub(e.clock.now()), want)
		}
		if e.cons.lastApplied().Serial != second.Serial {
			t.Fatal("certificate changed")
		}
		// Before the retry time nothing runs.
		e.rec.reset()
		e.m.renewDue(ctx)
		waitIdle(t, e.harness)
		if len(e.rec.list()) != 0 {
			t.Fatalf("retried early: %v", e.rec.list())
		}
		e.clock.add(want)
	}
	// Failing for a short while is no news; longer than 10 % of the
	// lifetime → degraded; after expiry → down.
	if lh, _ := e.m.LinkHealth(ctx, l.ID); lh.Status != sdk.StateOK {
		t.Fatalf("health %s %s", lh.Status, lh.Detail)
	}
	e.clock.add(4 * 24 * time.Hour)
	lh, _ := e.m.LinkHealth(ctx, l.ID)
	if lh.Status != sdk.StateDegraded || !strings.Contains(lh.Detail, "Продление не удалось") {
		t.Fatalf("health %s %s", lh.Status, lh.Detail)
	}
	e.clock.add(30 * 24 * time.Hour)
	lh, _ = e.m.LinkHealth(ctx, l.ID)
	if lh.Status != sdk.StateDown || !strings.Contains(lh.Detail, "истёк") {
		t.Fatalf("health %s %s", lh.Status, lh.Detail)
	}
}

func TestTLSRenewNamesChanged(t *testing.T) {
	e := newTLSEnv(t)
	ctx := context.Background()
	l := e.mustLink()
	e.cons.mu.Lock()
	e.cons.names = []string{"new.home"}
	e.cons.mu.Unlock()
	e.rec.reset()
	job, err := e.m.RenewLink(ctx, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.wait(job.ID)
	for _, line := range e.rec.list() {
		if strings.HasPrefix(line, "ca ") {
			t.Fatalf("issued with new names: %v", e.rec.list())
		}
	}
	lh, _ := e.m.LinkHealth(ctx, l.ID)
	if lh.Status != sdk.StateDegraded || !strings.Contains(lh.Detail, "Имена изменились") {
		t.Fatalf("health %s %s", lh.Status, lh.Detail)
	}
	// The reissue plan issues the new names after confirmation.
	pv, err := e.m.LinkChangePlan(ctx, l.ID, "reissue")
	if err != nil {
		t.Fatal(err)
	}
	if j := applyPlan(t, e.harness, pv, false); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if b := e.cons.lastApplied(); len(b.DNS) != 1 || b.DNS[0] != "new.home" {
		t.Fatalf("reissued %+v", b)
	}
	l2, _ := e.st.GetLink(ctx, l.ID)
	if l2.RenewError != "" || !strings.Contains(l2.Request, "new.home") {
		t.Fatalf("after reissue %+v", l2)
	}
}

// waitIdle waits until no job runs on the instances.
func waitIdle(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		h.m.mu.Lock()
		n := len(h.m.instJobs)
		h.m.mu.Unlock()
		if n == 0 {
			time.Sleep(20 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("jobs did not finish")
}
