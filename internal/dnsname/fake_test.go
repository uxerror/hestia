package dnsname

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hestia/internal/integrations/adguard"
	"hestia/internal/jobs"
	"hestia/internal/netscan"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/store"
)

const (
	agUser     = "admin"
	agPassword = "s3cret-AdGuard-pass"
	instanceID = "inst-test-1"
)

// fakeAG is an AdGuard Home v0.107 API: Basic auth, status, rewrites.
type fakeAG struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	user     string
	pass     string
	list     []adguard.Rewrite
	rewrites bool // rewrite/settings enabled
	dnsPort  int
	methods  []string // every authorized request: "METHOD path"
	authed   int      // requests that carried credentials
	failAdd  bool
}

func newFakeAG(t *testing.T, tlsOn bool) *fakeAG {
	f := &fakeAG{t: t, user: agUser, pass: agPassword, rewrites: true}
	h := http.HandlerFunc(f.serve)
	if tlsOn {
		f.srv = httptest.NewTLSServer(h)
	} else {
		f.srv = httptest.NewServer(h)
	}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAG) pin() string { return proxmox.CertFingerprint(f.srv.Certificate().Raw) }

func (f *fakeAG) records() []adguard.Rewrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]adguard.Rewrite(nil), f.list...)
}

func (f *fakeAG) set(domain, answer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = append(f.list, adguard.Rewrite{Domain: domain, Answer: answer})
}

func (f *fakeAG) lookup(domain string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.list {
		if strings.EqualFold(r.Domain, domain) && (r.Enabled == nil || *r.Enabled) {
			out = append(out, r.Answer)
		}
	}
	return out
}

func (f *fakeAG) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, p, ok := r.BasicAuth()
	if ok {
		f.authed++
	}
	if !ok || u != f.user || p != f.pass {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	f.methods = append(f.methods, r.Method+" "+r.URL.Path)
	var body struct {
		Domain, Answer string
		Enabled        *bool
		Target, Update *adguard.Rewrite
	}
	if r.Body != nil && r.Method != http.MethodGet {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	out := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.Method + " " + r.URL.Path {
	case "GET /control/status":
		out(map[string]any{"version": "v0.107.79", "running": true, "dns_port": f.dnsPort, "dns_addresses": []string{"127.0.0.1"}})
	case "GET /control/rewrite/settings":
		out(map[string]any{"enabled": f.rewrites})
	case "GET /control/rewrite/list":
		if f.list == nil {
			f.list = []adguard.Rewrite{}
		}
		out(f.list)
	case "POST /control/rewrite/add":
		if f.failAdd {
			http.Error(w, "boom", 500)
			return
		}
		f.list = append(f.list, adguard.Rewrite{Domain: body.Domain, Answer: body.Answer, Enabled: body.Enabled})
	case "POST /control/rewrite/delete":
		for i, x := range f.list {
			if x.Domain == body.Domain && x.Answer == body.Answer {
				f.list = append(f.list[:i], f.list[i+1:]...)
				return
			}
		}
		http.Error(w, "not found", 400)
	case "PUT /control/rewrite/update":
		for i, x := range f.list {
			if body.Target != nil && x.Domain == body.Target.Domain && x.Answer == body.Target.Answer {
				t := true
				f.list[i] = adguard.Rewrite{Domain: body.Update.Domain, Answer: body.Update.Answer, Enabled: &t}
				return
			}
		}
		http.Error(w, "not found", 400)
	default:
		http.NotFound(w, r)
	}
}

// fakeDNS answers A queries from the rewrites of a fakeAG, like AdGuard does.
type fakeDNS struct {
	conn net.PacketConn
	ag   *fakeAG

	mu       sync.Mutex
	override string // answer this instead (empty: the rewrites)
}

func newFakeDNS(t *testing.T, ag *fakeAG) *fakeDNS {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDNS{conn: conn, ag: ag}
	ag.dnsPort = conn.LocalAddr().(*net.UDPAddr).Port
	t.Cleanup(func() { _ = conn.Close() })
	go d.loop()
	return d
}

func (d *fakeDNS) setOverride(ip string) {
	d.mu.Lock()
	d.override = ip
	d.mu.Unlock()
}

func (d *fakeDNS) loop() {
	buf := make([]byte, 512)
	for {
		n, addr, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		_, _ = d.conn.WriteTo(d.reply(q), addr)
	}
}

func (d *fakeDNS) reply(q []byte) []byte {
	// Question name.
	off := 12
	var labels []string
	for q[off] != 0 {
		l := int(q[off])
		labels = append(labels, string(q[off+1:off+1+l]))
		off += 1 + l
	}
	qend := off + 1 + 4
	name := strings.Join(labels, ".")
	d.mu.Lock()
	ov := d.override
	d.mu.Unlock()
	answers := d.ag.lookup(name)
	if ov != "" {
		answers = []string{ov}
	}
	r := append([]byte(nil), q[:qend]...)
	r[2], r[3] = 0x81, 0x80
	if len(answers) == 0 {
		r[3] = 0x83 // NXDOMAIN
		return r
	}
	binary.BigEndian.PutUint16(r[6:], uint16(len(answers)))
	for _, a := range answers {
		ip := net.ParseIP(a).To4()
		r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		r = append(r, ip...)
	}
	return r
}

// fakeHosts is the last scan.
type fakeHosts struct{ hosts []netscan.Host }

func (f *fakeHosts) View(context.Context) (netscan.View, error) {
	return netscan.View{Hosts: f.hosts}, nil
}

type rig struct {
	t       *testing.T
	dir     string
	st      *store.Store
	sec     *secrets.Service
	runner  *jobs.Runner
	svc     *Service
	ag      *fakeAG
	dns     *fakeDNS
	health  *httptest.Server
	hostsrc *fakeHosts

	healthMu   sync.Mutex
	healthID   string
	healthHost string
}

// newRig builds a Service against a fake AdGuard (plain HTTP unless tlsOn),
// a fake DNS server on 127.0.0.1 and a fake "controller" for the health check.
func newRig(t *testing.T, tlsOn bool) *rig {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.Open(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, dir: dir, st: st, sec: sec, runner: runner, healthID: instanceID, hostsrc: &fakeHosts{}}
	r.ag = newFakeAG(t, tlsOn)
	r.dns = newFakeDNS(t, r.ag)
	r.health = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.healthMu.Lock()
		defer r.healthMu.Unlock()
		r.healthHost = q.Host
		_, _ = w.Write([]byte(`{"status":"ok","instance_id":"` + r.healthID + `"}`))
	}))
	hp, _ := strconv.Atoi(mustPort(r.health.URL))
	r.svc = (&Service{Store: st, Secrets: sec, Runner: runner, Hosts: r.hostsrc, InstanceID: instanceID,
		HealthPort: hp, DNSAttempts: 2, DNSPause: time.Millisecond}).Init()
	t.Cleanup(func() { r.health.Close(); runner.Shutdown(); _ = st.Close() })
	return r
}

func mustPort(raw string) string {
	u, _ := url.Parse(raw)
	return u.Port()
}

// connect saves the connection with the right credentials.
func (r *rig) connect() *ConnectResult {
	r.t.Helper()
	req := ConnectRequest{URL: r.ag.srv.URL, Username: agUser, Password: agPassword}
	if strings.HasPrefix(r.ag.srv.URL, "https") {
		req.TLSPin = r.ag.pin()
	}
	res, err := r.svc.Connect(context.Background(), req, false)
	if err != nil {
		r.t.Fatalf("connect: %v", err)
	}
	return res
}

// apply plans and applies, waits for the job and returns it.
func (r *rig) apply(action, domain string) (store.Job, error) {
	r.t.Helper()
	p, err := r.svc.MakePlan(context.Background(), action, domain)
	if err != nil {
		r.t.Fatalf("plan: %v", err)
	}
	return r.applyPlan(p)
}

func (r *rig) applyPlan(p *Plan) (store.Job, error) {
	r.t.Helper()
	j, err := r.svc.Apply(context.Background(), p.PlanID, p.Hash)
	if err != nil {
		return store.Job{}, err
	}
	r.runner.Wait()
	got, err := r.st.GetJob(context.Background(), j.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got, nil
}
