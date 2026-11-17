package inventory_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"hestia/internal/inventory"
	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/sshx"
	"hestia/internal/sshx/sshxtest"
	"hestia/internal/store"
)

const apiSecret = "aaaa-bbbb-cccc-dddd-secret-value"

var fixtureDir = filepath.Join("..", "proxmox", "testdata", "real-pve9-api")

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakePVE serves the real-cluster fixtures over TLS like the PVE API: bodies
// are wrapped in {"data": …}; the token header is checked.
type fakePVE struct {
	t    *testing.T
	port int
	fp   string

	mu       sync.Mutex
	calls    map[string]int
	inflight int32
	maxIn    int32
	delay    time.Duration

	forbidAgent bool           // agent calls answer 403
	hangVMID    int            // this VM's agent call never answers in time
	failAll     bool           // every request answers 500 (cluster unreachable)
	agentOK     map[int]string // vmid → fixture
	lxcOK       map[int]string // vmid → fixture
	block       chan struct{}  // if set, /cluster/resources waits for it
}

var (
	reNodeStatus  = regexp.MustCompile(`^/api2/json/nodes/([^/]+)/status$`)
	reNodeStorage = regexp.MustCompile(`^/api2/json/nodes/([^/]+)/storage$`)
	reLXC         = regexp.MustCompile(`^/api2/json/nodes/([^/]+)/lxc/(\d+)/interfaces$`)
	reAgent       = regexp.MustCompile(`^/api2/json/nodes/([^/]+)/qemu/(\d+)/agent/network-get-interfaces$`)
)

func newFakePVE(t *testing.T) *fakePVE {
	f := &fakePVE{t: t, calls: map[string]int{}, agentOK: map[int]string{109: "qemu109_agent_ifaces.json", 113: "qemu113_agent_ifaces.json"},
		lxcOK: map[int]string{110: "lxc_ifaces_110.json"}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	f.port, _ = strconv.Atoi(p)
	fp, err := proxmox.FetchCertFP(context.Background(), h, f.port)
	if err != nil {
		t.Fatal(err)
	}
	f.fp = fp
	return f
}

func (f *fakePVE) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, v := range f.calls {
		if strings.HasPrefix(k, prefix) {
			n += v
		}
	}
	return n
}

func (f *fakePVE) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls[r.URL.Path]++
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "PVEAPIToken=hestia@pve!hestia="+apiSecret {
		http.Error(w, `{"data":null}`, http.StatusUnauthorized)
		return
	}
	if f.failAll {
		f.errBody(w, 500, "connection refused")
		return
	}
	cur := atomic.AddInt32(&f.inflight, 1)
	defer atomic.AddInt32(&f.inflight, -1)
	for {
		m := atomic.LoadInt32(&f.maxIn)
		if cur <= m || atomic.CompareAndSwapInt32(&f.maxIn, m, cur) {
			break
		}
	}
	wrap := func(name string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + string(fixture(f.t, name)) + `}`))
	}
	p := r.URL.Path
	switch {
	case p == "/api2/json/cluster/resources":
		if f.block != nil {
			<-f.block
		}
		wrap("cluster_resources.json")
	case p == "/api2/json/cluster/status":
		wrap("cluster_status.json")
	case reNodeStatus.MatchString(p):
		wrap("node_status_" + reNodeStatus.FindStringSubmatch(p)[1] + ".json")
	case reNodeStorage.MatchString(p):
		wrap("node_storage_" + reNodeStorage.FindStringSubmatch(p)[1] + ".json")
	case reLXC.MatchString(p):
		id, _ := strconv.Atoi(reLXC.FindStringSubmatch(p)[2])
		if name, ok := f.lxcOK[id]; ok {
			wrap(name)
			return
		}
		f.errBody(w, 500, "container is not reachable")
	case reAgent.MatchString(p):
		id, _ := strconv.Atoi(reAgent.FindStringSubmatch(p)[2])
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		switch {
		case f.forbidAgent:
			f.errBody(w, 403, "Permission check failed (/vms/"+strconv.Itoa(id)+", VM.GuestAgent.Audit)")
		case id == f.hangVMID:
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case f.agentOK[id] != "":
			b := fixture(f.t, f.agentOK[id])
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + string(b) + `}`))
		default:
			f.errBody(w, 500, "QEMU guest agent is not running")
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakePVE) errBody(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]any{"data": nil, "message": msg + "\n"})
	_, _ = w.Write(b)
}

type env struct {
	t   *testing.T
	st  *store.Store
	run *jobs.Runner
	svc *inventory.Service
	id  secrets.Identity

	nowMu sync.Mutex
	now   time.Time
}

func (e *env) clock() time.Time {
	e.nowMu.Lock()
	defer e.nowMu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.nowMu.Lock()
	defer e.nowMu.Unlock()
	e.now = e.now.Add(d)
}

func newEnv(t *testing.T, mutate func(*inventory.Service)) *env {
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
	id, err := sec.EnsureIdentity(context.Background(), "ctl")
	if err != nil {
		t.Fatal(err)
	}
	run, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.Shutdown(); _ = st.Close() })
	e := &env{t: t, st: st, run: run, id: id, now: time.Now()}
	e.svc = &inventory.Service{Store: st, Secrets: sec, Runner: run, Identity: id, Now: e.clock}
	if mutate != nil {
		mutate(e.svc)
	}
	e.svc.Init()
	return e
}

// proxmoxTarget stores a Proxmox target whose API is the fake.
func (e *env) proxmoxTarget(f *fakePVE, secret string) store.Target {
	e.t.Helper()
	ref, err := e.svc.Secrets.Put(context.Background(), secrets.PurposeAPIToken, []byte(secret))
	if err != nil {
		e.t.Fatal(err)
	}
	tg := store.Target{Kind: store.KindProxmox, Name: "home", Host: "127.0.0.1", Port: 22, SSHUser: "root", HostKeyFP: "SHA256:x",
		APICertFP: f.fp, Cluster: "home", TokenID: proxmox.TokenID, TokenSecretRef: ref, Nodes: []store.Node{}}
	if err := e.st.CreateTarget(context.Background(), &tg); err != nil {
		e.t.Fatal(err)
	}
	e.svc.APIPort = f.port
	return tg
}

func (e *env) waitJob(j store.Job) store.Job {
	e.t.Helper()
	e.run.Wait()
	got, err := e.st.GetJob(context.Background(), j.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) refresh(id int64) (inventory.Entry, store.Job) {
	e.t.Helper()
	job, err := e.svc.Refresh(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	job = e.waitJob(job)
	ent, err := e.svc.Get(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return ent, job
}

func guestByID(s *inventory.Snapshot, vmid int) inventory.Guest {
	for _, g := range s.Guests {
		if g.VMID == vmid {
			return g
		}
	}
	return inventory.Guest{VMID: -1}
}

func TestCollectProxmoxFromRealFixtures(t *testing.T) {
	f := newFakePVE(t)
	e := newEnv(t, nil)
	tg := e.proxmoxTarget(f, apiSecret)

	ent, job := e.refresh(tg.ID)
	if job.Status != store.JobDone {
		t.Fatalf("job %s: %s", job.Status, job.Error)
	}
	s := ent.Snapshot
	if s == nil || ent.Error != "" || ent.CollectedAt == nil || ent.AgeSeconds == nil {
		t.Fatalf("entry: %+v", ent)
	}
	if s.Kind != "proxmox" || s.Cluster != "home" || !s.Clustered || !s.Quorate || s.Version != "9.2.10" {
		t.Fatalf("cluster: %+v", s)
	}
	if len(s.Nodes) != 3 || s.Nodes[0].Name != "pve" || s.Nodes[1].Name != "pve1" || s.Nodes[2].Name != "pve2" {
		t.Fatalf("nodes: %+v", s.Nodes)
	}
	n := s.Nodes[0]
	if n.IP != "10.10.10.10" || !n.Online || n.CPUModel != "Intel(R) Xeon(R) CPU E5-2420 0 @ 1.90GHz" ||
		n.Sockets != 2 || n.Cores != 12 || n.Threads != 24 || n.Load1 != 2.92 || n.Load15 != 4.01 ||
		n.MemTotal != 67392901120 || n.MemUsed != 33633132544 || n.SwapTotal != 8589930496 ||
		n.RootFSTotal != 100861726720 || n.Uptime != 3109344 || n.Kernel != "7.0.14-11-pve" || n.PVEVersion != "9.2.10" {
		t.Fatalf("node pve: %+v", n)
	}

	qemu, lxc, running := 0, 0, 0
	for _, g := range s.Guests {
		switch g.Type {
		case "qemu":
			qemu++
		case "lxc":
			lxc++
		}
		if g.Status == "running" {
			running++
		}
	}
	if qemu != 34 || lxc != 6 || running != 29 {
		t.Fatalf("guests: qemu %d lxc %d running %d", qemu, lxc, running)
	}

	// Shared storages once per cluster, local ones once per node.
	byName := map[string][]inventory.Storage{}
	for _, st := range s.Storages {
		byName[st.Name] = append(byName[st.Name], st)
	}
	if len(s.Storages) != 8 || len(byName["pbs01"]) != 1 || len(byName["pbs02"]) != 1 || len(byName["local"]) != 3 || len(byName["local-lvm"]) != 3 {
		t.Fatalf("storages: %+v", s.Storages)
	}
	pbs := byName["pbs01"][0]
	if !pbs.Shared || pbs.Type != "pbs" || !pbs.Active || len(pbs.Nodes) != 3 || pbs.Total != 421607403520 ||
		len(pbs.Content) != 1 || pbs.Content[0] != "backup" {
		t.Fatalf("pbs01: %+v", pbs)
	}
	if l := byName["local"][0]; l.Shared || len(l.Nodes) != 1 || len(l.Content) != 3 {
		t.Fatalf("local: %+v", l)
	}

	// Addresses: LXC via interfaces, QEMU via the guest agent (virtual bridges
	// and link-local addresses dropped).
	if g := guestByID(s, 110); g.IPSource != "lxc" || strings.Join(g.IPs, ",") != "10.10.10.118" || g.Name != "netronome" || g.Node != "pve2" ||
		len(g.Tags) != 4 || g.CPUs != 2 || g.MemTotal != 536870912 {
		t.Fatalf("lxc 110: %+v", g)
	}
	if g := guestByID(s, 109); g.IPSource != "agent" || strings.Join(g.IPs, ",") != "10.10.10.127,10.8.1.3" {
		t.Fatalf("qemu 109: %+v", g)
	}
	// A running VM without the agent: not an inventory error.
	var noAgent inventory.Guest
	for _, g := range s.Guests {
		if g.Type == "qemu" && g.Status == "running" && g.VMID != 109 && g.VMID != 113 {
			noAgent = g
			break
		}
	}
	if noAgent.IPSource != "none" || !strings.Contains(noAgent.IPError, "guest agent") || len(noAgent.IPs) != 0 {
		t.Fatalf("no agent: %+v", noAgent)
	}
	// Stopped guests are not asked.
	if g := guestByID(s, 101); g.Status != "stopped" || g.IPSource != "none" || g.IPError == "" {
		t.Fatalf("stopped: %+v", g)
	}
	if g := guestByID(s, 135); !g.Template || g.IPSource != "none" {
		t.Fatalf("template: %+v", g)
	}
	if f.count("/api2/json/nodes/pve2/qemu/101") != 0 || f.count("/api2/json/nodes/pve2/qemu/135") != 0 {
		t.Fatal("stopped guest or template was queried")
	}
	if s.NeedsAgentPriv {
		t.Fatal("needs_guest_agent_audit without any 403")
	}
	// The secret never reaches the job log.
	for _, l := range job.Log {
		if strings.Contains(l.Line, apiSecret) {
			t.Fatal("token in job log")
		}
	}
}

func TestAgentForbiddenSetsPrivilegeFlag(t *testing.T) {
	f := newFakePVE(t)
	f.forbidAgent = true
	e := newEnv(t, nil)
	tg := e.proxmoxTarget(f, apiSecret)
	ent, job := e.refresh(tg.ID)
	if job.Status != store.JobDone || ent.Snapshot == nil {
		t.Fatalf("job %s %s", job.Status, job.Error)
	}
	if !ent.Snapshot.NeedsAgentPriv {
		t.Fatal("403 on the agent must raise needs_guest_agent_audit")
	}
	if g := guestByID(ent.Snapshot, 109); g.IPSource != "none" || !strings.Contains(g.IPError, proxmox.GuestAgentPriv) {
		t.Fatalf("%+v", g)
	}
	// LXC addresses do not need the privilege.
	if g := guestByID(ent.Snapshot, 110); g.IPSource != "lxc" || len(g.IPs) != 1 {
		t.Fatalf("%+v", g)
	}
}

func TestOneGuestTimeoutDoesNotFailCollection(t *testing.T) {
	f := newFakePVE(t)
	f.hangVMID = 109
	e := newEnv(t, func(s *inventory.Service) { s.ReqTimeout = 300 * time.Millisecond })
	tg := e.proxmoxTarget(f, apiSecret)
	start := time.Now()
	ent, job := e.refresh(tg.ID)
	if job.Status != store.JobDone || ent.Snapshot == nil {
		t.Fatalf("job %s %s", job.Status, job.Error)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("a hanging guest stalled the collection")
	}
	if g := guestByID(ent.Snapshot, 109); g.IPSource != "none" || g.IPError == "" {
		t.Fatalf("hanging guest: %+v", g)
	}
	if g := guestByID(ent.Snapshot, 113); g.IPSource != "agent" || len(g.IPs) == 0 {
		t.Fatalf("other guest: %+v", g)
	}
}

func TestIPLookupsAreBoundedTo8(t *testing.T) {
	f := newFakePVE(t)
	f.delay = 40 * time.Millisecond
	e := newEnv(t, nil)
	tg := e.proxmoxTarget(f, apiSecret)
	if _, job := e.refresh(tg.ID); job.Status != store.JobDone {
		t.Fatal(job.Error)
	}
	if m := atomic.LoadInt32(&f.maxIn); m > inventory.MaxParallelIPLookups || m < 2 {
		t.Fatalf("max concurrent requests = %d, want 2..%d", m, inventory.MaxParallelIPLookups)
	}
}

func TestFailedCollectionKeepsPreviousSnapshot(t *testing.T) {
	f := newFakePVE(t)
	e := newEnv(t, nil)
	tg := e.proxmoxTarget(f, apiSecret)
	if ent, _ := e.refresh(tg.ID); ent.Snapshot == nil {
		t.Fatal("first collection failed")
	}
	f.failAll = true
	ent, job := e.refresh(tg.ID)
	if job.Status != store.JobFailed || ent.Error == "" {
		t.Fatalf("job %s, entry error %q", job.Status, ent.Error)
	}
	if ent.Snapshot == nil || len(ent.Snapshot.Guests) != 40 || ent.CollectedAt == nil {
		t.Fatal("previous snapshot must stay")
	}
	f.failAll = false
	if ent, job = e.refresh(tg.ID); job.Status != store.JobDone || ent.Error != "" {
		t.Fatalf("recovery: %s %q", job.Status, ent.Error)
	}
}

func TestWrongTokenAndPinnedCert(t *testing.T) {
	f := newFakePVE(t)
	e := newEnv(t, nil)
	tg := e.proxmoxTarget(f, "wrong-"+apiSecret)
	ent, job := e.refresh(tg.ID)
	if job.Status != store.JobFailed || !strings.Contains(ent.Error, "отклонил токен") {
		t.Fatalf("%s %q", job.Status, ent.Error)
	}
	if strings.Contains(ent.Error, "wrong-"+apiSecret) || strings.Contains(job.Error, "wrong-") {
		t.Fatal("token leaked into the error")
	}

	// A changed certificate is refused.
	f2 := newFakePVE(t)
	e2 := newEnv(t, nil)
	tg2 := e2.proxmoxTarget(f2, apiSecret)
	e2.svc.NewAPI = func(cfg proxmox.ClientConfig) inventory.API {
		cfg.PinFP = "AA:BB"
		return proxmox.NewClient(cfg)
	}
	ent, job = e2.refresh(tg2.ID)
	if job.Status != store.JobFailed || !strings.Contains(ent.Error, "отпечаток") {
		t.Fatalf("%s %q", job.Status, ent.Error)
	}
}

// ---- scheduler ----

// countingAPI is a minimal fake API (no network) that can be held up.
type countingAPI struct {
	resources int32
	gate      chan struct{}
}

func (a *countingAPI) ClusterResources(ctx context.Context) ([]proxmox.Resource, error) {
	atomic.AddInt32(&a.resources, 1)
	if a.gate != nil {
		select {
		case <-a.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []proxmox.Resource{{Type: "node", Node: "n1", Status: "online"}}, nil
}
func (a *countingAPI) ClusterStatus(context.Context) ([]proxmox.ClusterEntry, error) { return nil, nil }
func (a *countingAPI) NodeStatus(context.Context, string) (proxmox.NodeStatus, error) {
	return proxmox.NodeStatus{}, nil
}
func (a *countingAPI) NodeStorage(context.Context, string) ([]proxmox.NodeStorageEntry, error) {
	return nil, nil
}
func (a *countingAPI) LXCInterfaces(context.Context, string, int) ([]proxmox.Iface, error) {
	return nil, nil
}
func (a *countingAPI) AgentInterfaces(context.Context, string, int) ([]proxmox.Iface, error) {
	return nil, nil
}

func fakeAPIEnv(t *testing.T, api *countingAPI) (*env, store.Target) {
	e := newEnv(t, func(s *inventory.Service) {
		s.NewAPI = func(proxmox.ClientConfig) inventory.API { return api }
	})
	ref, _ := e.svc.Secrets.Put(context.Background(), secrets.PurposeAPIToken, []byte("t"))
	tg := store.Target{Kind: store.KindProxmox, Name: "p", Host: "h", Port: 22, SSHUser: "root", HostKeyFP: "x", APICertFP: "AA",
		TokenID: proxmox.TokenID, TokenSecretRef: ref}
	if err := e.st.CreateTarget(context.Background(), &tg); err != nil {
		t.Fatal(err)
	}
	return e, tg
}

func TestTickDoesNothingWithoutSubscribers(t *testing.T) {
	api := &countingAPI{}
	e, _ := fakeAPIEnv(t, api)
	e.svc.Tick(context.Background())
	e.run.Wait()
	if n := atomic.LoadInt32(&api.resources); n != 0 {
		t.Fatalf("collected %d times with nobody watching", n)
	}
	ch, cancel := e.svc.Subscribe()
	defer cancel()
	e.svc.Tick(context.Background())
	e.run.Wait()
	if n := atomic.LoadInt32(&api.resources); n != 1 {
		t.Fatalf("collected %d times, want 1", n)
	}
	// Events: "collecting" then the finished entry.
	var last inventory.Entry
	for len(ch) > 0 {
		last = <-ch
	}
	if last.Snapshot == nil || last.Collecting {
		t.Fatalf("last event: %+v", last)
	}
	// A fresh snapshot is not collected again right away.
	e.svc.Tick(context.Background())
	e.run.Wait()
	if n := atomic.LoadInt32(&api.resources); n != 1 {
		t.Fatalf("fresh snapshot refreshed again: %d", n)
	}
	// Once it is old enough it is.
	e.advance(e.svc.Interval)
	e.svc.Tick(context.Background())
	e.run.Wait()
	if n := atomic.LoadInt32(&api.resources); n != 2 {
		t.Fatalf("stale snapshot not refreshed: %d", n)
	}
	cancel()
	cancel() // idempotent
	if e.svc.Subscribers() != 0 {
		t.Fatal("subscriber not removed")
	}
}

func TestOneCollectionPerTarget(t *testing.T) {
	api := &countingAPI{gate: make(chan struct{})}
	e, tg := fakeAPIEnv(t, api)
	j1, err := e.svc.Refresh(context.Background(), tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	j2, err := e.svc.Refresh(context.Background(), tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j1.ID != j2.ID {
		t.Fatalf("second refresh started job %s while %s runs", j2.ID, j1.ID)
	}
	if ent, _ := e.svc.Get(context.Background(), tg.ID); !ent.Collecting {
		t.Fatal("entry must report collecting")
	}
	close(api.gate)
	e.waitJob(j1)
	if n := atomic.LoadInt32(&api.resources); n != 1 {
		t.Fatalf("collections: %d", n)
	}
	// After the end a new one may start.
	api.gate = nil
	j3, _ := e.svc.Refresh(context.Background(), tg.ID)
	if j3.ID == j1.ID {
		t.Fatal("finished job reused")
	}
	e.waitJob(j3)
	if _, err := e.svc.Refresh(context.Background(), 999); err == nil {
		t.Fatal("unknown target must fail")
	}
}

func TestStartLoopRefreshesOnlyWhileWatched(t *testing.T) {
	api := &countingAPI{}
	e, _ := fakeAPIEnv(t, api)
	e.svc.Interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	e.svc.Start(ctx)
	defer func() { cancel(); e.svc.Wait() }()

	time.Sleep(120 * time.Millisecond)
	if n := atomic.LoadInt32(&api.resources); n != 0 {
		t.Fatalf("polled %d times without subscribers", n)
	}
	_, unsub := e.svc.Subscribe()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&api.resources) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&api.resources) == 0 {
		t.Fatal("no refresh after subscribing")
	}
	unsub()
	e.run.Wait()
	n := atomic.LoadInt32(&api.resources)
	time.Sleep(150 * time.Millisecond)
	e.run.Wait()
	if m := atomic.LoadInt32(&api.resources); m != n {
		t.Fatalf("kept polling after the last subscriber left: %d → %d", n, m)
	}
}

// ---- standalone SSH server ----

func TestCollectSSHServer(t *testing.T) {
	var cmds []string
	var mu sync.Mutex
	srv := sshxtest.New(t)
	srv.Handler = func(user, cmd string, stdin []byte) (string, string, int) {
		mu.Lock()
		cmds = append(cmds, cmd)
		mu.Unlock()
		switch {
		case cmd == "uname -srm":
			return "Linux 6.1.0-18-amd64 x86_64\n", "", 0
		case cmd == "hostname":
			return "nas\n", "", 0
		case cmd == "cat /etc/os-release":
			return "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", "", 0
		case cmd == "nproc":
			return "4\n", "", 0
		case strings.HasPrefix(cmd, "free -b"):
			return "              total        used        free      shared  buff/cache   available\nMem:     8000000000  2000000000  4000000000     1000000  2000000000  6000000000\n", "", 0
		case strings.HasPrefix(cmd, "df -B1"):
			return "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 100000000000 40000000000 60000000000 40% /\n/dev/sdb1 500000000000 1000 1 1% /data\n", "", 0
		case cmd == "command -v docker":
			return "/usr/bin/docker\n", "", 0
		case cmd == "id -u":
			return "0\n", "", 0
		case strings.HasPrefix(cmd, "grep -m1 'model name'"):
			return "model name\t: Intel(R) N100\n", "", 0
		case cmd == "cat /proc/loadavg":
			return "0.80 0.40 0.20 1/300 1234\n", "", 0
		case cmd == "cat /proc/uptime":
			return "86400.55 1000.00\n", "", 0
		}
		return "", "unexpected command: " + cmd, 127
	}
	srv.KeyAuth = func(user string, key ssh.PublicKey) bool { return true }
	hostFP := srv.HostKeyFP()

	e := newEnv(t, func(s *inventory.Service) {
		s.Dial = func(ctx context.Context, cfg sshx.Config) (*sshx.Client, error) {
			if cfg.Host != "127.0.0.1" {
				t.Errorf("dial to %q", cfg.Host)
			}
			return sshx.Dial(ctx, cfg)
		}
	})
	tg := store.Target{Kind: store.KindSSH, Name: "nas", Host: srv.Host, Port: srv.Port, SSHUser: "root", HostKeyFP: hostFP}
	if err := e.st.CreateTarget(context.Background(), &tg); err != nil {
		t.Fatal(err)
	}
	ent, job := e.refresh(tg.ID)
	if job.Status != store.JobDone || ent.Snapshot == nil {
		t.Fatalf("%s %s", job.Status, job.Error)
	}
	s := ent.Snapshot
	if s.Kind != "ssh" || len(s.Nodes) != 1 || len(s.Guests) != 0 || len(s.Storages) != 0 {
		t.Fatalf("%+v", s)
	}
	n := s.Nodes[0]
	if n.Name != "nas" || n.IP != srv.Host || n.OS != "Debian GNU/Linux 12 (bookworm)" || n.Kernel != "Linux 6.1.0-18-amd64" ||
		n.Threads != 4 || n.CPUModel != "Intel(R) N100" || n.MemTotal != 8000000000 || n.MemUsed != 2000000000 ||
		n.RootFSTotal != 100000000000 || n.RootFSUsed != 40000000000 || n.Load1 != 0.8 || n.Uptime != 86400 || !n.Docker {
		t.Fatalf("%+v", n)
	}

	// A changed host key is refused and the snapshot stays.
	e.st.DB().Exec(`UPDATE targets SET host_key_fp = 'SHA256:wrong' WHERE id = ?`, tg.ID)
	ent, job = e.refresh(tg.ID)
	if job.Status != store.JobFailed || ent.Error == "" || ent.Snapshot == nil {
		t.Fatalf("changed host key: %s %q", job.Status, ent.Error)
	}
}
