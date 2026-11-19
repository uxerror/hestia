package netscan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/store"
)

type fakeInv struct {
	mu      sync.Mutex
	entries []inventory.Entry
}

func (f *fakeInv) List(context.Context) ([]inventory.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]inventory.Entry(nil), f.entries...), nil
}

type menv struct {
	t   *testing.T
	st  *store.Store
	run *jobs.Runner
	inv *fakeInv
	fn  *fakeNet
	m   *Manager
}

func newMEnv(t *testing.T) *menv {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run.Shutdown(); _ = st.Close() })
	e := &menv{t: t, st: st, run: run, inv: &fakeInv{}, fn: newFakeNet()}
	sc := &Scanner{Dialer: e.fn, ConnTimeout: 30 * time.Millisecond, ProbeTimeout: 800 * time.Millisecond, BannerTimeout: 100 * time.Millisecond,
		ARP: fakeARP{}, Resolver: fakeResolver{}}
	e.m = (&Manager{Store: st, Runner: run, Inventory: e.inv, Scanner: sc, Version: "v0.0.0-test"}).Init()
	return e
}

func (e *menv) target(kind, name, host string) store.Target {
	e.t.Helper()
	tg := store.Target{Kind: kind, Name: name, Host: host, Port: 22, SSHUser: "root", HostKeyFP: "SHA256:x"}
	if err := e.st.CreateTarget(context.Background(), &tg); err != nil {
		e.t.Fatal(err)
	}
	return tg
}

func (e *menv) setSnapshot(tg store.Target, snap inventory.Snapshot) {
	e.inv.mu.Lock()
	defer e.inv.mu.Unlock()
	for i, en := range e.inv.entries {
		if en.TargetID == tg.ID {
			e.inv.entries[i].Snapshot = &snap
			return
		}
	}
	e.inv.entries = append(e.inv.entries, inventory.Entry{TargetID: tg.ID, Snapshot: &snap})
}

func (e *menv) scan() store.Job {
	e.t.Helper()
	job, err := e.m.Scan(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	e.run.Wait()
	got, err := e.st.GetJob(context.Background(), job.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *menv) view() View {
	e.t.Helper()
	v, err := e.m.View(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func hostOf(v View, ip string) (Host, bool) {
	for _, h := range v.Hosts {
		if h.IP == ip {
			return h, true
		}
	}
	return Host{}, false
}

// ---- subnets and settings ----

func TestSubnetsFromBridgesFixtureManualAndExclusions(t *testing.T) {
	e := newMEnv(t)
	pve := e.target(store.KindProxmox, "home", "10.10.10.10")
	nas := e.target(store.KindSSH, "nas", "10.10.20.5")

	// The bridges of a real node: only vmbr0 has an address.
	raw, err := os.ReadFile("../proxmox/testdata/real-pve9-selfinstall/network-pve1.json")
	if err != nil {
		t.Fatal(err)
	}
	var ifs []proxmox.NetIface
	if err := json.Unmarshal(raw, &ifs); err != nil {
		t.Fatal(err)
	}
	var subs []inventory.Subnet
	for _, n := range ifs {
		if (n.Type == "bridge" || n.Type == "OVSBridge") && n.CIDR != "" {
			subs = append(subs, inventory.Subnet{Node: "pve1", Iface: n.Iface, CIDR: n.CIDR, Gateway: n.Gateway})
		}
	}
	e.setSnapshot(pve, inventory.Snapshot{Subnets: append(subs, inventory.Subnet{Node: "pve2", Iface: "vmbr0", CIDR: "10.10.10.51/24"}, inventory.Subnet{Node: "pve1", Iface: "vmbr9", CIDR: "10.20.0.1/16"})})
	e.setSnapshot(nas, inventory.Snapshot{Subnets: []inventory.Subnet{{Node: "nas", Iface: "eth0", CIDR: "10.10.20.5/24"}}})

	ctx := context.Background()
	infos, ps := e.m.Subnets(ctx)
	if len(ps) != 2 || ps[0].String() != "10.10.10.0/24" || ps[1].String() != "10.10.20.0/24" {
		t.Fatalf("scanned: %v", ps)
	}
	if len(infos) != 3 {
		t.Fatalf("infos: %+v", infos)
	}
	if infos[0].Gateway != "10.10.10.1" {
		t.Fatalf("gateway from the bridge: %+v", infos[0])
	}
	if infos[0].CIDR != "10.10.10.0/24" || infos[0].Source != "proxmox" || !strings.Contains(infos[0].Label, "pve1 · vmbr0") || !strings.Contains(infos[0].Label, "pve2 · vmbr0") {
		t.Fatalf("merged: %+v", infos[0])
	}
	if infos[1].Source != "ssh" || infos[1].CIDR != "10.10.20.0/24" {
		t.Fatalf("ssh: %+v", infos[1])
	}
	if infos[2].Error == "" || !strings.Contains(infos[2].Error, "/22") {
		t.Fatalf("a /16 bridge is listed but not scanned: %+v", infos[2])
	}

	// Manual subnets, exclusions; refused ones.
	extra, excl, err := e.m.SetSettings(ctx, []string{"10.10.30.7/24", "10.10.30.0/24", ""}, []string{"10.10.10.1", "10.10.10.1"})
	if err != nil || len(extra) != 1 || extra[0] != "10.10.30.0/24" || len(excl) != 1 {
		t.Fatalf("%v %v %v", extra, excl, err)
	}
	if _, ps := e.m.Subnets(ctx); len(ps) != 3 {
		t.Fatalf("with manual: %v", ps)
	}
	for _, c := range []struct{ extra, excl []string }{
		{[]string{"10.10.0.0/16"}, nil}, {[]string{"nope"}, nil}, {[]string{"127.0.0.0/30"}, nil}, {nil, []string{"x.y"}},
	} {
		_, _, err := e.m.SetSettings(ctx, c.extra, c.excl)
		var ie *InputError
		if !errors.As(err, &ie) {
			t.Errorf("%v %v: %v", c.extra, c.excl, err)
		}
	}
	// A refused update changes nothing.
	if x, ex := e.m.Settings(ctx); len(x) != 1 || len(ex) != 1 {
		t.Fatalf("settings changed: %v %v", x, ex)
	}
	var many []string
	for i := 0; i < MaxManualSubnets+1; i++ {
		many = append(many, "10.20."+itoa(i)+".0/24")
	}
	if _, _, err := e.m.SetSettings(ctx, many, nil); err == nil {
		t.Fatal("too many subnets")
	}
	// Default: no exclusions, 6 hours.
	e2 := newMEnv(t)
	if x, ex := e2.m.Settings(ctx); len(x) != 0 || len(ex) != 0 || e2.m.IntervalHours(ctx) != 6 {
		t.Fatal("defaults")
	}
}

// ---- a scan end to end ----

func plainServer(t *testing.T, title, server string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if server != "" {
			w.Header().Set("Server", server)
		}
		_, _ = w.Write([]byte("<html><head><title>" + title + "</title></head></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestScanJobStoresHostsLinksAndKeepsVanished(t *testing.T) {
	e := newMEnv(t)
	pve := e.target(store.KindProxmox, "home", "10.10.10.10")
	e.setSnapshot(pve, inventory.Snapshot{
		Subnets: []inventory.Subnet{{Node: "pve1", Iface: "vmbr0", CIDR: "10.10.10.10/28"}},
		Nodes:   []inventory.Node{{Name: "pve1", IP: "10.10.10.10", Online: true}},
		Guests: []inventory.Guest{
			{VMID: 100, Type: "lxc", Name: "web", Node: "pve1", Status: "running", IPs: []string{"10.10.10.5"}, MACs: []string{"bc:24:11:00:00:05"}},
			{VMID: 101, Type: "qemu", Name: "quiet", Node: "pve1", Status: "running", IPs: []string{"10.10.10.9"}},
			{VMID: 102, Type: "qemu", Name: "off", Node: "pve1", Status: "stopped", IPs: []string{"10.10.10.8"}},
		},
	})
	e.fn.route("10.10.10.5", 22, listenBanner(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"))
	e.fn.route("10.10.10.5", 80, plainServer(t, "Gotify", "nginx"))
	e.fn.route("10.10.10.10", 8006, plainServer(t, "pve - Proxmox Virtual Environment", "pve-api-daemon/3.0"))
	e.m.Scanner.Resolver = fakeResolver{"10.10.10.5": {"web.lan."}}
	e.m.Scanner.ARP = fakeARP{table: mapARP("10.10.10.10", "bc:24:11:11:22:33"), local: true}

	// Before any scan: no hosts, and the inventory guests are not claimed silent.
	if v := e.view(); len(v.Hosts) != 0 || v.LastScan != nil || v.NextScanAt == nil || v.Scanning {
		t.Fatalf("before: %+v", v)
	}

	job := e.scan()
	if job.Status != store.JobDone || job.Kind != JobKind || job.Title != "Сканирование сети" {
		t.Fatalf("job: %s %s", job.Status, job.Error)
	}
	var steps []string
	for _, s := range job.Steps {
		steps = append(steps, s.Title)
		if s.Status != store.StepDone {
			t.Errorf("step %s: %s", s.Title, s.Status)
		}
	}
	if strings.Join(steps, "|") != "Подсети|Обнаружение|Отпечатки|Сохранение" {
		t.Fatalf("steps: %v", steps)
	}
	for _, l := range job.Log { // a summary, never response bodies
		if strings.Contains(l.Line, "<html") || strings.Contains(l.Line, "Gotify") {
			t.Errorf("response data in the log: %q", l.Line)
		}
	}
	if !logHas(job, "10.10.10.0/28") || !logHas(job, "Проверено 14 из 14") {
		t.Errorf("log: %+v", job.Log)
	}

	v := e.view()
	if v.LastScan == nil || v.LastScan.FinishedAt == nil || v.LastScan.Error != "" || v.LastScan.Stats.Alive != 2 || v.LastScan.Stats.Addresses != 14 ||
		v.LastScan.Stats.Subnets != 1 || v.LastScan.Stats.Services != 3 || len(v.LastScan.Subnets) != 1 || v.NextScanAt == nil {
		t.Fatalf("last scan: %+v", v.LastScan)
	}
	web, ok := hostOf(v, "10.10.10.5")
	if !ok || !web.Alive || web.Source != SourceScan || len(web.Ports) != 2 || len(web.Services) != 2 {
		t.Fatalf("web: %+v", web)
	}
	if web.Link == nil || web.Link.Kind != "guest" || web.Link.VMID != 100 || web.Link.Target != "home" || web.Link.Node != "pve1" || web.Link.GuestType != "lxc" {
		t.Fatalf("web link: %+v", web.Link)
	}
	// No ARP entry: the guest's only MAC from the inventory is used; its vendor is known.
	if web.MAC != "bc:24:11:00:00:05" || web.Vendor != "Proxmox Server Solutions GmbH" {
		t.Fatalf("web mac: %q %q", web.MAC, web.Vendor)
	}
	names := map[string]string{}
	for _, n := range web.Names {
		names[n.Name] = n.Source
	}
	if names["web"] != SourceInventory || names["web.lan"] != "ptr" || names["Gotify"] != "title" {
		t.Fatalf("names: %+v", web.Names)
	}
	var svcRules []string
	for _, s := range web.Services {
		svcRules = append(svcRules, s.Rule)
	}
	if strings.Join(svcRules, ",") != "ssh,gotify" {
		t.Fatalf("services: %v", svcRules)
	}
	node, ok := hostOf(v, "10.10.10.10")
	if !ok || node.Link == nil || node.Link.Kind != "node" || node.Link.Node != "pve1" || node.MAC != "bc:24:11:11:22:33" {
		t.Fatalf("node: %+v", node)
	}
	// The 8006 answer was plain HTTP though the port suggests TLS: still Proxmox VE.
	if len(node.Services) != 1 || node.Services[0].Rule != "proxmox-ve" || node.Services[0].Proto != "http" {
		t.Fatalf("node services: %+v", node.Services)
	}
	// A running guest that did not answer is shown with that note; a stopped one is not.
	quiet, ok := hostOf(v, "10.10.10.9")
	if !ok || quiet.Alive || !quiet.NoResponse || quiet.Source != SourceInventory || quiet.Link == nil || quiet.Link.VMID != 101 {
		t.Fatalf("quiet: %+v ok=%v", quiet, ok)
	}
	if _, ok := hostOf(v, "10.10.10.8"); ok {
		t.Fatal("a stopped guest is not listed as silent")
	}
	if len(v.Hosts) != 3 {
		t.Fatalf("hosts: %d", len(v.Hosts))
	}
	firstSeen := web.FirstSeen

	// Second scan: the web guest is gone. Its data stays, marked as not alive.
	e.fn.unroute("10.10.10.5", 22)
	e.fn.unroute("10.10.10.5", 80)
	delete(e.fn.alive, mustAddr("10.10.10.5"))
	time.Sleep(15 * time.Millisecond)
	if job := e.scan(); job.Status != store.JobDone {
		t.Fatalf("second: %s", job.Error)
	}
	v = e.view()
	web, _ = hostOf(v, "10.10.10.5")
	if web.Alive || len(web.Services) != 2 || web.MAC == "" || !web.NoResponse || !web.FirstSeen.Equal(firstSeen) || !web.LastSeen.Equal(firstSeen) && !web.LastSeen.After(time.Time{}) {
		t.Fatalf("vanished: %+v", web)
	}
	node, _ = hostOf(v, "10.10.10.10")
	if !node.Alive || !node.FirstSeen.Equal(firstSeen) && node.FirstSeen.After(node.LastSeen) {
		t.Fatalf("node after second scan: %+v", node)
	}
	if !node.LastSeen.After(web.LastSeen) {
		t.Fatalf("last_seen of the live host must move: %v vs %v", node.LastSeen, web.LastSeen)
	}

	// Forget: the stored row goes away (the silent guest is still known from the inventory).
	if err := e.m.Forget(context.Background(), "10.10.10.5"); err != nil {
		t.Fatal(err)
	}
	if err := e.m.Forget(context.Background(), "10.10.10.5"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second forget: %v", err)
	}
	if err := e.m.Forget(context.Background(), "garbage"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bad ip: %v", err)
	}
	web, _ = hostOf(e.view(), "10.10.10.5")
	if web.Source != SourceInventory || web.Alive {
		t.Fatalf("after forget: %+v", web)
	}
}

func logHas(j store.Job, sub string) bool {
	for _, l := range j.Log {
		if strings.Contains(l.Line, sub) {
			return true
		}
	}
	return false
}

func TestScanWithoutSubnetsFailsWithAnExplanation(t *testing.T) {
	e := newMEnv(t)
	job := e.scan()
	if job.Status != store.JobFailed || !strings.Contains(job.Error, "нет подсетей") {
		t.Fatalf("%s %q", job.Status, job.Error)
	}
	if v := e.view(); v.LastScan != nil {
		t.Fatalf("a scan that never started leaves no record: %+v", v.LastScan)
	}
}

func TestExcludedAddressesAreNotDialled(t *testing.T) {
	e := newMEnv(t)
	if _, _, err := e.m.SetSettings(context.Background(), []string{"10.10.30.0/29"}, []string{"10.10.30.1", "10.10.30.4/30"}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	dialled := map[string]bool{}
	e.m.Scanner.Dialer = dialFunc(func(ctx context.Context, ip netipAddr, port int) (netConn, error) {
		mu.Lock()
		dialled[ip.String()] = true
		mu.Unlock()
		return nil, context.DeadlineExceeded
	})
	e.m.Scanner.Ports = Ports[:5]
	if job := e.scan(); job.Status != store.JobDone {
		t.Fatalf("%s", job.Error)
	}
	// /29: .1–.6 hosts; .1 and .4–.7 excluded → .2 and .3.
	if len(dialled) != 2 || !dialled["10.10.30.2"] || !dialled["10.10.30.3"] {
		t.Fatalf("dialled: %v", dialled)
	}
}

// ---- one scan at a time, cancel ----

func TestOneScanAtATimeAndCancelKeepsHosts(t *testing.T) {
	e := newMEnv(t)
	if _, _, err := e.m.SetSettings(context.Background(), []string{"10.10.40.0/29"}, nil); err != nil {
		t.Fatal(err)
	}
	// An earlier result that a cancelled scan must not erase.
	if err := e.st.SaveScanHosts(context.Background(), 0, []store.NetHost{{IP: "10.10.40.2", FirstSeen: time.Now(), LastSeen: time.Now(), Source: SourceScan}}); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var once sync.Once
	e.m.Scanner.Dialer = dialFunc(func(ctx context.Context, ip netipAddr, port int) (netConn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	e.m.Scanner.ConnTimeout = 30 * time.Second

	first, err := e.m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	second, err := e.m.Scan(context.Background())
	if !errors.Is(err, ErrBusy) || second.ID != first.ID {
		t.Fatalf("second scan: %v %s vs %s", err, second.ID, first.ID)
	}
	if v := e.view(); !v.Scanning || v.JobID != first.ID || v.NextScanAt != nil {
		t.Fatalf("view while scanning: %+v", v)
	}
	if !e.m.Cancel() {
		t.Fatal("cancel found nothing")
	}
	waited := make(chan struct{})
	go func() { e.run.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("scan did not stop\n%s", buf[:n])
	}
	job, _ := e.st.GetJob(context.Background(), first.ID)
	if job.Status != store.JobCancelled {
		t.Fatalf("job: %s %q", job.Status, job.Error)
	}
	v := e.view()
	if v.Scanning || v.LastScan == nil || v.LastScan.Error != "отменено" {
		t.Fatalf("view: %+v %+v", v.Scanning, v.LastScan)
	}
	if h, ok := hostOf(v, "10.10.40.2"); !ok || !h.Alive {
		t.Fatalf("host after a cancelled scan: %+v", h)
	}
	if e.m.Cancel() {
		t.Fatal("nothing runs now")
	}
	// A new scan can start again.
	e.m.Scanner.Dialer = newFakeNet()
	e.m.Scanner.ConnTimeout = 20 * time.Millisecond
	if job := e.scan(); job.Status != store.JobDone {
		t.Fatalf("again: %s %s", job.Status, job.Error)
	}
}

func TestShutdownCancelsScan(t *testing.T) {
	e := newMEnv(t)
	_, _, _ = e.m.SetSettings(context.Background(), []string{"10.10.40.0/29"}, nil)
	started := make(chan struct{})
	var once sync.Once
	e.m.Scanner.Dialer = dialFunc(func(ctx context.Context, ip netipAddr, port int) (netConn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	e.m.Scanner.ConnTimeout = 30 * time.Second
	job, err := e.m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	e.run.Shutdown()
	got, _ := e.st.GetJob(context.Background(), job.ID)
	if got.Status != store.JobCancelled {
		t.Fatalf("%s", got.Status)
	}
}

// ---- the schedule ----

func TestNextScanRules(t *testing.T) {
	start := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	iv, first := 6*time.Hour, 5*time.Minute
	// No scan yet: five minutes after start.
	if got := NextScan(start, start, time.Time{}, iv, first); !got.Equal(start.Add(first)) {
		t.Fatalf("first: %v", got)
	}
	// The last scan is older than the interval: also five minutes after start.
	if got := NextScan(start, start, start.Add(-7*time.Hour), iv, first); !got.Equal(start.Add(first)) {
		t.Fatalf("stale: %v", got)
	}
	// A recent scan: an interval after it.
	last := start.Add(-2 * time.Hour)
	if got := NextScan(start, start, last, iv, first); !got.Equal(last.Add(iv)) {
		t.Fatalf("recent: %v", got)
	}
	// Exactly an interval old counts as old.
	if got := NextScan(start, start, start.Add(-iv), iv, first); !got.Equal(start.Add(first)) {
		t.Fatalf("exact: %v", got)
	}
}

func TestSchedulerRunsAutomaticallyOneAtATime(t *testing.T) {
	e := newMEnv(t)
	_, _, _ = e.m.SetSettings(context.Background(), []string{"10.10.50.0/30"}, nil)
	e.m.Scanner.Ports = Ports[:3]
	e.m.FirstDelay = 40 * time.Millisecond
	e.m.Interval = 250 * time.Millisecond
	e.m.started = e.m.Now()

	var mu sync.Mutex
	cur, maxCur := 0, 0
	e.m.Scanner.Dialer = dialFunc(func(ctx context.Context, ip netipAddr, port int) (netConn, error) {
		mu.Lock()
		cur++
		if cur > maxCur {
			maxCur = cur
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		cur--
		mu.Unlock()
		return nil, context.DeadlineExceeded
	})

	ctx, cancel := context.WithCancel(context.Background())
	e.m.Start(ctx)
	// Nothing runs before the first delay; the planned time is exposed.
	time.Sleep(5 * time.Millisecond)
	if v := e.view(); v.LastScan != nil || v.NextScanAt == nil || v.NextScanAt.After(e.m.started.Add(200*time.Millisecond)) {
		t.Fatalf("planned: %+v", v.NextScanAt)
	}
	deadline := time.Now().Add(5 * time.Second)
	var scans []store.ScanRow
	for time.Now().Before(deadline) {
		scans, _ = e.st.ListScans(context.Background(), 10, true)
		if len(scans) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	e.m.Wait()
	e.run.Wait()
	if len(scans) < 2 {
		t.Fatalf("scans: %d", len(scans))
	}
	older, newer := scans[1], scans[0]
	if !newer.StartedAt.After(*older.FinishedAt) && !newer.StartedAt.Equal(*older.FinishedAt) {
		t.Fatalf("scans overlap: %v < %v", newer.StartedAt, older.FinishedAt)
	}
	// The interval counts from the end of the previous scan.
	if gap := newer.StartedAt.Sub(*older.FinishedAt); gap < 200*time.Millisecond {
		t.Fatalf("gap between scans %v, interval 250ms", gap)
	}
	if maxCur > 24 {
		t.Fatalf("concurrency %d", maxCur)
	}
}

func TestSchedulerSkipsWhenManualScanRanRecently(t *testing.T) {
	e := newMEnv(t)
	_, _, _ = e.m.SetSettings(context.Background(), []string{"10.10.50.0/30"}, nil)
	e.m.Scanner.Ports = Ports[:2]
	e.m.Scanner.Dialer = newFakeNet()
	e.m.Scanner.ConnTimeout = 10 * time.Millisecond
	// A manual scan has just finished.
	if job := e.scan(); job.Status != store.JobDone {
		t.Fatal(job.Error)
	}
	e.m.FirstDelay = 20 * time.Millisecond
	e.m.Interval = time.Hour
	e.m.started = e.m.Now()
	ctx, cancel := context.WithCancel(context.Background())
	e.m.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()
	e.m.Wait()
	e.run.Wait()
	scans, _ := e.st.ListScans(context.Background(), 10, false)
	if len(scans) != 1 {
		t.Fatalf("an automatic scan ran right after a manual one: %d", len(scans))
	}
}

func mapARP(ip, mac string) map[netipAddr]string {
	return map[netipAddr]string{mustAddr(ip): mac}
}
