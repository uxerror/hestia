package netscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hestia/internal/inventory"
	"hestia/internal/jobs"
	"hestia/internal/netscan/oui"
	"hestia/internal/store"
)

// Job and settings names.
const (
	JobKind          = "netscan"
	SettingExtra     = "netscan.extra_subnets"
	SettingExclude   = "netscan.exclude"
	SettingIntervalH = "netscan.interval_hours"
)

// Scheduling defaults.
const (
	DefaultIntervalHours = 6
	DefaultFirstDelay    = 5 * time.Minute
)

// ErrBusy is returned when a scan is already running.
var ErrBusy = errors.New("сканирование уже идёт")

// InputError is a refused setting (bad subnet, too large, …).
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// Inventory is the part of the inventory service the scan uses.
type Inventory interface {
	List(ctx context.Context) ([]inventory.Entry, error)
}

// Manager owns the scan settings, runs scans as jobs and schedules them.
type Manager struct {
	Store     *store.Store
	Runner    *jobs.Runner
	Inventory Inventory
	Scanner   *Scanner
	Version   string
	Now       func() time.Time
	// Interval and FirstDelay override the defaults (6 h setting, 5 min).
	Interval   time.Duration
	FirstDelay time.Duration

	mu       sync.Mutex
	jobID    string
	cancel   context.CancelFunc
	idle     chan struct{} // closed while no scan runs
	nextAt   time.Time
	lastEnd  time.Time
	started  time.Time
	loopDone sync.WaitGroup
}

// Init fills in defaults; call it once.
func (m *Manager) Init() *Manager {
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.Scanner == nil {
		m.Scanner = &Scanner{Dialer: NetDialer{}, ARP: SystemARP{}, Resolver: SystemResolver{}}
	}
	if m.Scanner.UserAgent == "" {
		v := m.Version
		if v == "" {
			v = "dev"
		}
		m.Scanner.UserAgent = "Hestia/" + v + " (network inventory)"
	}
	if m.FirstDelay <= 0 {
		m.FirstDelay = DefaultFirstDelay
	}
	m.idle = make(chan struct{})
	close(m.idle)
	m.started = m.Now()
	return m
}

// ---- settings ----

func (m *Manager) getList(ctx context.Context, key string) []string {
	v, err := m.Store.GetSetting(ctx, key)
	if err != nil {
		return []string{}
	}
	var l []string
	if json.Unmarshal([]byte(v), &l) != nil || l == nil {
		return []string{}
	}
	return l
}

// Settings returns the manual subnets and the exclusions.
func (m *Manager) Settings(ctx context.Context) (extra, exclude []string) {
	return m.getList(ctx, SettingExtra), m.getList(ctx, SettingExclude)
}

// IntervalHours is the scan interval in hours (setting, default 6).
func (m *Manager) IntervalHours(ctx context.Context) int {
	if v, err := m.Store.GetSetting(ctx, SettingIntervalH); err == nil {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 24*7 {
			return n
		}
	}
	return DefaultIntervalHours
}

func (m *Manager) interval(ctx context.Context) time.Duration {
	if m.Interval > 0 {
		return m.Interval
	}
	return time.Duration(m.IntervalHours(ctx)) * time.Hour
}

// SetSettings validates and stores the manual subnets and exclusions; the
// canonical forms are returned.
func (m *Manager) SetSettings(ctx context.Context, extra, exclude []string) ([]string, []string, error) {
	var canonExtra []string
	seen := map[string]bool{}
	for _, raw := range extra {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := ParseSubnet(raw)
		if err != nil {
			return nil, nil, &InputError{err.Error()}
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			canonExtra = append(canonExtra, p.String())
		}
	}
	if len(canonExtra) > MaxManualSubnets {
		return nil, nil, &InputError{fmt.Sprintf("слишком много подсетей (не больше %d)", MaxManualSubnets)}
	}
	_, canonEx, err := ParseExclusion(exclude)
	if err != nil {
		return nil, nil, &InputError{err.Error()}
	}
	if canonExtra == nil {
		canonExtra = []string{}
	}
	if canonEx == nil {
		canonEx = []string{}
	}
	for k, v := range map[string][]string{SettingExtra: canonExtra, SettingExclude: canonEx} {
		b, _ := json.Marshal(v)
		if err := m.Store.SetSetting(ctx, k, string(b)); err != nil {
			return nil, nil, err
		}
	}
	return canonExtra, canonEx, nil
}

// ---- subnets ----

// Subnets lists the subnets of a scan (automatic ones first, then manual)
// and the ones that will really be scanned.
func (m *Manager) Subnets(ctx context.Context) ([]SubnetInfo, []netip.Prefix) {
	var entries []inventory.Entry
	if m.Inventory != nil {
		entries, _ = m.Inventory.List(ctx)
	}
	targets := map[int64]store.Target{}
	if ts, err := m.Store.ListTargets(ctx); err == nil {
		for _, t := range ts {
			targets[t.ID] = t
		}
	}
	raw := subnetsFromInventory(entries, targets)
	extra, _ := m.Settings(ctx)
	for _, c := range extra {
		raw = append(raw, SubnetInfo{CIDR: c, Source: "manual", Label: "добавлена вручную"})
	}
	return resolveSubnets(raw)
}

// resolveSubnets normalises and merges equal subnets; the unusable ones stay
// in the list with an error.
func resolveSubnets(raw []SubnetInfo) ([]SubnetInfo, []netip.Prefix) {
	type item struct {
		info SubnetInfo
		p    netip.Prefix
		ok   bool
	}
	byKey := map[string]*item{}
	var order []*item
	for _, r := range raw {
		p, err := ParseSubnet(r.CIDR)
		key, info := p.String(), r
		if err != nil {
			key = "bad:" + r.CIDR
			info.Error = errText(err)
		} else {
			info.CIDR = p.String()
		}
		if it, ok := byKey[key]; ok {
			if !strings.Contains(it.info.Label, info.Label) {
				it.info.Label += ", " + info.Label
			}
			if it.info.Gateway == "" {
				it.info.Gateway = info.Gateway
			}
			continue
		}
		it := &item{info: info, p: p, ok: err == nil}
		byKey[key] = it
		order = append(order, it)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.ok != b.ok {
			return a.ok
		}
		if !a.ok {
			return a.info.CIDR < b.info.CIDR
		}
		return a.p.Addr().Less(b.p.Addr())
	})
	var infos []SubnetInfo
	var ps []netip.Prefix
	for _, it := range order {
		infos = append(infos, it.info)
		if it.ok {
			ps = append(ps, it.p)
		}
	}
	if infos == nil {
		infos = []SubnetInfo{}
	}
	return infos, ps
}

func errText(err error) string {
	s := err.Error()
	if i := strings.Index(s, "больше /"); i >= 0 {
		return "подсеть больше /" + strconv.Itoa(MaxPrefixBits) + " — не сканируется"
	}
	return s
}

// ---- reading ----

// View is what GET /network returns.
type View struct {
	LastScan      *Scan        `json:"last_scan"`
	NextScanAt    *time.Time   `json:"next_scan_at"`
	Scanning      bool         `json:"scanning"`
	JobID         string       `json:"job_id"`
	IntervalHours int          `json:"interval_hours"`
	Subnets       []SubnetInfo `json:"subnets"`
	ExtraSubnets  []string     `json:"extra_subnets"` // the manual ones (also listed in Subnets)
	Exclude       []string     `json:"exclude"`
	Hosts         []Host       `json:"hosts"`
}

func scanFromRow(r store.ScanRow) Scan {
	s := Scan{ID: r.ID, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, Error: r.Error, Subnets: []string{}}
	_ = json.Unmarshal(r.Subnets, &s.Subnets)
	_ = json.Unmarshal(r.Stats, &s.Stats)
	return s
}

// View assembles the state of the network screen.
func (m *Manager) View(ctx context.Context) (View, error) {
	v := View{IntervalHours: m.IntervalHours(ctx)}
	if m.Interval > 0 {
		v.IntervalHours = int(m.Interval / time.Hour)
	}
	if row, err := m.Store.LastScan(ctx); err == nil {
		sc := scanFromRow(row)
		v.LastScan = &sc
	} else if !errors.Is(err, store.ErrNotFound) {
		return v, err
	}
	v.Subnets, _ = m.Subnets(ctx)
	v.ExtraSubnets, v.Exclude = m.Settings(ctx)
	m.mu.Lock()
	v.JobID, v.Scanning = m.jobID, m.jobID != ""
	if !m.nextAt.IsZero() && !v.Scanning {
		t := m.nextAt
		v.NextScanAt = &t
	}
	m.mu.Unlock()
	if v.NextScanAt == nil && !v.Scanning {
		t := m.computeNext(ctx)
		v.NextScanAt = &t
	}

	rows, err := m.Store.ListHosts(ctx)
	if err != nil {
		return v, err
	}
	ix := m.loadIndex(ctx)
	have := map[string]bool{}
	v.Hosts = make([]Host, 0, len(rows))
	for _, r := range rows {
		h := hostFromRow(r)
		have[h.IP] = true
		if l := ix.lookup(h.IP, h.MAC); l != nil {
			h.Link = l
		} else if !ix.empty {
			h.Link = nil
		}
		h.NoResponse = !h.Alive && h.Link != nil && h.Link.Kind == "guest" && h.Link.Status == "running"
		v.Hosts = append(v.Hosts, h)
	}
	if v.LastScan != nil {
		v.Hosts = append(v.Hosts, ix.missing(have)...)
	}
	sort.Slice(v.Hosts, func(i, j int) bool { return addrLess(v.Hosts[i].IP, v.Hosts[j].IP) })
	return v, nil
}

func addrLess(a, b string) bool {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return a < b
	}
	return x.Less(y)
}

func hostFromRow(r store.NetHost) Host {
	h := Host{
		IP: r.IP, MAC: r.MAC, Vendor: r.Vendor, RandomMAC: r.RandomMAC, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		LastScanID: r.LastScanID, Alive: r.Alive, Source: r.Source, Names: []Name{}, Ports: []int{}, Services: []ServiceInfo{},
	}
	_ = json.Unmarshal(r.Names, &h.Names)
	_ = json.Unmarshal(r.Ports, &h.Ports)
	_ = json.Unmarshal(r.Services, &h.Services)
	_ = json.Unmarshal(r.Link, &h.Link)
	return h
}

// Forget deletes a host from the list (it reappears if the next scan finds it).
func (m *Manager) Forget(ctx context.Context, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return store.ErrNotFound
	}
	return m.Store.DeleteHost(ctx, a.String())
}

// ---- running a scan ----

// Scan starts a scan job. If one is already running it returns that job and
// ErrBusy.
func (m *Manager) Scan(ctx context.Context) (store.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.jobID != "" {
		j, _ := m.Store.GetJob(ctx, m.jobID)
		return j, ErrBusy
	}
	cctx, cancel := context.WithCancel(context.Background())
	idle := make(chan struct{})
	job, err := m.Runner.Start(JobKind, "Сканирование сети", func(jctx context.Context, run *jobs.Run) error {
		sctx, stop := context.WithCancel(jctx)
		defer stop()
		defer context.AfterFunc(cctx, stop)() // Cancel() stops the scan
		defer func() {
			m.mu.Lock()
			m.jobID, m.cancel = "", nil
			m.lastEnd = m.Now()
			m.nextAt = time.Time{}
			m.mu.Unlock()
			cancel()
			close(idle)
		}()
		return m.runScan(sctx, run)
	})
	if err != nil {
		cancel()
		return store.Job{}, err
	}
	m.jobID, m.cancel, m.idle = job.ID, cancel, idle
	return job, nil
}

// Cancel stops the running scan; it reports whether one was running.
func (m *Manager) Cancel() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel == nil {
		return false
	}
	m.cancel()
	return true
}

type scanState struct {
	infos    []SubnetInfo
	prefixes []netip.Prefix
	ex       Exclusion
	addrs    []netip.Addr
	found    []Discovery
	results  []HostResult
	started  time.Time
}

func (m *Manager) runScan(ctx context.Context, run *jobs.Run) (err error) {
	// The step functions get the runner context; the scan uses ctx, which
	// also ends when Cancel is called.
	st := &scanState{started: m.Now()}
	var scanID int64
	var stats Stats
	defer func() {
		if scanID == 0 {
			return
		}
		stats.DurationMS = m.Now().Sub(st.started).Milliseconds()
		b, _ := json.Marshal(stats)
		msg := ""
		switch {
		case errors.Is(err, context.Canceled) || ctx.Err() != nil:
			msg = "отменено"
		case err != nil:
			msg = err.Error()
		}
		// The job context may be cancelled: the record must still be closed.
		if ferr := m.Store.FinishScan(context.Background(), scanID, m.Now().UTC(), b, msg); ferr != nil {
			slog.Warn("сканирование: не закрыта запись", "err", ferr)
		}
	}()

	if err := run.Step("Подсети", func(context.Context) error {
		st.infos, st.prefixes = m.Subnets(ctx)
		_, excl := m.Settings(ctx)
		ex, _, perr := ParseExclusion(excl)
		if perr != nil {
			return perr
		}
		st.ex = ex
		for _, s := range st.infos {
			if s.Error != "" {
				run.Log("warn", fmt.Sprintf("Подсеть %s пропущена: %s (%s)", s.CIDR, s.Error, s.Label))
				continue
			}
			run.Log("info", fmt.Sprintf("Подсеть %s — %s", s.CIDR, s.Label))
		}
		if len(excl) > 0 {
			run.Log("info", "Исключения: "+strings.Join(excl, ", "))
		}
		if len(st.prefixes) == 0 {
			return errors.New("нет подсетей для сканирования: подключите Proxmox или SSH-сервер либо добавьте подсеть вручную")
		}
		seen := map[netip.Addr]bool{}
		for _, p := range st.prefixes {
			for _, a := range Hosts(p, st.ex) {
				if !seen[a] {
					seen[a] = true
					st.addrs = append(st.addrs, a)
				}
			}
		}
		var cidrs []string
		for _, p := range st.prefixes {
			cidrs = append(cidrs, p.String())
		}
		sb, _ := json.Marshal(cidrs)
		id, berr := m.Store.BeginScan(context.Background(), st.started.UTC(), sb)
		if berr != nil {
			return berr
		}
		scanID = id
		stats.Subnets, stats.Addresses = len(st.prefixes), len(st.addrs)
		run.Log("info", fmt.Sprintf("Адресов к проверке: %d, портов на адрес: %d", len(st.addrs), len(m.Scanner.ports())))
		return nil
	}); err != nil {
		return err
	}

	if err := run.Step("Обнаружение", func(context.Context) error {
		var logMu sync.Mutex // progress arrives from many goroutines
		lastLog := 0
		found, derr := m.Scanner.Discover(ctx, st.addrs, st.prefixes, func(checked, total, alive int) {
			logMu.Lock()
			defer logMu.Unlock()
			if step := total / 10; (step > 0 && checked-lastLog >= step) || checked == total {
				lastLog = checked
				run.Log("info", fmt.Sprintf("Проверено %d из %d адресов, найдено %d", checked, total, alive))
			}
		})
		if derr != nil {
			return derr
		}
		st.found = found
		run.Log("info", fmt.Sprintf("Живых адресов: %d", len(found)))
		return nil
	}); err != nil {
		return err
	}

	if err := run.Step("Отпечатки", func(context.Context) error {
		res, ferr := m.Scanner.Fingerprint(ctx, st.found, st.prefixes, nil)
		if ferr != nil {
			return ferr
		}
		st.results = res
		n := 0
		for _, r := range res {
			n += len(r.Services)
		}
		stats.Services = n
		run.Log("info", fmt.Sprintf("Определено сервисов: %d", n))
		return nil
	}); err != nil {
		return err
	}

	return run.Step("Сохранение", func(context.Context) error {
		hosts, herr := m.buildHosts(ctx, st, scanID)
		if herr != nil {
			return herr
		}
		stats.Alive = len(hosts)
		if err := m.Store.SaveScanHosts(context.Background(), scanID, hosts); err != nil {
			return err
		}
		run.Log("info", fmt.Sprintf("Сохранено хостов: %d", len(hosts)))
		return nil
	})
}

// buildHosts turns the results into rows, adding names, MACs and links from
// the inventory.
func (m *Manager) buildHosts(ctx context.Context, st *scanState, scanID int64) ([]store.NetHost, error) {
	old, err := m.Store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	first := map[string]time.Time{}
	for _, h := range old {
		first[h.IP] = h.FirstSeen
	}
	ix := m.loadIndex(ctx)
	now := m.Now().UTC()
	out := make([]store.NetHost, 0, len(st.results))
	for _, r := range st.results {
		ip := r.IP.String()
		mac, vendor, random := r.MAC, r.Vendor, r.RandomMAC
		link := ix.lookup(ip, mac)
		names := r.Names
		if link != nil && link.Name != "" {
			names = mergeNames([]Name{{Name: link.Name, Source: SourceInventory}}, names)
		}
		if mac == "" {
			if own := ix.ownMAC(ip); own != "" {
				mac = own
				vendor, random = oui.Lookup(mac)
			}
		}
		ft, ok := first[ip]
		if !ok {
			ft = now
		}
		nb, _ := json.Marshal(names)
		pb, _ := json.Marshal(r.Ports)
		sb, _ := json.Marshal(r.Services)
		lb, _ := json.Marshal(link)
		out = append(out, store.NetHost{
			IP: ip, MAC: mac, Vendor: vendor, RandomMAC: random, Names: nb, FirstSeen: ft, LastSeen: now,
			LastScanID: scanID, Alive: true, Source: SourceScan, Ports: pb, Services: sb, Link: lb,
		})
	}
	return out, nil
}

// ---- schedule ----

// NextScan is the time of the next automatic scan: the first one 5 minutes
// after start (if there is no scan or the last one is older than the
// interval), later ones an interval after the previous scan.
func NextScan(now, started time.Time, last time.Time, interval, firstDelay time.Duration) time.Time {
	if last.IsZero() || now.Sub(last) >= interval {
		return started.Add(firstDelay)
	}
	return last.Add(interval)
}

func (m *Manager) lastFinished(ctx context.Context) time.Time {
	var last time.Time
	if row, err := m.Store.LastScan(ctx); err == nil && row.FinishedAt != nil {
		last = *row.FinishedAt
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastEnd.After(last) {
		last = m.lastEnd
	}
	return last
}

func (m *Manager) computeNext(ctx context.Context) time.Time {
	return NextScan(m.Now(), m.started, m.lastFinished(ctx), m.interval(ctx), m.FirstDelay)
}

// Start runs the scheduler until ctx ends. A running scan is never doubled:
// the scheduler waits for it and counts the interval from its end.
func (m *Manager) Start(ctx context.Context) {
	m.loopDone.Add(1)
	go func() {
		defer m.loopDone.Done()
		for {
			next := m.computeNext(ctx)
			m.mu.Lock()
			m.nextAt = next
			m.mu.Unlock()
			wait := next.Sub(m.Now())
			if wait > 0 {
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
				// A manual scan may have moved the schedule meanwhile.
				if m.computeNext(ctx).After(m.Now()) {
					continue
				}
			}
			if ctx.Err() != nil {
				return
			}
			if _, err := m.Scan(ctx); err != nil && !errors.Is(err, ErrBusy) {
				slog.Warn("сканирование сети не запущено", "err", err)
				m.mu.Lock()
				m.lastEnd = m.Now() // do not retry in a tight loop
				m.mu.Unlock()
			}
			m.waitIdle(ctx)
			if ctx.Err() != nil {
				return
			}
		}
	}()
}

func (m *Manager) waitIdle(ctx context.Context) {
	m.mu.Lock()
	idle := m.idle
	m.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
	}
}

// Wait blocks until the scheduler has stopped.
func (m *Manager) Wait() { m.loopDone.Wait() }
