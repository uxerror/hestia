package netscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/netscan/oui"
)

func TestOUI(t *testing.T) {
	for mac, want := range map[string]string{
		"BC:24:11:aa:bb:cc": "Proxmox Server Solutions GmbH",
		"bc-24-11-AA-BB-CC": "Proxmox Server Solutions GmbH",
		"04:F4:1C:00:00:01": "Routerboard.com",
		"9c6b00000001":      "ASRock Incorporation",
	} {
		if v, rnd := oui.Lookup(mac); v != want || rnd {
			t.Errorf("%s: %q random=%v, want %q", mac, v, rnd, want)
		}
	}
	// Locally administered: no vendor, random.
	if v, rnd := oui.Lookup("DA:A1:19:00:00:01"); v != "" || !rnd {
		t.Errorf("random MAC: %q %v", v, rnd)
	}
	if v, rnd := oui.Lookup("02:00:00:00:00:01"); v != "" || !rnd {
		t.Errorf("02:…: %q %v", v, rnd)
	}
	// Unknown / malformed.
	if v, rnd := oui.Lookup("00:00:00:00:00:00"); v != "" && rnd {
		t.Errorf("zero: %q %v", v, rnd)
	}
	if v, rnd := oui.Lookup("nonsense"); v != "" || rnd {
		t.Errorf("bad MAC: %q %v", v, rnd)
	}
	if oui.Normalize("BC:24:11:AA:BB:CC") != "bc:24:11:aa:bb:cc" || oui.Normalize("bc2411") != "" {
		t.Error("normalize")
	}
}

func TestParseSubnet(t *testing.T) {
	p, err := ParseSubnet("10.10.10.50/24")
	if err != nil || p.String() != "10.10.10.0/24" {
		t.Fatalf("%v %v", p, err)
	}
	if p, err := ParseSubnet(" 10.10.8.0/22 "); err != nil || p.Bits() != 22 {
		t.Fatalf("/22 allowed: %v %v", p, err)
	}
	for _, bad := range []string{"10.10.0.0/16", "10.0.0.0/8", "10.10.8.0/21", "abc", "10.10.10.0", "", "fd00::/64", "127.0.0.0/30", "169.254.0.0/24", "224.0.0.0/24", "0.0.0.0/24"} {
		if _, err := ParseSubnet(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseSubnet("10.10.0.0/16"); err == nil || !strings.Contains(err.Error(), "больше /22") {
		t.Errorf("explanation: %v", err)
	}
}

func TestHostsAndExclusions(t *testing.T) {
	p := netip.MustParsePrefix("10.10.10.0/24")
	ex, canon, err := ParseExclusion([]string{"10.10.10.1", "10.10.10.128/25", "10.10.10.1", " "})
	if err != nil || len(canon) != 2 || canon[0] != "10.10.10.1" || canon[1] != "10.10.10.128/25" {
		t.Fatalf("%v %v", canon, err)
	}
	hs := Hosts(p, ex)
	// 254 hosts, minus .1 and the 126 of .128/25 without .255 (broadcast, already skipped): 254 - 1 - 127 = 126.
	if len(hs) != 126 {
		t.Fatalf("hosts: %d", len(hs))
	}
	if hs[0].String() != "10.10.10.2" || hs[len(hs)-1].String() != "10.10.10.127" {
		t.Fatalf("range: %s … %s", hs[0], hs[len(hs)-1])
	}
	all := Hosts(p, Exclusion{})
	if len(all) != 254 || all[0].String() != "10.10.10.1" || all[253].String() != "10.10.10.254" {
		t.Fatalf("no network/broadcast: %d", len(all))
	}
	if n := len(Hosts(netip.MustParsePrefix("10.10.8.0/22"), Exclusion{})); n != 1022 {
		t.Fatalf("/22: %d", n)
	}
	if n := len(Hosts(netip.MustParsePrefix("10.10.10.4/31"), Exclusion{})); n != 2 {
		t.Fatalf("/31: %d", n)
	}
	if n := len(Hosts(netip.MustParsePrefix("10.10.10.9/32"), Exclusion{})); n != 1 {
		t.Fatalf("/32: %d", n)
	}
	for _, bad := range []string{"nope", "10.10.10.300", "fd00::1", "10.10.10.0/99"} {
		if _, _, err := ParseExclusion([]string{bad}); err == nil {
			t.Errorf("exclusion %q accepted", bad)
		}
	}
}

func TestPortList(t *testing.T) {
	if len(Ports) < 130 || len(Ports) > 160 {
		t.Fatalf("%d ports", len(Ports))
	}
	seen := map[int]bool{}
	for _, p := range Ports {
		if seen[p.Port] {
			t.Errorf("port %d twice", p.Port)
		}
		seen[p.Port] = true
		if p.Port <= 0 || p.Port > 65535 || p.Proto == "" {
			t.Errorf("bad entry %+v", p)
		}
	}
	for _, want := range []int{22, 80, 443, 445, 8006, 8007, 9091, 8291, 8728, 32400, 51820} {
		if !seen[want] {
			t.Errorf("port %d missing", want)
		}
	}
	if PortHint(8006).Proto != ProtoHTTPS || PortHint(22).Proto != ProtoSSH || PortHint(31337).Proto != ProtoAuto {
		t.Error("hints")
	}
}

// The real file format of /proc/net/arp.
const arpSample = `IP address       HW type     Flags       HW address            Mask     Device
10.10.10.1       0x1         0x2         04:f4:1c:aa:bb:01     *        eth0
10.10.10.33      0x1         0x2         BC:24:11:aa:bb:33     *        eth0
10.10.10.77      0x1         0x0         00:00:00:00:00:00     *        eth0
10.10.10.78      0x1         0x0         3c:22:fb:00:00:78     *        eth0
10.10.10.79      0x1         0x6         9c:6b:00:00:00:79     *        eth0
garbage line
`

func TestParseARP(t *testing.T) {
	tab := ParseARP(strings.NewReader(arpSample))
	if len(tab) != 3 {
		t.Fatalf("entries: %v", tab)
	}
	if tab[netip.MustParseAddr("10.10.10.1")] != "04:f4:1c:aa:bb:01" || tab[netip.MustParseAddr("10.10.10.33")] != "bc:24:11:aa:bb:33" {
		t.Fatalf("%v", tab)
	}
	// Incomplete entries (flag 0x0) say nothing; 0x6 has the complete bit.
	if _, ok := tab[netip.MustParseAddr("10.10.10.77")]; ok {
		t.Fatal("incomplete entry kept")
	}
	if _, ok := tab[netip.MustParseAddr("10.10.10.78")]; ok {
		t.Fatal("incomplete entry with a MAC kept")
	}
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/arp", []byte(arpSample), 0o600); err != nil {
		t.Fatal(err)
	}
	if tab, err := (SystemARP{Path: dir + "/arp"}).Table(); err != nil || len(tab) != 3 {
		t.Fatalf("%v %v", tab, err)
	}
}

func addrs(prefix string, from, to int) []netip.Addr {
	var out []netip.Addr
	for i := from; i <= to; i++ {
		out = append(out, netip.MustParseAddr(prefix+"."+itoa(i)))
	}
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestDiscoverFindsOpenRefusedAndARPHosts(t *testing.T) {
	fn := newFakeNet()
	fn.route("10.10.10.5", 22, listenBanner(t, "SSH-2.0-x\r\n"))
	fn.route("10.10.10.5", 80, listenBanner(t, ""))
	fn.alive[netip.MustParseAddr("10.10.10.6")] = true // closed ports answer RST
	sub := []netip.Prefix{netip.MustParsePrefix("10.10.10.0/24")}
	arp := fakeARP{table: map[netip.Addr]string{netip.MustParseAddr("10.10.10.7"): "3c:22:fb:00:00:07"}, local: true}
	sc := &Scanner{Dialer: fn, ARP: arp, ConnTimeout: 40 * time.Millisecond, Ports: []PortInfo{{22, "ssh", ProtoSSH}, {80, "http", ProtoHTTP}, {443, "https", ProtoHTTPS}}}
	var lastChecked, lastTotal int
	var mu sync.Mutex
	found, err := sc.Discover(context.Background(), addrs("10.10.10", 4, 9), sub, func(c, total, alive int) {
		mu.Lock()
		lastChecked, lastTotal = c, total
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Discovery{}
	for _, d := range found {
		got[d.IP.String()] = d
	}
	if len(got) != 3 {
		t.Fatalf("found: %+v", found)
	}
	if d := got["10.10.10.5"]; len(d.Open) != 2 || d.Open[0] != 22 || d.Open[1] != 80 {
		t.Fatalf(".5: %+v", d)
	}
	if d := got["10.10.10.6"]; !d.Refused || len(d.Open) != 0 {
		t.Fatalf(".6 (RST): %+v", d)
	}
	if _, ok := got["10.10.10.7"]; !ok {
		t.Fatal(".7 answers ARP only: alive")
	}
	if _, ok := got["10.10.10.8"]; ok {
		t.Fatal("a timeout is not a sign of life")
	}
	if lastChecked != 6 || lastTotal != 6 {
		t.Fatalf("progress %d of %d", lastChecked, lastTotal)
	}

	// Outside the machine's own subnet the ARP table proves nothing.
	sc.ARP = fakeARP{table: arp.table, local: false}
	found, err = sc.Discover(context.Background(), addrs("10.10.10", 7, 8), sub, nil)
	if err != nil || len(found) != 0 {
		t.Fatalf("non-local ARP: %v %v", found, err)
	}
	// No ARP at all (other OS): ports and RST still work.
	sc.ARP = fakeARP{err: os.ErrNotExist}
	found, _ = sc.Discover(context.Background(), addrs("10.10.10", 5, 6), sub, nil)
	if len(found) != 2 {
		t.Fatalf("without ARP: %v", found)
	}
}

func TestRefusedIsRecognisedOnRealLoopback(t *testing.T) {
	// A real closed port on 127.0.0.1 gives a real RST: the same check must see it.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	_, err := (&net.Dialer{Timeout: time.Second}).Dial("tcp", addr)
	if err == nil || !isRefused(err) {
		t.Fatalf("err %v, refused=%v", err, err != nil && isRefused(err))
	}
	if isRefused(context.DeadlineExceeded) || isRefused(errors.New("x")) || !isRefused(syscall.ECONNREFUSED) {
		t.Fatal("isRefused")
	}
}

// countingNet measures concurrency.
type countingNet struct {
	mu        sync.Mutex
	cur, max  int
	perHost   map[netip.Addr]int
	maxHost   int
	hold      time.Duration
	dials     atomic.Int64
	started   chan struct{}
	startOnce sync.Once
}

func (c *countingNet) DialContext(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
	c.dials.Add(1)
	c.startOnce.Do(func() {
		if c.started != nil {
			close(c.started)
		}
	})
	c.mu.Lock()
	c.cur++
	c.perHost[ip]++
	if c.cur > c.max {
		c.max = c.cur
	}
	if c.perHost[ip] > c.maxHost {
		c.maxHost = c.perHost[ip]
	}
	c.mu.Unlock()
	select {
	case <-time.After(c.hold):
	case <-ctx.Done():
	}
	c.mu.Lock()
	c.cur--
	c.perHost[ip]--
	c.mu.Unlock()
	return nil, &net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func TestDiscoverLimitsConcurrency(t *testing.T) {
	cn := &countingNet{perHost: map[netip.Addr]int{}, hold: 3 * time.Millisecond}
	sc := &Scanner{Dialer: cn, ConnTimeout: time.Second}
	// 20 hosts × 150 ports: the default port list.
	found, err := sc.Discover(context.Background(), addrs("10.10.10", 1, 20), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 20 {
		t.Fatalf("refused hosts are alive: %d", len(found))
	}
	if got := cn.dials.Load(); got != int64(20*len(Ports)) {
		t.Fatalf("dials %d, want %d", got, 20*len(Ports))
	}
	if cn.max > MaxConnsScan {
		t.Fatalf("%d concurrent connects, limit %d", cn.max, MaxConnsScan)
	}
	if cn.max < 50 {
		t.Fatalf("no parallelism: %d", cn.max)
	}
	if cn.maxHost > MaxConnsHost {
		t.Fatalf("%d connects to one host, limit %d", cn.maxHost, MaxConnsHost)
	}

	// One host alone: the per-host limit is what holds.
	cn2 := &countingNet{perHost: map[netip.Addr]int{}, hold: 3 * time.Millisecond}
	_, _ = (&Scanner{Dialer: cn2, ConnTimeout: time.Second}).Discover(context.Background(), addrs("10.10.10", 1, 1), nil, nil)
	if cn2.maxHost > MaxConnsHost || cn2.maxHost < MaxConnsHost-4 {
		t.Fatalf("single host: %d (limit %d)", cn2.maxHost, MaxConnsHost)
	}
}

func TestDiscoverCancel(t *testing.T) {
	cn := &countingNet{perHost: map[netip.Addr]int{}, hold: 10 * time.Second, started: make(chan struct{})}
	sc := &Scanner{Dialer: cn, ConnTimeout: 10 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := sc.Discover(ctx, addrs("10.10.10", 1, 50), nil, nil)
		done <- err
	}()
	<-cn.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("scan did not stop after cancel")
	}
	if cn.dials.Load() >= int64(50*len(Ports)) {
		t.Fatal("everything was dialled after cancel")
	}
}

func TestOrderIsShuffled(t *testing.T) {
	// The first dials must not all go to one host.
	var mu sync.Mutex
	var order []netip.Addr
	d := dialFunc(func(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
		mu.Lock()
		order = append(order, ip)
		mu.Unlock()
		return nil, &net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	})
	sc := &Scanner{Dialer: d, ConnTimeout: time.Second, Ports: Ports[:20]}
	_, _ = sc.Discover(context.Background(), addrs("10.10.10", 1, 20), nil, nil)
	same := 0
	for i := 1; i < 40 && i < len(order); i++ {
		if order[i] == order[i-1] {
			same++
		}
	}
	if same > 15 {
		t.Fatalf("hosts hit in a row: %d of 40 neighbours equal", same)
	}
}

type dialFunc func(ctx context.Context, ip netip.Addr, port int) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
	return f(ctx, ip, port)
}
