package netscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Limits and timeouts of a scan.
const (
	ConnTimeout   = 700 * time.Millisecond
	MaxConnsScan  = 256 // concurrent connects per scan (service nofile limit is 1024)
	MaxConnsHost  = 24  // concurrent connects per host
	MaxProbes     = 32  // concurrent fingerprint probes per scan
	ProbeTimeout  = 3 * time.Second
	BannerTimeout = 1500 * time.Millisecond
	PTRTimeout    = time.Second
	MaxPTR        = 16
	BannerMax     = 256
	BodyMax       = 64 << 10
)

// Dialer opens a TCP connection to ip:port. Tests map addresses to local
// listeners through it, so a test never touches a real network.
type Dialer interface {
	DialContext(ctx context.Context, ip netip.Addr, port int) (net.Conn, error)
}

// NetDialer is the real Dialer.
type NetDialer struct{}

func (NetDialer) DialContext(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

// Resolver looks up the names of an address (PTR).
type Resolver interface {
	LookupAddr(ctx context.Context, ip netip.Addr) ([]string, error)
}

// SystemResolver uses the system resolver.
type SystemResolver struct{}

func (SystemResolver) LookupAddr(ctx context.Context, ip netip.Addr) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, ip.String())
}

// Discovery is what the connect scan learned about one address.
type Discovery struct {
	IP      netip.Addr
	Open    []int
	Refused bool // got an RST: something is there
}

// Progress is called as addresses are finished: checked of total addresses
// done, found of them alive so far.
type Progress func(checked, total, found int)

// Scanner runs the discovery and fingerprinting phases.
type Scanner struct {
	Dialer   Dialer
	ARP      ARP
	Resolver Resolver
	// UserAgent is sent with HTTP probes.
	UserAgent string
	// Overridable in tests.
	ConnTimeout   time.Duration
	ProbeTimeout  time.Duration
	BannerTimeout time.Duration
	Ports         []PortInfo
}

func (s *Scanner) connTimeout() time.Duration { return orDur(s.ConnTimeout, ConnTimeout) }
func (s *Scanner) probeTimeout() time.Duration {
	return orDur(s.ProbeTimeout, ProbeTimeout)
}
func (s *Scanner) bannerTimeout() time.Duration { return orDur(s.BannerTimeout, BannerTimeout) }

func orDur(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

func (s *Scanner) ports() []PortInfo {
	if s.Ports != nil {
		return s.Ports
	}
	return Ports
}

// isRefused tells a closed port (RST: the host is there) from a timeout.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

type task struct {
	host *hostState
	port int
}

type hostState struct {
	ip      netip.Addr
	sem     chan struct{}
	left    int32
	mu      sync.Mutex
	open    []int
	refused bool
}

// Discover connects to every port of every address and returns the addresses
// that look alive: an open port, a refused connection, or (after the pass) a
// complete ARP entry. Tasks are shuffled so no host is hit in a row. It
// returns ctx.Err() if cancelled.
func (s *Scanner) Discover(ctx context.Context, addrs []netip.Addr, subnets []netip.Prefix, progress Progress) ([]Discovery, error) {
	ports := s.ports()
	hosts := make([]*hostState, len(addrs))
	tasks := make([]task, 0, len(addrs)*len(ports))
	for i, a := range addrs {
		h := &hostState{ip: a, sem: make(chan struct{}, MaxConnsHost), left: int32(len(ports))}
		hosts[i] = h
		for _, p := range ports {
			tasks = append(tasks, task{h, p.Port})
		}
	}
	shuffle(tasks)

	var checked, found atomic.Int32
	total := len(addrs)
	finish := func(h *hostState) {
		if atomic.AddInt32(&h.left, -1) != 0 {
			return
		}
		h.mu.Lock()
		alive := len(h.open) > 0 || h.refused
		h.mu.Unlock()
		if alive {
			found.Add(1)
		}
		n := checked.Add(1)
		if progress != nil {
			progress(int(n), total, int(found.Load()))
		}
	}

	global := make(chan struct{}, MaxConnsScan)
	var wg sync.WaitGroup
	timeout := s.connTimeout()
loop:
	for _, t := range tasks {
		select {
		case <-ctx.Done():
			break loop
		case global <- struct{}{}:
		}
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			defer func() { <-global }()
			select {
			case t.host.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-t.host.sem }()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			conn, err := s.Dialer.DialContext(cctx, t.host.ip, t.port)
			cancel()
			switch {
			case err == nil:
				_ = conn.Close()
				t.host.mu.Lock()
				t.host.open = append(t.host.open, t.port)
				t.host.mu.Unlock()
			case isRefused(err):
				t.host.mu.Lock()
				t.host.refused = true
				t.host.mu.Unlock()
			}
			finish(t.host)
		}(t)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// A host that answers ARP is alive even if every port is filtered.
	var arp map[netip.Addr]string
	if s.ARP != nil {
		if tab, err := s.ARP.Table(); err == nil {
			arp = tab
		}
	}
	local := func(a netip.Addr) bool {
		for _, p := range subnets {
			if p.Contains(a) {
				return s.ARP != nil && s.ARP.Local(p)
			}
		}
		return false
	}
	var out []Discovery
	for _, h := range hosts {
		_, inARP := arp[h.ip]
		if len(h.open) == 0 && !h.refused && !(inARP && local(h.ip)) {
			continue
		}
		sort.Ints(h.open)
		out = append(out, Discovery{IP: h.ip, Open: h.open, Refused: h.refused})
	}
	return out, nil
}
