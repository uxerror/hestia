package netscan

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/uxerror/hestia/internal/netscan/oui"
)

// HostResult is what a scan learned about one live address.
type HostResult struct {
	IP        netip.Addr
	Ports     []int
	Refused   bool
	Services  []ServiceInfo
	MAC       string
	Vendor    string
	RandomMAC bool
	Names     []Name
}

// Fingerprint probes every open port of the discovered hosts (at most
// MaxProbes at a time), looks up PTR names (at most MaxPTR at a time) and
// attaches MAC and vendor from the ARP table. done(n, total) reports the
// probed ports.
func (s *Scanner) Fingerprint(ctx context.Context, found []Discovery, subnets []netip.Prefix, done func(n, total int)) ([]HostResult, error) {
	res := make([]HostResult, len(found))
	total := 0
	for i, d := range found {
		res[i] = HostResult{IP: d.IP, Ports: append([]int{}, d.Open...), Refused: d.Refused, Services: []ServiceInfo{}, Names: []Name{}}
		total += len(d.Open)
	}

	var n atomic.Int32
	probes := make(chan struct{}, MaxProbes)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range found {
		for _, p := range found[i].Open {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil, ctx.Err()
			case probes <- struct{}{}:
			}
			wg.Add(1)
			go func(i, p int) {
				defer wg.Done()
				defer func() { <-probes }()
				f := s.probePort(ctx, found[i].IP, PortHint(p))
				f.OpenPorts = found[i].Open
				s.followups(ctx, f)
				svc := Identify(f)
				mu.Lock()
				res[i].Services = append(res[i].Services, svc)
				mu.Unlock()
				if done != nil {
					done(int(n.Add(1)), total)
				}
			}(i, p)
		}
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.resolve(ctx, res)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.attachMACs(res, subnets)
	for i := range res {
		sort.Slice(res[i].Services, func(a, b int) bool { return res[i].Services[a].Port < res[i].Services[b].Port })
		res[i].Names = mergeNames(res[i].Names, namesFromServices(res[i].Services))
	}
	return res, nil
}

// resolve fills PTR names with bounded parallelism.
func (s *Scanner) resolve(ctx context.Context, res []HostResult) {
	if s.Resolver == nil {
		return
	}
	sem := make(chan struct{}, MaxPTR)
	var wg sync.WaitGroup
	for i := range res {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			rctx, cancel := context.WithTimeout(ctx, PTRTimeout)
			defer cancel()
			names, err := s.Resolver.LookupAddr(rctx, res[i].IP)
			if err != nil {
				return
			}
			for _, nm := range names {
				nm = strings.TrimSuffix(strings.TrimSpace(nm), ".")
				if nm != "" {
					res[i].Names = append(res[i].Names, Name{Name: nm, Source: "ptr"})
				}
			}
		}(i)
	}
	wg.Wait()
}

// attachMACs sets MAC and vendor from the ARP table, only for subnets the
// machine itself is in (elsewhere the table holds the router's MAC).
func (s *Scanner) attachMACs(res []HostResult, subnets []netip.Prefix) {
	if s.ARP == nil {
		return
	}
	tab, err := s.ARP.Table()
	if err != nil {
		return
	}
	local := map[netip.Prefix]bool{}
	for _, p := range subnets {
		local[p] = s.ARP.Local(p)
	}
	for i := range res {
		mac, ok := tab[res[i].IP]
		if !ok {
			continue
		}
		for p, l := range local {
			if l && p.Contains(res[i].IP) {
				res[i].MAC = mac
				res[i].Vendor, res[i].RandomMAC = oui.Lookup(mac)
				break
			}
		}
	}
}

// namesFromServices collects certificate names and web page titles.
func namesFromServices(svcs []ServiceInfo) []Name {
	var out []Name
	for _, s := range svcs {
		if s.Cert != nil {
			if s.Cert.CN != "" {
				out = append(out, Name{Name: s.Cert.CN, Source: "cert"})
			}
			for _, n := range s.Cert.SAN {
				if _, err := netip.ParseAddr(n); err != nil && n != "localhost" {
					out = append(out, Name{Name: n, Source: "cert"})
				}
			}
		}
		if t := usefulTitle(s); t != "" {
			out = append(out, Name{Name: t, Source: "title"})
		}
	}
	return out
}

// usefulTitle is a page title that names the device rather than a generic
// error or default page.
func usefulTitle(s ServiceInfo) string {
	t := strings.TrimSpace(s.Title)
	if t == "" || len([]rune(t)) > 60 || s.Status < 200 || s.Status >= 300 {
		return ""
	}
	l := strings.ToLower(t)
	for _, g := range []string{"welcome to nginx", "default page", "it works", "index of", "login", "error"} {
		if strings.Contains(l, g) {
			return ""
		}
	}
	return t
}

// mergeNames appends add to base without repeating a name (case-insensitive).
func mergeNames(base, add []Name) []Name {
	seen := map[string]bool{}
	out := make([]Name, 0, len(base)+len(add))
	for _, n := range append(append([]Name{}, base...), add...) {
		k := strings.ToLower(n.Name)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, n)
	}
	return out
}
