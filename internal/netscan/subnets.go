package netscan

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
)

// MaxPrefixBits is the widest subnet that is scanned: /22 (1022 hosts).
const MaxPrefixBits = 22

// MaxManualSubnets bounds the list of subnets added by hand.
const MaxManualSubnets = 16

// ParseSubnet validates an IPv4 subnet ("10.10.10.50/24" or "10.10.10.0/24")
// and returns it with the host bits cleared. Subnets wider than /22,
// loopback, link-local and multicast ranges are refused.
func ParseSubnet(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("«%s» — не подсеть (нужен вид 10.0.0.0/24)", s)
	}
	a := p.Addr().Unmap()
	if !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("«%s»: поддерживается только IPv4", s)
	}
	p = netip.PrefixFrom(a, p.Bits()).Masked()
	if p.Bits() < MaxPrefixBits {
		return netip.Prefix{}, fmt.Errorf("подсеть %s больше /%d — сканировать такую сеть слишком долго", p, MaxPrefixBits)
	}
	if err := checkScannable(p.Addr()); err != nil {
		return netip.Prefix{}, fmt.Errorf("подсеть %s: %w", p, err)
	}
	return p, nil
}

func checkScannable(a netip.Addr) error {
	switch {
	case a.IsLoopback():
		return errors.New("петлевой адрес не сканируется")
	case a.IsLinkLocalUnicast():
		return errors.New("адреса link-local не сканируются")
	case a.IsMulticast(), a.IsUnspecified():
		return errors.New("недопустимый диапазон")
	}
	return nil
}

// Exclusion is a set of addresses and subnets left out of the scan.
type Exclusion struct {
	prefixes []netip.Prefix
}

// ParseExclusion parses entries that are single IPs or subnets (any size).
func ParseExclusion(list []string) (Exclusion, []string, error) {
	var ex Exclusion
	var canon []string
	seen := map[string]bool{}
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(raw, "/") {
			q, err := netip.ParsePrefix(raw)
			if err != nil || !q.Addr().Unmap().Is4() {
				return Exclusion{}, nil, fmt.Errorf("исключение «%s»: нужен IPv4-адрес или подсеть", raw)
			}
			p = netip.PrefixFrom(q.Addr().Unmap(), q.Bits()).Masked()
		} else {
			a, err := netip.ParseAddr(raw)
			if err != nil || !a.Unmap().Is4() {
				return Exclusion{}, nil, fmt.Errorf("исключение «%s»: нужен IPv4-адрес или подсеть", raw)
			}
			p = netip.PrefixFrom(a.Unmap(), 32)
		}
		c := p.String()
		if p.Bits() == 32 {
			c = p.Addr().String()
		}
		if !seen[c] {
			seen[c] = true
			ex.prefixes = append(ex.prefixes, p)
			canon = append(canon, c)
		}
	}
	return ex, canon, nil
}

// Contains reports whether the address is excluded.
func (e Exclusion) Contains(a netip.Addr) bool {
	for _, p := range e.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Hosts lists the scanned addresses of a subnet: all but the network and the
// broadcast address (/31 and /32 have no such addresses).
func Hosts(p netip.Prefix, ex Exclusion) []netip.Addr {
	var out []netip.Addr
	first := p.Masked().Addr()
	for a := first; a.IsValid() && p.Contains(a); a = a.Next() {
		if p.Bits() <= 30 && (a == first || !p.Contains(a.Next())) {
			continue
		}
		if ex.Contains(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// SortedPrefixes orders prefixes by address.
func SortedPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

func shuffle[T any](s []T) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}
