package netscan

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	"hestia/internal/netscan/oui"
)

// ARP gives access to the neighbour table of the machine Hestia runs on.
type ARP interface {
	// Table returns the complete entries (IP → MAC). An error means the table
	// is unavailable (no MACs, no ARP-based liveness).
	Table() (map[netip.Addr]string, error)
	// Local reports whether the machine has an interface in the subnet: only
	// then the table says anything about its hosts.
	Local(p netip.Prefix) bool
}

// ParseARP parses the format of /proc/net/arp and keeps the entries with the
// "complete" flag (0x2) and a real MAC.
func ParseARP(r io.Reader) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		mac := oui.Normalize(f[3])
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		out[ip] = mac
	}
	return out
}

// SystemARP reads /proc/net/arp (Linux only; elsewhere it is unavailable).
type SystemARP struct {
	Path string // default /proc/net/arp
}

func (s SystemARP) Table() (map[netip.Addr]string, error) {
	if runtime.GOOS != "linux" && s.Path == "" {
		return nil, os.ErrNotExist
	}
	path := s.Path
	if path == "" {
		path = "/proc/net/arp"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseARP(f), nil
}

func (s SystemARP) Local(p netip.Prefix) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && p.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}
