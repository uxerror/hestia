package inventory

import (
	"context"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"github.com/uxerror/hestia/internal/target"
)

// collectSSH gathers the facts of a standalone server over SSH with Hestia's
// key: the same facts as the connection probe plus CPU model, load and uptime.
func collectSSH(ctx context.Context, run progress, tg target.Target, host string) (*Snapshot, error) {
	snap := &Snapshot{Kind: "ssh", Nodes: []Node{}, Storages: []Storage{}, Guests: []Guest{}, Subnets: []Subnet{}, Warnings: []string{}}
	err := run.Step("Данные сервера", func(ctx context.Context) error {
		f, err := tg.Facts(ctx)
		if err != nil {
			return err
		}
		n := Node{
			Name: f.Hostname, IP: host, Online: true, Threads: f.CPUs, Kernel: f.Kernel, OS: f.OS, Docker: f.Docker,
			MemTotal: f.MemTotal, MemUsed: f.MemTotal - f.MemAvail,
		}
		if n.Name == "" {
			n.Name = host
		}
		if f.MemTotal == 0 {
			n.MemUsed = 0
		}
		if d, ok := rootDisk(f.Disks); ok {
			n.RootFSTotal, n.RootFSUsed = d.Size, d.Used
		}
		// Best effort: a missing file or command leaves the field empty.
		if r, err := tg.Exec(ctx, "grep -m1 'model name' /proc/cpuinfo"); err == nil {
			if _, v, ok := strings.Cut(r.Stdout, ":"); ok {
				n.CPUModel = strings.TrimSpace(v)
			}
		}
		if r, err := tg.Exec(ctx, "cat /proc/loadavg"); err == nil {
			n.Load1, n.Load5, n.Load15 = parseLoadAvg(r.Stdout)
		}
		if r, err := tg.Exec(ctx, "cat /proc/uptime"); err == nil {
			if f := strings.Fields(r.Stdout); len(f) > 0 {
				if v, err := strconv.ParseFloat(f[0], 64); err == nil {
					n.Uptime = int64(v)
				}
			}
		}
		if n.Threads > 0 {
			n.CPUUsage = clamp01(n.Load1 / float64(n.Threads))
		}
		snap.Nodes = append(snap.Nodes, n)
		// Best effort: the subnets of the server's interfaces (for the network scan).
		if r, err := tg.Exec(ctx, "ip -4 -j addr"); err == nil {
			snap.Subnets = parseIPAddr(n.Name, r.Stdout)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

func rootDisk(disks []target.Disk) (target.Disk, bool) {
	var best target.Disk
	found := false
	for _, d := range disks {
		if d.Mount == "/" {
			return d, true
		}
		if !found || d.Size > best.Size {
			best, found = d, true
		}
	}
	return best, found
}

func parseLoadAvg(s string) (l1, l5, l15 float64) {
	f := strings.Fields(s)
	if len(f) < 3 {
		return
	}
	l1, _ = strconv.ParseFloat(f[0], 64)
	l5, _ = strconv.ParseFloat(f[1], 64)
	l15, _ = strconv.ParseFloat(f[2], 64)
	return
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

// parseIPAddr reads `ip -4 -j addr`: the subnets of the real interfaces
// (no loopback, link-local or container bridges).
func parseIPAddr(node, out string) []Subnet {
	var ifs []struct {
		Name string `json:"ifname"`
		Addr []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	subs := []Subnet{}
	if json.Unmarshal([]byte(out), &ifs) != nil {
		return subs
	}
	for _, f := range ifs {
		if skipIface(f.Name) {
			continue
		}
		for _, a := range f.Addr {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || a.Scope == "host" {
				continue
			}
			subs = append(subs, Subnet{Node: node, Iface: f.Name, CIDR: netip.PrefixFrom(ip, a.Prefix).String()})
		}
	}
	return subs
}
