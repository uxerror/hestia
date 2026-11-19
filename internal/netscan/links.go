package netscan

import (
	"context"
	"net/netip"
	"strings"

	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/netscan/oui"
	"github.com/uxerror/hestia/internal/store"
)

// linkIndex finds the Proxmox node or guest behind an address or MAC.
type linkIndex struct {
	byIP  map[string]*Link
	byMAC map[string]*Link
	macs  map[*Link][]string // guest → its MACs
	empty bool
}

// buildIndex reads the inventory snapshots; targets maps a target id to its name.
func buildIndex(entries []inventory.Entry, targets map[int64]string) *linkIndex {
	ix := &linkIndex{byIP: map[string]*Link{}, byMAC: map[string]*Link{}, macs: map[*Link][]string{}, empty: true}
	for _, e := range entries {
		if e.Snapshot == nil {
			continue
		}
		ix.empty = false
		tname := targets[e.TargetID]
		for _, n := range e.Snapshot.Nodes {
			if n.IP == "" {
				continue
			}
			st := "offline"
			if n.Online {
				st = "online"
			}
			ix.byIP[n.IP] = &Link{Kind: "node", TargetID: e.TargetID, Target: tname, Node: n.Name, Name: n.Name, Status: st}
		}
		for _, g := range e.Snapshot.Guests {
			if g.Template {
				continue
			}
			l := &Link{Kind: "guest", TargetID: e.TargetID, Target: tname, Node: g.Node, VMID: g.VMID, Name: g.Name, GuestType: g.Type, Status: g.Status}
			for _, ip := range g.IPs {
				if _, taken := ix.byIP[ip]; !taken {
					ix.byIP[ip] = l
				}
			}
			for _, m := range g.MACs {
				if m = oui.Normalize(m); m != "" {
					ix.byMAC[m] = l
					ix.macs[l] = append(ix.macs[l], m)
				}
			}
		}
	}
	return ix
}

// lookup finds the link by address, then by MAC.
func (ix *linkIndex) lookup(ip, mac string) *Link {
	if l, ok := ix.byIP[ip]; ok {
		c := *l
		return &c
	}
	if mac != "" {
		if l, ok := ix.byMAC[mac]; ok {
			c := *l
			return &c
		}
	}
	return nil
}

// ownMAC is the only MAC of a guest, if it has exactly one.
func (ix *linkIndex) ownMAC(ip string) string {
	if l, ok := ix.byIP[ip]; ok && l.Kind == "guest" {
		if ms := ix.macs[l]; len(ms) == 1 {
			return ms[0]
		}
	}
	return ""
}

// inventoryHosts are the running guests and online nodes known from Proxmox
// whose address is not among the hosts: they did not answer the scan.
func (ix *linkIndex) missing(have map[string]bool) []Host {
	var out []Host
	for ip, l := range ix.byIP {
		if have[ip] {
			continue
		}
		if a, err := netip.ParseAddr(ip); err != nil || !a.Unmap().Is4() {
			continue
		}
		if (l.Kind == "guest" && l.Status != "running") || (l.Kind == "node" && l.Status != "online") {
			continue
		}
		lc := *l
		out = append(out, Host{
			IP: ip, Names: []Name{{Name: l.Name, Source: SourceInventory}}, Source: SourceInventory,
			Ports: []int{}, Services: []ServiceInfo{}, Link: &lc, NoResponse: true,
		})
	}
	return out
}

func (m *Manager) loadIndex(ctx context.Context) *linkIndex {
	var entries []inventory.Entry
	if m.Inventory != nil {
		if es, err := m.Inventory.List(ctx); err == nil {
			entries = es
		}
	}
	names := map[int64]string{}
	if ts, err := m.Store.ListTargets(ctx); err == nil {
		for _, t := range ts {
			names[t.ID] = t.Name
		}
	}
	return buildIndex(entries, names)
}

// subnetsFromInventory lists the subnets reported by the snapshots.
func subnetsFromInventory(entries []inventory.Entry, targets map[int64]store.Target) []SubnetInfo {
	var out []SubnetInfo
	for _, e := range entries {
		if e.Snapshot == nil {
			continue
		}
		t := targets[e.TargetID]
		src := "proxmox"
		if t.Kind == store.KindSSH {
			src = "ssh"
		}
		for _, s := range e.Snapshot.Subnets {
			label := strings.TrimSpace(s.Node + " · " + s.Iface)
			if t.Name != "" && t.Name != s.Node {
				label = t.Name + " · " + label
			}
			out = append(out, SubnetInfo{CIDR: s.CIDR, Source: src, Label: label, Gateway: s.Gateway})
		}
	}
	return out
}
