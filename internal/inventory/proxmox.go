package inventory

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uxerror/hestia/internal/netscan/oui"
	"github.com/uxerror/hestia/internal/proxmox"
)

// API is the part of the Proxmox API client the collector uses.
type API interface {
	ClusterResources(ctx context.Context) ([]proxmox.Resource, error)
	ClusterStatus(ctx context.Context) ([]proxmox.ClusterEntry, error)
	NodeStatus(ctx context.Context, node string) (proxmox.NodeStatus, error)
	NodeStorage(ctx context.Context, node string) ([]proxmox.NodeStorageEntry, error)
	LXCInterfaces(ctx context.Context, node string, vmid int) ([]proxmox.Iface, error)
	AgentInterfaces(ctx context.Context, node string, vmid int) ([]proxmox.Iface, error)
	Network(ctx context.Context, node string) ([]proxmox.NetIface, error)
}

// progress is the part of *jobs.Run the collectors use.
type progress interface {
	Step(title string, fn func(ctx context.Context) error) error
	Log(level, line string)
}

const (
	// MaxParallelIPLookups bounds concurrent guest IP requests.
	MaxParallelIPLookups = 8
	// DefaultReqTimeout is the timeout of a single API request.
	DefaultReqTimeout = 5 * time.Second
)

type proxmoxCollector struct {
	api        API
	run        progress
	reqTimeout time.Duration
	fallback   string // cluster name stored with the target
}

func (c *proxmoxCollector) req(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.reqTimeout)
}

// collectProxmox builds a snapshot from the API. Only a failure of the cluster
// resources request fails the collection; everything else degrades into
// warnings or per-guest IP errors.
func collectProxmox(ctx context.Context, api API, run progress, reqTimeout time.Duration, clusterName string) (*Snapshot, error) {
	if reqTimeout <= 0 {
		reqTimeout = DefaultReqTimeout
	}
	c := &proxmoxCollector{api: api, run: run, reqTimeout: reqTimeout, fallback: clusterName}
	snap := &Snapshot{Kind: "proxmox", Nodes: []Node{}, Storages: []Storage{}, Guests: []Guest{}, Subnets: []Subnet{}, Warnings: []string{}}
	if err := run.Step("Узлы и хранилища", func(ctx context.Context) error { return c.structure(ctx, snap) }); err != nil {
		return nil, err
	}
	if err := run.Step("IP гостей", func(ctx context.Context) error { c.ips(ctx, snap); return nil }); err != nil {
		return nil, err
	}
	return snap, nil
}

func (c *proxmoxCollector) warn(snap *Snapshot, msg string) {
	snap.Warnings = append(snap.Warnings, msg)
	c.run.Log("warn", msg)
}

func (c *proxmoxCollector) structure(ctx context.Context, snap *Snapshot) error {
	rctx, cancel := c.req(ctx)
	res, err := c.api.ClusterResources(rctx)
	cancel()
	if err != nil {
		return err
	}

	snap.Cluster = c.fallback
	ips := map[string]string{}
	rctx, cancel = c.req(ctx)
	status, err := c.api.ClusterStatus(rctx)
	cancel()
	if err != nil {
		c.warn(snap, "Состояние кластера недоступно: "+err.Error())
	}
	for _, e := range status {
		switch e.Type {
		case "cluster":
			snap.Clustered, snap.Quorate = true, e.Quorate != 0
			if e.Name != "" {
				snap.Cluster = e.Name
			}
		case "node":
			ips[e.Name] = e.IP
		}
	}

	byNode := map[string]*Node{}
	resStorages := map[string][]proxmox.Resource{} // fallback for offline nodes
	for _, r := range res {
		switch r.Type {
		case "node":
			snap.Nodes = append(snap.Nodes, Node{
				Name: r.Node, IP: ips[r.Node], Online: r.Status == "online", CPUUsage: r.CPU,
				Threads: int(r.MaxCPU), MemUsed: r.Mem, MemTotal: r.MaxMem,
				RootFSUsed: r.Disk, RootFSTotal: r.MaxDisk, Uptime: r.Uptime,
			})
		case "storage":
			resStorages[r.Node] = append(resStorages[r.Node], r)
		case "qemu", "lxc":
			snap.Guests = append(snap.Guests, Guest{
				VMID: r.VMID, Type: r.Type, Name: r.Name, Node: r.Node, Status: r.Status,
				Template: r.Template != 0, Tags: splitTags(r.Tags), CPUs: int(r.MaxCPU), CPUUsage: r.CPU,
				MemUsed: r.Mem, MemTotal: r.MaxMem, DiskUsed: r.Disk, DiskTotal: r.MaxDisk, Uptime: r.Uptime,
				IPs: []string{}, MACs: []string{}, IPSource: IPSourceNone,
			})
		}
	}
	sort.Slice(snap.Nodes, func(i, j int) bool { return snap.Nodes[i].Name < snap.Nodes[j].Name })
	sort.Slice(snap.Guests, func(i, j int) bool { return snap.Guests[i].VMID < snap.Guests[j].VMID })
	for i := range snap.Nodes {
		byNode[snap.Nodes[i].Name] = &snap.Nodes[i]
	}

	var b storageBuilder
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if !n.Online {
			c.warn(snap, "Узел "+n.Name+" не в сети — данные неполные")
			b.addResources(n.Name, resStorages[n.Name])
			continue
		}
		rctx, cancel := c.req(ctx)
		ns, err := c.api.NodeStatus(rctx, n.Name)
		cancel()
		if err != nil {
			c.warn(snap, "Узел "+n.Name+": состояние недоступно: "+err.Error())
		} else {
			applyNodeStatus(n, ns)
			if snap.Version == "" {
				snap.Version = n.PVEVersion
			}
		}
		rctx, cancel = c.req(ctx)
		nets, err := c.api.Network(rctx, n.Name)
		cancel()
		if err != nil {
			c.warn(snap, "Узел "+n.Name+": сетевые интерфейсы недоступны: "+err.Error())
		} else {
			snap.Subnets = append(snap.Subnets, bridgeSubnets(n.Name, nets)...)
		}
		rctx, cancel = c.req(ctx)
		st, err := c.api.NodeStorage(rctx, n.Name)
		cancel()
		if err != nil {
			c.warn(snap, "Узел "+n.Name+": хранилища недоступны: "+err.Error())
			b.addResources(n.Name, resStorages[n.Name])
			continue
		}
		b.addNode(n.Name, st)
	}
	// Storages of nodes that are not in the node list at all (should not happen).
	for node, rs := range resStorages {
		if byNode[node] == nil {
			b.addResources(node, rs)
		}
	}
	snap.Storages = b.result()
	if !snap.Clustered {
		snap.Cluster = ""
	}
	return nil
}

func applyNodeStatus(n *Node, ns proxmox.NodeStatus) {
	n.CPUModel = ns.CPUInfo.Model
	n.Sockets, n.Cores = ns.CPUInfo.Sockets, ns.CPUInfo.Cores
	if ns.CPUInfo.CPUs > 0 {
		n.Threads = ns.CPUInfo.CPUs
	}
	n.CPUUsage = ns.CPU
	for i, p := range []*float64{&n.Load1, &n.Load5, &n.Load15} {
		if i < len(ns.LoadAvg) {
			*p, _ = strconv.ParseFloat(ns.LoadAvg[i], 64)
		}
	}
	n.MemUsed, n.MemTotal = ns.Memory.Used, ns.Memory.Total
	n.SwapUsed, n.SwapTotal = ns.Swap.Used, ns.Swap.Total
	n.RootFSUsed, n.RootFSTotal = ns.RootFS.Used, ns.RootFS.Total
	n.Uptime = ns.Uptime
	n.Kernel = ns.CurrentKernel.Release
	n.PVEVersion = pveVersion(ns.PVEVersion)
}

// pveVersion turns "pve-manager/9.2.10/43df2e01f27a1a19" into "9.2.10".
func pveVersion(s string) string {
	parts := strings.Split(s, "/")
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "pve-manager") {
		return parts[1]
	}
	return s
}

func splitTags(s string) []string {
	out := []string{}
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' }) {
		out = append(out, t)
	}
	return out
}

// storageBuilder merges per-node storage lists: a shared storage appears once
// for the whole cluster, a local one once per node.
type storageBuilder struct {
	list   []Storage
	shared map[string]int // name → index in list
}

func (b *storageBuilder) add(node string, s Storage) {
	if s.Shared {
		if b.shared == nil {
			b.shared = map[string]int{}
		}
		if i, ok := b.shared[s.Name]; ok {
			cur := &b.list[i]
			cur.Nodes = append(cur.Nodes, node)
			cur.Active = cur.Active || s.Active
			if cur.Total == 0 { // a node that could not read it reports zeros
				cur.Used, cur.Total = s.Used, s.Total
			}
			return
		}
		b.shared[s.Name] = len(b.list)
	}
	s.Nodes = []string{node}
	b.list = append(b.list, s)
}

func (b *storageBuilder) addNode(node string, in []proxmox.NodeStorageEntry) {
	for _, e := range in {
		if e.Enabled == 0 && e.Total == 0 && e.Active == 0 && e.Type == "" {
			continue
		}
		b.add(node, Storage{Name: e.Storage, Type: e.Type, Content: splitTags(e.Content), Shared: e.Shared != 0,
			Active: e.Active != 0, Used: e.Used, Total: e.Total})
	}
}

func (b *storageBuilder) addResources(node string, in []proxmox.Resource) {
	for _, r := range in {
		b.add(node, Storage{Name: r.Storage, Type: r.PlugType, Content: splitTags(r.Content), Shared: r.Shared != 0,
			Active: r.Status == "available", Used: r.Disk, Total: r.MaxDisk})
	}
}

func (b *storageBuilder) result() []Storage {
	out := b.list
	if out == nil {
		out = []Storage{}
	}
	for i := range out {
		sort.Strings(out[i].Nodes)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return strings.Join(out[i].Nodes, ",") < strings.Join(out[j].Nodes, ",")
	})
	return out
}

// ips looks up guest addresses with bounded parallelism. A failure of one
// guest only sets its ip_source to "none" and records the reason.
func (c *proxmoxCollector) ips(ctx context.Context, snap *Snapshot) {
	var forbidden atomic.Bool
	sem := make(chan struct{}, MaxParallelIPLookups)
	var wg sync.WaitGroup
	for i := range snap.Guests {
		g := &snap.Guests[i]
		switch {
		case g.Template:
			g.IPError = "шаблон"
			continue
		case g.Status != "running":
			g.IPError = "гость остановлен"
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rctx, cancel := c.req(ctx)
			defer cancel()
			var ifs []proxmox.Iface
			var err error
			src := IPSourceLXC
			if g.Type == "lxc" {
				ifs, err = c.api.LXCInterfaces(rctx, g.Node, g.VMID)
			} else {
				src = IPSourceAgent
				ifs, err = c.api.AgentInterfaces(rctx, g.Node, g.VMID)
			}
			if err != nil {
				var ae *proxmox.APIError
				if src == IPSourceAgent && errors.As(err, &ae) && ae.Status == 403 {
					forbidden.Store(true)
				}
				g.IPError = ipError(err, src)
				return
			}
			g.IPs = guestIPs(ifs)
			g.MACs = guestMACs(ifs)
			g.IPSource = src
		}()
	}
	wg.Wait()
	if forbidden.Load() {
		snap.NeedsAgentPriv = true
		c.warn(snap, "Роль Hestia не позволяет читать данные гостевого агента — не хватает "+proxmox.GuestAgentPriv)
	}
}

// ipError turns a failed lookup into a short reason. Agent failures are the
// normal state of VMs without the agent and are not errors of the inventory.
func ipError(err error, src string) string {
	var ae *proxmox.APIError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "таймаут запроса"
	case errors.As(err, &ae) && ae.Status == 403:
		return "нет права " + proxmox.GuestAgentPriv
	case errors.As(err, &ae) && ae.Detail != "":
		return ae.Detail
	case errors.As(err, &ae):
		return "API вернул " + strconv.Itoa(ae.Status)
	case src == IPSourceAgent:
		return "гостевой агент недоступен"
	}
	return err.Error()
}

// virtualIfacePrefixes are container/VM bridges and veth pairs: their
// addresses are not the guest's address on the LAN.
var virtualIfacePrefixes = []string{"lo", "veth", "docker", "br-", "virbr", "cni", "flannel"}

func skipIface(name string) bool {
	for _, p := range virtualIfacePrefixes {
		if name == p || (p != "lo" && strings.HasPrefix(name, p)) {
			return true
		}
	}
	return false
}

// guestIPs picks usable addresses (no loopback, link-local or virtual
// bridges), IPv4 first.
func guestIPs(ifs []proxmox.Iface) []string {
	var v4, v6 []string
	seen := map[string]bool{}
	add := func(raw string) {
		raw, _, _ = strings.Cut(raw, "/")
		ip := net.ParseIP(raw)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	for _, f := range ifs {
		if skipIface(f.Name) {
			continue
		}
		if f.Inet != "" {
			add(f.Inet)
		}
		if f.Inet6 != "" {
			add(f.Inet6)
		}
		for _, a := range f.IPAddresses {
			add(a.Address)
		}
	}
	return append(append([]string{}, v4...), v6...)
}

// bridgeSubnets returns the IPv4 subnets of the active bridges of a node
// (GET /nodes/{n}/network, field cidr).
func bridgeSubnets(node string, nets []proxmox.NetIface) []Subnet {
	var out []Subnet
	for _, n := range nets {
		if n.Type != "bridge" && n.Type != "OVSBridge" {
			continue
		}
		if n.Active == 0 || n.CIDR == "" {
			continue
		}
		p, err := netip.ParsePrefix(n.CIDR)
		if err != nil || !p.Addr().Unmap().Is4() {
			continue
		}
		out = append(out, Subnet{Node: node, Iface: n.Iface, CIDR: n.CIDR, Gateway: n.Gateway})
	}
	return out
}

// guestMACs picks the hardware addresses of the real interfaces (no loopback
// or virtual bridges), normalised and without repeats.
func guestMACs(ifs []proxmox.Iface) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, f := range ifs {
		if skipIface(f.Name) {
			continue
		}
		raw := f.HWAddr
		if raw == "" {
			raw = f.HardwareAddress
		}
		mac := oui.Normalize(raw)
		if mac == "" || mac == "00:00:00:00:00:00" || seen[mac] {
			continue
		}
		seen[mac] = true
		out = append(out, mac)
	}
	return out
}
