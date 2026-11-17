package proxmox

import (
	"context"
	"net/url"
	"strconv"
)

// Resource is an entry of GET /cluster/resources (node, storage, qemu, lxc, …).
type Resource struct {
	Type     string  `json:"type"`
	ID       string  `json:"id"`
	Node     string  `json:"node"`
	Name     string  `json:"name"`
	VMID     int     `json:"vmid"`
	Status   string  `json:"status"`
	CPU      float64 `json:"cpu"`
	MaxCPU   float64 `json:"maxcpu"`
	Mem      int64   `json:"mem"`
	MaxMem   int64   `json:"maxmem"`
	Disk     int64   `json:"disk"`
	MaxDisk  int64   `json:"maxdisk"`
	Uptime   int64   `json:"uptime"`
	Tags     string  `json:"tags"`
	Template int     `json:"template"`
	Storage  string  `json:"storage"`
	Content  string  `json:"content"`
	Shared   int     `json:"shared"`
	PlugType string  `json:"plugintype"`
}

// ClusterEntry is an entry of GET /cluster/status: the cluster itself
// (type "cluster") or one of its nodes (type "node").
type ClusterEntry struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Online  int    `json:"online"`
	Local   int    `json:"local"`
	Nodes   int    `json:"nodes"`
	Quorate int    `json:"quorate"`
}

// NodeStatus is GET /nodes/{node}/status.
type NodeStatus struct {
	CPU     float64 `json:"cpu"`
	CPUInfo struct {
		Model   string `json:"model"`
		Sockets int    `json:"sockets"`
		Cores   int    `json:"cores"`
		CPUs    int    `json:"cpus"`
	} `json:"cpuinfo"`
	LoadAvg []string `json:"loadavg"`
	Memory  struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"memory"`
	Swap struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"swap"`
	RootFS struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"rootfs"`
	Uptime        int64  `json:"uptime"`
	PVEVersion    string `json:"pveversion"`
	CurrentKernel struct {
		Release string `json:"release"`
	} `json:"current-kernel"`
}

// NodeStorageEntry is an entry of GET /nodes/{node}/storage.
type NodeStorageEntry struct {
	Storage string `json:"storage"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Active  int    `json:"active"`
	Enabled int    `json:"enabled"`
	Shared  int    `json:"shared"`
	Total   int64  `json:"total"`
	Used    int64  `json:"used"`
	Avail   int64  `json:"avail"`
}

// Iface is a network interface of a guest. LXC reports Inet/Inet6 ("addr/prefix"),
// the QEMU guest agent reports IPAddresses.
type Iface struct {
	Name        string `json:"name"`
	Inet        string `json:"inet"`
	Inet6       string `json:"inet6"`
	IPAddresses []struct {
		Address string `json:"ip-address"`
		Type    string `json:"ip-address-type"`
	} `json:"ip-addresses"`
}

// ClusterResources returns nodes, storages, VMs and containers in one call.
func (c *Client) ClusterResources(ctx context.Context) ([]Resource, error) {
	var r []Resource
	return r, c.get(ctx, "/cluster/resources", &r)
}

// ClusterStatus returns the cluster name, quorum and node addresses.
func (c *Client) ClusterStatus(ctx context.Context) ([]ClusterEntry, error) {
	var r []ClusterEntry
	return r, c.get(ctx, "/cluster/status", &r)
}

// NodeStatus returns hardware and load of one node.
func (c *Client) NodeStatus(ctx context.Context, node string) (NodeStatus, error) {
	var r NodeStatus
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/status", &r)
}

// NodeStorage lists the storages of one node.
func (c *Client) NodeStorage(ctx context.Context, node string) ([]NodeStorageEntry, error) {
	var r []NodeStorageEntry
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/storage", &r)
}

// LXCInterfaces returns the network interfaces of a running container.
func (c *Client) LXCInterfaces(ctx context.Context, node string, vmid int) ([]Iface, error) {
	var r []Iface
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/lxc/"+strconv.Itoa(vmid)+"/interfaces", &r)
}

// AgentInterfaces returns the interfaces reported by the QEMU guest agent of
// a running VM.
func (c *Client) AgentInterfaces(ctx context.Context, node string, vmid int) ([]Iface, error) {
	var r struct {
		Result []Iface `json:"result"`
	}
	err := c.get(ctx, "/nodes/"+url.PathEscape(node)+"/qemu/"+strconv.Itoa(vmid)+"/agent/network-get-interfaces", &r)
	return r.Result, err
}
