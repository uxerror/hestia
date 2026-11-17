// Package inventory collects a read-only picture of every connected target
// (nodes, hardware, load, storages, guests with their IPs), keeps the last
// snapshot in the store and refreshes it on demand and, while somebody
// watches, periodically.
package inventory

import "time"

// Snapshot is the normalised inventory of one target.
type Snapshot struct {
	Kind      string    `json:"kind"` // proxmox | ssh
	Cluster   string    `json:"cluster"`
	Clustered bool      `json:"clustered"`
	Quorate   bool      `json:"quorate"`
	Version   string    `json:"version"`
	Nodes     []Node    `json:"nodes"`
	Storages  []Storage `json:"storages"`
	Guests    []Guest   `json:"guests"`
	// NeedsAgentPriv is set when the API refused guest agent calls (403): the
	// Hestia role lacks the privilege (see proxmox.PrivilegesFor).
	NeedsAgentPriv bool     `json:"needs_guest_agent_audit"`
	Warnings       []string `json:"warnings"`
}

// Node is a Proxmox node or a standalone server.
type Node struct {
	Name        string  `json:"name"`
	IP          string  `json:"ip"`
	Online      bool    `json:"online"`
	CPUModel    string  `json:"cpu_model"`
	Sockets     int     `json:"sockets"`
	Cores       int     `json:"cores"`
	Threads     int     `json:"threads"`
	CPUUsage    float64 `json:"cpu_usage"` // fraction 0..1
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	MemUsed     int64   `json:"mem_used"`
	MemTotal    int64   `json:"mem_total"`
	SwapUsed    int64   `json:"swap_used"`
	SwapTotal   int64   `json:"swap_total"`
	RootFSUsed  int64   `json:"rootfs_used"`
	RootFSTotal int64   `json:"rootfs_total"`
	Uptime      int64   `json:"uptime"` // seconds
	Kernel      string  `json:"kernel"`
	PVEVersion  string  `json:"pve_version,omitempty"`
	OS          string  `json:"os,omitempty"`
	Docker      bool    `json:"docker,omitempty"`
}

// Storage is a storage of a cluster: a shared one appears once with all the
// nodes that see it, a local one once per node.
type Storage struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Content []string `json:"content"`
	Shared  bool     `json:"shared"`
	Active  bool     `json:"active"`
	Used    int64    `json:"used"`
	Total   int64    `json:"total"`
	Nodes   []string `json:"nodes"`
}

// IP sources of a guest.
const (
	IPSourceLXC   = "lxc"
	IPSourceAgent = "agent"
	IPSourceNone  = "none"
)

// Guest is a VM (qemu) or a container (lxc).
type Guest struct {
	VMID      int      `json:"vmid"`
	Type      string   `json:"type"` // qemu | lxc
	Name      string   `json:"name"`
	Node      string   `json:"node"`
	Status    string   `json:"status"`
	Template  bool     `json:"template"`
	Tags      []string `json:"tags"`
	CPUs      int      `json:"cpus"`
	CPUUsage  float64  `json:"cpu_usage"` // fraction 0..1 of the guest's CPUs
	MemUsed   int64    `json:"mem_used"`
	MemTotal  int64    `json:"mem_total"`
	DiskUsed  int64    `json:"disk_used"`
	DiskTotal int64    `json:"disk_total"`
	Uptime    int64    `json:"uptime"`
	IPs       []string `json:"ips"`
	IPSource  string   `json:"ip_source"`
	IPError   string   `json:"ip_error"`
}

// Entry is what the API serves per target: the last snapshot plus its age.
type Entry struct {
	TargetID    int64      `json:"target_id"`
	CollectedAt *time.Time `json:"collected_at"`
	AgeSeconds  *int64     `json:"age_seconds"`
	Snapshot    *Snapshot  `json:"snapshot"`
	Error       string     `json:"error"`
	Collecting  bool       `json:"collecting"`
}
