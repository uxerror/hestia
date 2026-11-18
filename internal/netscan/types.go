// Package netscan finds the devices and services of the home network:
// TCP connect discovery of the subnets of connected systems, banner and HTTP
// fingerprints, vendor lookup by MAC, and the job/scheduler around it.
// Read-only: no logins, no POST, only TCP connects, banners and GET requests
// for a fixed list of paths.
package netscan

import "time"

// Host sources.
const (
	SourceScan      = "scan"
	SourceInventory = "inventory" // known from Proxmox, did not answer the scan
)

// Service categories.
const (
	CatInfra      = "infra"
	CatNetwork    = "network"
	CatStorage    = "storage"
	CatMedia      = "media"
	CatDev        = "dev"
	CatMonitoring = "monitoring"
	CatHome       = "home"
	CatDB         = "db"
	CatRemote     = "remote"
	CatOther      = "other"
)

// Name is a name of a host with the place it came from.
type Name struct {
	Name   string `json:"name"`
	Source string `json:"source"` // ptr | inventory | cert | title
}

// CertInfo is what is kept of a TLS certificate.
type CertInfo struct {
	CN         string    `json:"cn"`
	SAN        []string  `json:"san"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
}

// ServiceInfo is a service found on an open port. Bodies of responses are not
// kept: only this digest.
type ServiceInfo struct {
	Port     int       `json:"port"`
	Proto    string    `json:"proto"` // http | https | ssh | banner | tcp
	Rule     string    `json:"rule"`
	Name     string    `json:"name"`
	Category string    `json:"category"`
	Version  string    `json:"version,omitempty"`
	OS       string    `json:"os,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	URL      string    `json:"url,omitempty"`
	Title    string    `json:"title,omitempty"`
	Server   string    `json:"server,omitempty"`
	Status   int       `json:"status,omitempty"`
	Location string    `json:"location,omitempty"`
	Cookies  []string  `json:"cookies,omitempty"` // names only
	Cert     *CertInfo `json:"cert,omitempty"`
}

// Link ties a host to the Proxmox inventory.
type Link struct {
	Kind      string `json:"kind"` // node | guest
	TargetID  int64  `json:"target_id"`
	Target    string `json:"target"`
	Node      string `json:"node"`
	VMID      int    `json:"vmid,omitempty"`
	Name      string `json:"name,omitempty"`
	GuestType string `json:"guest_type,omitempty"` // qemu | lxc
	Status    string `json:"status,omitempty"`     // running | stopped | …
}

// Host is a device of the network.
type Host struct {
	IP         string        `json:"ip"`
	MAC        string        `json:"mac"`
	Vendor     string        `json:"vendor"`
	RandomMAC  bool          `json:"random_mac"`
	Names      []Name        `json:"names"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	LastScanID int64         `json:"last_scan_id"`
	Alive      bool          `json:"alive"`
	Source     string        `json:"source"`
	Ports      []int         `json:"ports"`
	Services   []ServiceInfo `json:"services"`
	Link       *Link         `json:"link"`
	// NoResponse: the inventory says the guest runs, but it did not answer on
	// any scanned port.
	NoResponse bool `json:"no_response"`
}

// SubnetInfo is a subnet to scan and where it came from.
type SubnetInfo struct {
	CIDR   string `json:"cidr"`
	Source string `json:"source"` // proxmox | ssh | manual
	Label  string `json:"label"`
	// Gateway is the router of the subnet, if a system reports it.
	Gateway string `json:"gateway,omitempty"`
	// Error is set for a subnet that is not scanned (for example too large).
	Error string `json:"error,omitempty"`
}

// Stats is the summary of a finished scan.
type Stats struct {
	Subnets    int   `json:"subnets"`
	Addresses  int   `json:"addresses"`
	Alive      int   `json:"alive"`
	Services   int   `json:"services"`
	DurationMS int64 `json:"duration_ms"`
}

// Scan is a record of a scan run.
type Scan struct {
	ID         int64      `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Subnets    []string   `json:"subnets"`
	Stats      Stats      `json:"stats"`
	Error      string     `json:"error"`
}
