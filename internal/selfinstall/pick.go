package selfinstall

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"hestia/internal/proxmox"
)

// Defaults of the controller container.
const (
	DefaultVMIDFrom = 900 // service guests of Hestia live in 900+
	DefaultHostname = "hestia"
	DefaultCores    = 1
	DefaultMemoryMB = 512
	DefaultSwapMB   = 512
	DefaultDiskGB   = 4
	DefaultPort     = 80
	FallbackPort    = 8080
	templatePackage = "debian-13-standard"
)

// PickTemplate returns the newest "debian-13-standard" amd64 template of the
// official "system" section. TurnKey and other images are never chosen.
func PickTemplate(apl []proxmox.AplTemplate) (proxmox.AplTemplate, bool) {
	var best proxmox.AplTemplate
	found := false
	for _, a := range apl {
		if a.Section != "system" || a.Package != templatePackage || a.Architecture != "amd64" || a.Type != "lxc" {
			continue
		}
		if !found || versionLess(best.Version, a.Version) {
			best, found = a, true
		}
	}
	return best, found
}

// versionLess compares versions like "13.6-1" numerically by segment.
func versionLess(a, b string) bool {
	split := func(s string) []int {
		var out []int
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' }) {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	x, y := split(a), split(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var xi, yi int
		if i < len(x) {
			xi = x[i]
		}
		if i < len(y) {
			yi = y[i]
		}
		if xi != yi {
			return xi < yi
		}
	}
	return false
}

// FirstFreeVMID returns the first VMID >= from not used by any guest or
// template of the cluster.
func FirstFreeVMID(res []proxmox.Resource, from int) int {
	used := map[int]bool{}
	for _, r := range res {
		if r.VMID > 0 {
			used[r.VMID] = true
		}
	}
	id := from
	for used[id] {
		id++
	}
	return id
}

// VMIDUsed reports whether any guest or template has the VMID.
func VMIDUsed(res []proxmox.Resource, vmid int) bool {
	for _, r := range res {
		if r.VMID == vmid {
			return true
		}
	}
	return false
}

// PickNode returns the candidate node with the largest share of free RAM
// (ties: by name). Nodes missing from res or not online are skipped; "" if none.
func PickNode(res []proxmox.Resource, candidates []string) string {
	want := map[string]bool{}
	for _, c := range candidates {
		want[c] = true
	}
	best, bestFree := "", -1.0
	names := []string{}
	byName := map[string]proxmox.Resource{}
	for _, r := range res {
		if r.Type == "node" && r.Status == "online" && want[r.Node] && r.MaxMem > 0 {
			names = append(names, r.Node)
			byName[r.Node] = r
		}
	}
	sort.Strings(names)
	for _, n := range names {
		r := byName[n]
		free := float64(r.MaxMem-r.Mem) / float64(r.MaxMem)
		if free > bestFree {
			best, bestFree = n, free
		}
	}
	return best
}

// hasContent reports whether a storage "content" list ("iso,vztmpl") has kind.
func hasContent(content, kind string) bool {
	for _, c := range strings.Split(content, ",") {
		if strings.TrimSpace(c) == kind {
			return true
		}
	}
	return false
}

// usable: enabled and active.
func usable(e proxmox.NodeStorageEntry) bool { return e.Enabled != 0 && e.Active != 0 }

// RootStorages lists the active storages that can hold container disks, most
// free space first.
func RootStorages(entries []proxmox.NodeStorageEntry) []proxmox.NodeStorageEntry {
	var out []proxmox.NodeStorageEntry
	for _, e := range entries {
		if usable(e) && hasContent(e.Content, "rootdir") {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Avail > out[j].Avail })
	return out
}

// PickRootStorage returns "local-lvm" if it can hold container disks and has
// room for diskGB, otherwise the rootdir storage with the most free space
// that still fits ("" if none).
func PickRootStorage(entries []proxmox.NodeStorageEntry, diskGB int) string {
	need := int64(diskGB) << 30
	roots := RootStorages(entries)
	for _, e := range roots {
		if e.Storage == "local-lvm" && e.Avail >= need {
			return e.Storage
		}
	}
	for _, e := range roots {
		if e.Avail >= need {
			return e.Storage
		}
	}
	return ""
}

// PickTemplateStorage returns "local" if it holds templates, otherwise the
// vztmpl storage with the most free space ("" if none).
func PickTemplateStorage(entries []proxmox.NodeStorageEntry) string {
	best := ""
	var bestAvail int64 = -1
	for _, e := range entries {
		if !usable(e) || !hasContent(e.Content, "vztmpl") {
			continue
		}
		if e.Storage == "local" {
			return e.Storage
		}
		if e.Avail > bestAvail {
			best, bestAvail = e.Storage, e.Avail
		}
	}
	return best
}

// Bridges returns the names of the node's bridges and the default one:
// "vmbr0" if present, otherwise the first.
func Bridges(nets []proxmox.NetIface) (names []string, def string) {
	for _, n := range nets {
		if n.Type == "bridge" || n.Type == "OVSBridge" {
			names = append(names, n.Iface)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if n == "vmbr0" {
			return names, n
		}
	}
	if len(names) > 0 {
		def = names[0]
	}
	return names, def
}

// BridgeGateway is the gateway configured on the bridge ("" if none).
func BridgeGateway(nets []proxmox.NetIface, bridge string) string {
	for _, n := range nets {
		if n.Iface == bridge {
			return n.Gateway
		}
	}
	return ""
}

// templateVolID is the volume id of a template in a storage.
func templateVolID(storage, template string) string { return storage + ":vztmpl/" + template }

// hostURL builds http://host[:port]; port 80 is omitted.
func hostURL(host string, port int) string {
	if port == 0 || port == DefaultPort {
		if strings.Contains(host, ":") {
			return "http://[" + host + "]"
		}
		return "http://" + host
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}
