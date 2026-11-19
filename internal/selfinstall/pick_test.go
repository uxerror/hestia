package selfinstall_test

import (
	"encoding/json"
	"testing"

	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/selfinstall"
)

func load[T any](t *testing.T, name string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(fixture(t, name), &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

// The fixtures are real outputs of a PVE 9.2 cluster (see testdata).

func TestPickTemplateFromRealAplinfo(t *testing.T) {
	apl := load[[]proxmox.AplTemplate](t, "aplinfo.json")
	if len(apl) < 100 {
		t.Fatalf("fixture too small: %d", len(apl))
	}
	tpl, ok := selfinstall.PickTemplate(apl)
	if !ok || tpl.Template != "debian-13-standard_13.6-1_amd64.tar.zst" || tpl.Version != "13.6-1" || tpl.Section != "system" {
		t.Fatalf("picked %+v", tpl)
	}
	// TurnKey images (also debian-13) and the arm64 build are never chosen.
	for _, a := range apl {
		if a.Template == tpl.Template {
			continue
		}
		if a.Package == "debian-13-standard" && a.Architecture == "amd64" {
			t.Fatalf("another amd64 candidate: %+v", a)
		}
	}
	only := []proxmox.AplTemplate{}
	for _, a := range apl {
		if a.Section == "turnkeylinux" || a.Architecture == "arm64" {
			only = append(only, a)
		}
	}
	if _, ok := selfinstall.PickTemplate(only); ok {
		t.Fatal("a TurnKey/arm64 template was picked")
	}
	// the newest version wins
	apl = append(apl, proxmox.AplTemplate{Template: "debian-13-standard_13.10-1_amd64.tar.zst", Package: "debian-13-standard",
		Section: "system", Version: "13.10-1", Architecture: "amd64", Type: "lxc"})
	if tpl, _ := selfinstall.PickTemplate(apl); tpl.Version != "13.10-1" {
		t.Fatalf("newest not picked: %+v", tpl)
	}
}

func TestTemplateAlreadyDownloaded(t *testing.T) {
	vols := load[[]proxmox.Volume](t, "storage-local-vztmpl.json")
	found := false
	for _, v := range vols {
		if v.VolID == "local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst" && v.Size > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("template volume not found: %+v", vols)
	}
}

func TestFirstFreeVMIDFromRealResources(t *testing.T) {
	res := load[[]proxmox.Resource](t, "cluster-resources.json")
	if got := selfinstall.FirstFreeVMID(res, selfinstall.DefaultVMIDFrom); got != 900 {
		t.Fatalf("VMID = %d, want 900", got)
	}
	if !selfinstall.VMIDUsed(res, 127) || selfinstall.VMIDUsed(res, 900) {
		t.Fatal("VMIDUsed")
	}
	// 900–902 taken → 903
	for _, id := range []int{900, 901, 902} {
		res = append(res, proxmox.Resource{Type: "lxc", VMID: id})
	}
	if got := selfinstall.FirstFreeVMID(res, 900); got != 903 {
		t.Fatalf("VMID = %d, want 903", got)
	}
}

func TestPickNodeByFreeRAM(t *testing.T) {
	res := load[[]proxmox.Resource](t, "cluster-resources.json")
	// free share: pve 0.50, pve1 0.79, pve2 0.81
	if got := selfinstall.PickNode(res, []string{"pve", "pve1", "pve2"}); got != "pve2" {
		t.Fatalf("node = %q", got)
	}
	if got := selfinstall.PickNode(res, []string{"pve", "pve1"}); got != "pve1" {
		t.Fatalf("node = %q", got)
	}
	if got := selfinstall.PickNode(res, []string{"nope"}); got != "" {
		t.Fatalf("node = %q", got)
	}
}

func TestBridgeAndStorageFromRealNode(t *testing.T) {
	nets := load[[]proxmox.NetIface](t, "network-pve1.json")
	names, def := selfinstall.Bridges(nets)
	if len(names) != 1 || names[0] != "vmbr0" || def != "vmbr0" {
		t.Fatalf("bridges %v / %q", names, def)
	}
	if gw := selfinstall.BridgeGateway(nets, "vmbr0"); gw == "" {
		t.Fatal("bridge gateway not read")
	}
	stor := load[[]proxmox.NodeStorageEntry](t, "storage-pve1.json")
	if got := selfinstall.PickRootStorage(stor, 4); got != "local-lvm" {
		t.Fatalf("root storage = %q", got)
	}
	if got := selfinstall.PickTemplateStorage(stor); got != "local" {
		t.Fatalf("template storage = %q", got)
	}
	// without local-lvm: the rootdir storage with the most free space
	var noLVM []proxmox.NodeStorageEntry
	for _, s := range stor {
		if s.Storage != "local-lvm" {
			noLVM = append(noLVM, s)
		}
	}
	noLVM = append(noLVM, proxmox.NodeStorageEntry{Storage: "big", Content: "rootdir,images", Active: 1, Enabled: 1, Avail: 1 << 40},
		proxmox.NodeStorageEntry{Storage: "small", Content: "rootdir", Active: 1, Enabled: 1, Avail: 1 << 30})
	if got := selfinstall.PickRootStorage(noLVM, 4); got != "big" {
		t.Fatalf("fallback storage = %q", got)
	}
	// too little room everywhere
	if got := selfinstall.PickRootStorage(noLVM, 1<<20); got != "" {
		t.Fatalf("storage = %q", got)
	}
}
