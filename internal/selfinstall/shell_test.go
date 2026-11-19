package selfinstall_test

import (
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/selfinstall"
)

// roundTrip writes a file through the controller shell and runs a command.
func roundTrip(t *testing.T, sh *selfinstall.ControllerShell, m *fakeMachine) {
	t.Helper()
	defer sh.Close()
	if err := sh.PutFile(ctxBG(), nil, "/usr/local/bin/hestia.new", []byte("payload"), "0755", "root:root"); err != nil {
		t.Fatal(err)
	}
	if b, ok := m.file("/usr/local/bin/hestia.new"); !ok || string(b) != "payload" {
		t.Fatalf("file on the machine: %q %v", b, ok)
	}
	m.mu.Lock()
	mode, owner := m.modes["/usr/local/bin/hestia.new"], m.owners["/usr/local/bin/hestia.new"]
	m.mu.Unlock()
	if mode != "0755" || owner != "root:root" {
		t.Fatalf("mode %q owner %q", mode, owner)
	}
	r, err := sh.Exec(ctxBG(), "echo hi", nil)
	if err != nil || strings.TrimSpace(r.Stdout) != "hi" {
		t.Fatalf("exec: %+v %v", r, err)
	}
}

func TestOpenShellLXC(t *testing.T) {
	e := newEnv(t)
	e.node.addCT(900)
	sh, err := e.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "lxc", TargetID: e.tgt.ID, Node: "pve1", VMID: 900})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, sh, e.node.ct(900))
}

func TestOpenShellLXCUnknownContainer(t *testing.T) {
	e := newEnv(t)
	sh, err := e.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "lxc", TargetID: e.tgt.ID, Node: "pve1", VMID: 901})
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	if _, err := sh.Exec(ctxBG(), "echo hi", nil); err == nil {
		t.Fatal("a missing container must fail")
	}
}

func TestOpenShellServerRootAndSudo(t *testing.T) {
	for _, c := range []struct {
		name string
		uid  int
	}{{"root", 0}, {"sudo", 1000}} {
		t.Run(c.name, func(t *testing.T) {
			e, m := newServerEnv(t, c.uid, true)
			sh, err := e.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "ssh", TargetID: e.tgt.ID})
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, sh, m)
		})
	}
}

func TestOpenShellErrors(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "lxc", TargetID: 999, Node: "pve1", VMID: 900}); err == nil || !strings.Contains(err.Error(), "не подключена") {
		t.Fatalf("unknown target: %v", err)
	}
	if _, err := e.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "lxc", TargetID: e.tgt.ID, Node: "nope", VMID: 900}); err == nil {
		t.Fatal("unknown node")
	}
	if _, err := e.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "weird", TargetID: e.tgt.ID}); err == nil {
		t.Fatal("unknown kind")
	}
	es, _ := newServerEnv(t, 1000, false)
	if _, err := es.svc.OpenShell(ctxBG(), selfinstall.Location{Kind: "ssh", TargetID: es.tgt.ID}); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("no sudo: %v", err)
	}
}
