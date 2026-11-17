package onboard_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"hestia/internal/proxmox"
	"hestia/internal/store"
)

// connectProxmox connects the fake cluster and returns the stored target id.
func connectProxmox(t *testing.T, e *env) int64 {
	t.Helper()
	res := probeOK(t, e, "proxmox")
	job, err := e.svc.Connect(context.Background(), e.confirm(res))
	if err != nil {
		t.Fatal(err)
	}
	if j := e.waitJob(job); j.Status != store.JobDone {
		t.Fatalf("connect: %s %s", j.Status, j.Error)
	}
	ts, _ := e.st.ListTargets(context.Background())
	if len(ts) != 1 {
		t.Fatalf("targets: %d", len(ts))
	}
	return ts[0].ID
}

func TestRolePlanAndFixAfterConfirmation(t *testing.T) {
	host := newFakeProxmox("", "pve1")
	e := newEnv(t, host)
	var mu sync.Mutex
	var changed []int64
	e.svc.AfterChange = func(id int64) { mu.Lock(); changed = append(changed, id); mu.Unlock() }
	id := connectProxmox(t, e)
	mu.Lock()
	if len(changed) != 1 || changed[0] != id {
		t.Fatalf("AfterChange after connect: %v", changed)
	}
	changed = nil
	mu.Unlock()

	// A healthy role needs nothing.
	p, err := e.svc.RolePlan(context.Background(), id)
	if err != nil || p.Needed || p.Command != "" || len(p.Missing) != 0 {
		t.Fatalf("%+v %v", p, err)
	}

	// A role from before the stage lacks the guest agent privilege (and an
	// extra privilege somebody added must survive).
	agentPriv := proxmox.PrivilegesFor("8.2.4")[len(proxmox.Privileges)]
	host.mu.Lock()
	var old []string
	for _, p := range strings.Split(host.roles[proxmox.RoleName], ",") {
		if p != agentPriv {
			old = append(old, p)
		}
	}
	host.roles[proxmox.RoleName] = strings.Join(append(old, "Datastore.Allocate"), ",")
	host.cmds = nil
	host.mu.Unlock()

	p, err = e.svc.RolePlan(context.Background(), id)
	if err != nil || !p.Needed || len(p.Missing) != 1 || p.Missing[0] != agentPriv ||
		!strings.HasPrefix(p.Command, "pveum role modify Hestia --privs ") || !strings.Contains(p.Command, agentPriv) ||
		!strings.Contains(p.Command, "Datastore.Allocate") {
		t.Fatalf("%+v %v", p, err)
	}
	// The plan is read-only.
	for _, c := range host.commands() {
		if strings.Contains(c, "role modify") || strings.Contains(c, "role add") {
			t.Fatalf("plan changed the host: %s", c)
		}
	}

	job, err := e.svc.FixRole(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if j := e.waitJob(job); j.Status != store.JobDone {
		t.Fatalf("%s %s\n%s", j.Status, j.Error, e.jobText(j))
	}
	host.mu.Lock()
	got := host.roles[proxmox.RoleName]
	host.mu.Unlock()
	if !strings.Contains(got, agentPriv) || !strings.Contains(got, "Datastore.Allocate") {
		t.Fatalf("role after fix: %s", got)
	}
	mu.Lock()
	if len(changed) != 1 || changed[0] != id {
		t.Fatalf("AfterChange after fix: %v", changed)
	}
	mu.Unlock()
	if p, _ = e.svc.RolePlan(context.Background(), id); p.Needed {
		t.Fatalf("still needed: %+v", p)
	}
}

func TestRoleFixRejectsSSHTargetsAndUnknownIDs(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "x"))
	if _, err := e.svc.RolePlan(context.Background(), 99); err == nil {
		t.Fatal("unknown target")
	}
	if _, err := e.svc.FixRole(context.Background(), 99); err == nil {
		t.Fatal("unknown target")
	}
	tg := store.Target{Kind: store.KindSSH, Name: "s", Host: "h", Port: 22, SSHUser: "u", HostKeyFP: "x"}
	if err := e.st.CreateTarget(context.Background(), &tg); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.RolePlan(context.Background(), tg.ID)
	if oe := asErr(t, err); oe.Status != 400 {
		t.Fatalf("%+v", oe)
	}
}

func TestPrivilegesByVersion(t *testing.T) {
	has := func(l []string, p string) bool {
		for _, x := range l {
			if x == p {
				return true
			}
		}
		return false
	}
	v9, v8 := proxmox.PrivilegesFor("9.2.10"), proxmox.PrivilegesFor("8.2.4")
	if !has(v9, "VM.GuestAgent.Audit") || has(v9, "VM.Monitor") {
		t.Fatalf("9: %v", v9)
	}
	if has(v8, "VM.GuestAgent.Audit") || !has(v8, "VM.Monitor") {
		t.Fatalf("8: %v", v8)
	}
	if !has(proxmox.PrivilegesFor(""), "VM.GuestAgent.Audit") {
		t.Fatal("unknown version is treated as current")
	}
}
