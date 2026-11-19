package onboard_test

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/uxerror/hestia/internal/onboard"
	"github.com/uxerror/hestia/internal/sshx/sshxtest"
	"github.com/uxerror/hestia/internal/store"
)

func nodeByName(res *onboard.ProbeResult, name string) store.Node {
	for _, n := range res.Nodes {
		if n.Name == name {
			return n
		}
	}
	return store.Node{}
}

func rsaLine(node string, sg ssh.Signer) string {
	return node + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey())))
}

func connectJob(t *testing.T, e *env, res *onboard.ProbeResult) store.Job {
	t.Helper()
	job, err := e.svc.Connect(context.Background(), e.confirm(res))
	if err != nil {
		t.Fatal(err)
	}
	return e.waitJob(job)
}

func TestProbeReportsNodeHostKeys(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2", "pve3")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	for i, name := range []string{"pve1", "pve2", "pve3"} {
		n := nodeByName(res, name)
		srv := e.main
		if i > 0 {
			srv = e.nodes[n.IP]
		}
		want := ssh.FingerprintSHA256(srv.HostKeyOf("ssh-rsa"))
		if n.HostKeyFP != want || n.HostKeyType != "ssh-rsa" {
			t.Errorf("%s: %q %q, want %q ssh-rsa", name, n.HostKeyFP, n.HostKeyType, want)
		}
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
}

func TestConnectSavesNodeHostKeys(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	if j := connectJob(t, e, res); j.Status != store.JobDone {
		t.Fatalf("%s\n%s", j.Error, e.jobText(j))
	}
	ts, _ := e.st.ListTargets(context.Background())
	for _, n := range ts[0].Nodes {
		want := nodeByName(res, n.Name)
		if n.HostKeyFP == "" || n.HostKeyFP != want.HostKeyFP || n.HostKeyType != "ssh-rsa" {
			t.Errorf("saved %+v, probed %+v", n, want)
		}
	}
}

func TestNodeWithoutClusterKeyWarnsAndStopsWithoutTOFU(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2", "pve3")
	e := newEnv(t, host)
	delete(host.nodeKeys, "pve3")
	res := probeOK(t, e, "proxmox")
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "pve3") || !strings.Contains(res.Warnings[0], "ssh_known_hosts") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	j := connectJob(t, e, res)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "pve3") || !strings.Contains(j.Error, "нет SSH-ключа") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if len(host.roles)+len(host.users)+len(host.tokens) != 0 || host.authKeys != "" {
		t.Fatal("changes were not rolled back")
	}
	if ts, _ := e.st.ListTargets(context.Background()); len(ts) != 0 {
		t.Fatal("target saved")
	}
}

func TestNodeWithDifferentHostKeyIsRejected(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	// pve2 now presents another RSA key than the cluster recorded.
	node := nodeByName(res, "pve2")
	e.nodes[node.IP].SetHostKey(sshxtest.NewRSASigner(t))
	j := connectJob(t, e, res)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "pve2") || !strings.Contains(j.Error, "изменился") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if len(host.roles)+len(host.users)+len(host.tokens) != 0 {
		t.Fatal("changes were not rolled back")
	}
}

// The cluster lists an RSA key; a node that offers only ed25519 must not be
// accepted (the client is restricted to rsa-sha2-*), not even on first use.
func TestNodeKeyTypeIsRestrictedToThePinnedAlgorithm(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	node := nodeByName(res, "pve2")
	e.nodes[node.IP].SetHostKey(sshxtest.NewSigner(t)) // ed25519 only
	j := connectJob(t, e, res)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "pve2") || !strings.Contains(j.Error, "rsa-sha2-512") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
}

func TestNodeKeysChangedBetweenProbeAndConnect(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	host.nodeKeys["pve2"] = rsaLine("pve2", sshxtest.NewRSASigner(t))
	j := connectJob(t, e, res)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "pve2") || !strings.Contains(j.Error, "изменился с момента проверки") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if len(host.roles)+len(host.users)+len(host.tokens) != 0 {
		t.Fatal("changes made despite changed node keys")
	}
}

func TestPrimaryKeyMismatchWarns(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2")
	e := newEnv(t, host)
	host.nodeKeys["pve1"] = rsaLine("pve1", sshxtest.NewRSASigner(t)) // not the server's key
	res := probeOK(t, e, "proxmox")
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "pve1") || !strings.Contains(res.Warnings[0], "не совпадает") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
}

// A cluster key of another type than the one the client negotiated by default
// is still verified, by asking the server for that very type.
func TestPrimaryKeyOfOtherTypeIsVerifiedNotWarned(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2")
	e := newEnv(t, host)
	ed := sshxtest.NewSigner(t)
	e.main.AddHostKey(ed)
	host.nodeKeys["pve1"] = rsaLine("pve1", ed) // "ssh-ed25519 …"
	res := probeOK(t, e, "proxmox")
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	if n := nodeByName(res, "pve1"); n.HostKeyType != "ssh-ed25519" || n.HostKeyFP != ssh.FingerprintSHA256(ed.PublicKey()) {
		t.Fatalf("%+v", n)
	}
}

func TestSingleNodeNeedsNoClusterKeys(t *testing.T) {
	host := newFakeProxmox("", "solo")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	if len(res.Warnings) != 0 || res.Nodes[0].HostKeyFP != "" {
		t.Fatalf("%+v", res)
	}
	if j := connectJob(t, e, res); j.Status != store.JobDone {
		t.Fatalf("%s\n%s", j.Error, e.jobText(j))
	}
}
