package store

import (
	"context"
	"errors"
	"testing"
)

func TestTargetsCRUD(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	ref, err := s.InsertSecret(ctx, "proxmox_api_token", []byte("n"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	tg := Target{Kind: KindProxmox, Name: "lab", Host: "h1", Port: 22, SSHUser: "root", HostKeyFP: "SHA256:x",
		APICertFP: "AA", Cluster: "lab", TokenID: "hestia@pve!hestia", TokenSecretRef: ref,
		Nodes: []Node{{Name: "b", IP: "2", HostKeyFP: "SHA256:b", HostKeyType: "ssh-rsa"}, {Name: "a", IP: "1", Online: true}}}
	if err := s.CreateTarget(ctx, &tg); err != nil || tg.ID == 0 {
		t.Fatal(err)
	}
	got, err := s.GetTarget(ctx, tg.ID)
	if err != nil || got.Name != "lab" || got.TokenSecretRef != ref || len(got.Nodes) != 2 || got.Nodes[0].Name != "a" || !got.Nodes[0].Online || got.Nodes[1].Online {
		t.Fatalf("%+v %v", got, err)
	}
	if got.Nodes[1].HostKeyFP != "SHA256:b" || got.Nodes[1].HostKeyType != "ssh-rsa" || got.Nodes[0].HostKeyFP != "" {
		t.Fatalf("node host keys: %+v", got.Nodes)
	}

	// Duplicate name or host:port.
	d := Target{Kind: KindSSH, Name: "lab", Host: "h2", Port: 22, SSHUser: "u", HostKeyFP: "x"}
	if err := s.CreateTarget(ctx, &d); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("name: %v", err)
	}
	d = Target{Kind: KindSSH, Name: "other", Host: "h1", Port: 22, SSHUser: "u", HostKeyFP: "x"}
	if err := s.CreateTarget(ctx, &d); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("addr: %v", err)
	}
	d.Port = 2222
	d.Nodes = nil
	if err := s.CreateTarget(ctx, &d); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListTargets(ctx); len(l) != 2 || l[1].Nodes == nil {
		t.Fatalf("%+v", l)
	}
	if f, err := s.FindTargetByAddr(ctx, "h1", 22); err != nil || f.ID != tg.ID {
		t.Fatal(f, err)
	}

	// Deleting removes nodes and the token secret.
	if err := s.DeleteTarget(ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetTarget(ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.GetSecret(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("secret survived: %v", err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM target_nodes WHERE target_id = ?`, tg.ID).Scan(&n)
	if n != 0 {
		t.Fatal("nodes survived")
	}
	if err := s.DeleteTarget(ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
