package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationsAndNames(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.GetIntegrationByKind(ctx, KindAdGuard); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.GetDNSName(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	id, err := s.NextIntegrationID(ctx)
	if err != nil || id != 1 {
		t.Fatalf("%d %v", id, err)
	}
	sec, err := s.InsertSecret(ctx, "adguard:1", []byte("n"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	in := Integration{ID: id, Kind: KindAdGuard, Name: "AdGuard Home (10.10.10.2)", BaseURL: "https://10.10.10.2", TLSPin: "AA", Username: "u", SecretID: sec}
	if err := s.CreateIntegration(ctx, &in); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.NextIntegrationID(ctx); n != 2 {
		t.Fatal(n)
	}
	got, err := s.GetIntegrationByKind(ctx, KindAdGuard)
	if err != nil || got.BaseURL != "https://10.10.10.2" || got.SecretID != sec || got.CreatedAt.IsZero() {
		t.Fatalf("%+v %v", got, err)
	}
	got.Version = "v1"
	if err := s.UpdateIntegration(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.GetIntegrationByKind(ctx, KindAdGuard); g.Version != "v1" {
		t.Fatalf("%+v", g)
	}
	if err := s.UpdateIntegration(ctx, &Integration{ID: 99}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	n := DNSName{IntegrationID: id, Domain: "hestia.home", Answer: "10.10.10.5", VerifiedAt: &now}
	if err := s.SaveDNSName(ctx, &n); err != nil || n.ID == 0 {
		t.Fatalf("%+v %v", n, err)
	}
	// One name per controller: saving again replaces it.
	n2 := DNSName{IntegrationID: id, Domain: "hestia.lan", Answer: "10.10.10.5"}
	if err := s.SaveDNSName(ctx, &n2); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetDNSName(ctx)
	if err != nil || g.Domain != "hestia.lan" || g.Status != "ok" || g.VerifiedAt != nil {
		t.Fatalf("%+v %v", g, err)
	}
	if err := s.UpdateDNSNameStatus(ctx, g.ID, "ip_changed", "x", "", now, &now); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateDNSNameStatus(ctx, g.ID, "missing", "y", "10.10.10.9", now, nil); err != nil {
		t.Fatal(err)
	}
	g, _ = s.GetDNSName(ctx)
	if g.Status != "missing" || g.Answer != "10.10.10.9" || g.VerifiedAt == nil || g.CheckedAt == nil {
		t.Fatalf("verified_at must be kept, answer replaced: %+v", g)
	}

	// Deleting the integration removes the name (cascade) and the secret.
	if err := s.DeleteIntegration(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDNSName(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatal("name survived")
	}
	if _, err := s.GetSecret(ctx, sec); !errors.Is(err, ErrNotFound) {
		t.Fatal("secret survived")
	}
	if err := s.DeleteIntegration(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
