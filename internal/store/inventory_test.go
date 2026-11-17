package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInventoryRows(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	tg := Target{Kind: KindSSH, Name: "a", Host: "h", Port: 22, SSHUser: "u", HostKeyFP: "x"}
	if err := s.CreateTarget(ctx, &tg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetInventory(ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	// An error before any snapshot leaves no data and no time.
	if err := s.SetInventoryError(ctx, tg.ID, "boom"); err != nil {
		t.Fatal(err)
	}
	r, _ := s.GetInventory(ctx, tg.ID)
	if r.Error != "boom" || !r.CollectedAt.IsZero() || len(r.Data) != 0 {
		t.Fatalf("%+v", r)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.PutInventory(ctx, tg.ID, at, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	r, _ = s.GetInventory(ctx, tg.ID)
	if r.Error != "" || !r.CollectedAt.Equal(at) || string(r.Data) != `{"a":1}` {
		t.Fatalf("%+v", r)
	}
	// A later failure keeps the last snapshot and its time.
	_ = s.SetInventoryError(ctx, tg.ID, "again")
	r, _ = s.GetInventory(ctx, tg.ID)
	if r.Error != "again" || !r.CollectedAt.Equal(at) || string(r.Data) != `{"a":1}` {
		t.Fatalf("%+v", r)
	}
	if rows, err := s.ListInventory(ctx); err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	// Deleting the target removes its inventory.
	if err := s.DeleteTarget(ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if rows, _ := s.ListInventory(ctx); len(rows) != 0 {
		t.Fatalf("inventory not cascaded: %v", rows)
	}
}
