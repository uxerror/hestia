package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestScansRotateToFifty(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	var last int64
	for i := 0; i < KeepScans+7; i++ {
		id, err := s.BeginScan(ctx, t0.Add(time.Duration(i)*time.Minute), []byte(`["10.10.10.0/24"]`))
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 { // some scans stay unfinished (a crash)
			if err := s.FinishScan(ctx, id, t0.Add(time.Duration(i)*time.Minute+time.Second), []byte(`{"alive":3}`), ""); err != nil {
				t.Fatal(err)
			}
		}
		last = id
	}
	all, err := s.ListScans(ctx, 1000, false)
	if err != nil || len(all) != KeepScans {
		t.Fatalf("kept %d, %v", len(all), err)
	}
	if all[0].ID != last || all[len(all)-1].ID != last-KeepScans+1 {
		t.Fatalf("newest first, oldest dropped: %d..%d (last %d)", all[0].ID, all[len(all)-1].ID, last)
	}
	// The newest finished one (here the newest, i = 56 is even).
	row, err := s.LastScan(ctx)
	if err != nil || row.FinishedAt == nil || row.ID != last || string(row.Stats) != `{"alive":3}` {
		t.Fatalf("last: %+v %v", row, err)
	}
	empty, _ := Open(t.TempDir())
	defer empty.Close()
	if _, err := empty.LastScan(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
}

func TestHostsUpsertAliveAndForget(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	t1 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(6 * time.Hour)
	svc := json.RawMessage(`[{"port":22,"name":"SSH"}]`)

	s1, _ := s.BeginScan(ctx, t1, nil)
	err = s.SaveScanHosts(ctx, s1, []NetHost{
		{IP: "10.10.10.5", MAC: "bc:24:11:00:00:05", Vendor: "Proxmox Server Solutions GmbH", FirstSeen: t1, LastSeen: t1, Source: "scan", Services: svc, Ports: json.RawMessage(`[22]`)},
		{IP: "10.10.10.6", FirstSeen: t1, LastSeen: t1, Source: "scan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	hs, _ := s.ListHosts(ctx)
	if len(hs) != 2 {
		t.Fatalf("%d hosts", len(hs))
	}
	by := map[string]NetHost{}
	for _, h := range hs {
		by[h.IP] = h
	}
	if h := by["10.10.10.6"]; !h.Alive || string(h.Names) != "[]" || string(h.Services) != "[]" || string(h.Link) != "null" {
		t.Fatalf("defaults: %+v", h)
	}

	// The second scan finds only .6; .5 vanished.
	s2, _ := s.BeginScan(ctx, t2, nil)
	if err := s.SaveScanHosts(ctx, s2, []NetHost{{IP: "10.10.10.6", MAC: "", FirstSeen: t2, LastSeen: t2, Source: "scan"}}); err != nil {
		t.Fatal(err)
	}
	hs, _ = s.ListHosts(ctx)
	by = map[string]NetHost{}
	for _, h := range hs {
		by[h.IP] = h
	}
	g := by["10.10.10.5"]
	if g.Alive || string(g.Services) != string(svc) || g.MAC != "bc:24:11:00:00:05" || !g.FirstSeen.Equal(t1) || !g.LastSeen.Equal(t1) || g.LastScanID != s1 {
		t.Fatalf("vanished host: %+v", g)
	}
	// first_seen is not overwritten by a new sighting; last_seen moves.
	if h := by["10.10.10.6"]; !h.Alive || !h.FirstSeen.Equal(t1) || !h.LastSeen.Equal(t2) || h.LastScanID != s2 {
		t.Fatalf("seen again: %+v", h)
	}

	// A host that comes back without a MAC keeps the known one; a new MAC replaces it.
	s3, _ := s.BeginScan(ctx, t2.Add(time.Hour), nil)
	_ = s.SaveScanHosts(ctx, s3, []NetHost{{IP: "10.10.10.5", FirstSeen: t2, LastSeen: t2, Source: "scan"}, {IP: "10.10.10.6", MAC: "3c:22:fb:00:00:06", Vendor: "Apple", FirstSeen: t2, LastSeen: t2, Source: "scan"}})
	hs, _ = s.ListHosts(ctx)
	for _, h := range hs {
		switch h.IP {
		case "10.10.10.5":
			if !h.Alive || h.MAC != "bc:24:11:00:00:05" || h.Vendor == "" {
				t.Fatalf(".5: %+v", h)
			}
		case "10.10.10.6":
			if h.MAC != "3c:22:fb:00:00:06" || h.Vendor != "Apple" {
				t.Fatalf(".6: %+v", h)
			}
		}
	}

	if err := s.DeleteHost(ctx, "10.10.10.5"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHost(ctx, "10.10.10.5"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if hs, _ = s.ListHosts(ctx); len(hs) != 1 {
		t.Fatalf("after forget: %d", len(hs))
	}
}
