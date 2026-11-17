package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenMigrationsIdempotentAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SchemaVersion(context.Background())
	if err != nil || v != len(migrations) {
		t.Fatalf("version = %d, %v", v, err)
	}
	for _, tbl := range []string{"users", "sessions", "jobs", "job_steps", "job_log", "schema_migrations", "secrets", "targets", "target_nodes"} {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s missing (%v)", tbl, err)
		}
	}
	var fk int
	_ = s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	if fk != 1 {
		t.Error("foreign_keys not enabled")
	}
	_ = s.Close()

	s2, err := Open(dir) // reopening must not re-apply migrations
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	_ = s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n)
	if n != len(migrations) {
		t.Errorf("schema_migrations rows = %d", n)
	}

	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Join(dir, "hestia.db")); st.Mode().Perm() != 0o600 {
		t.Errorf("db mode %v", st.Mode().Perm())
	}
}

func TestFirstUserOnlyOnce(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.CreateFirstUser(ctx, "admin", "h"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateFirstUser(ctx, "other", "h"); err != ErrUsersExist {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.CreateFirstUser(ctx, "admin", "h"); err != ErrUsersExist {
		t.Fatalf("err = %v", err)
	}
}

func TestSessions(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	u, _ := s.CreateFirstUser(ctx, "admin", "h")
	now := time.Now()
	if err := s.CreateSession(ctx, "hash1", u.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.UserBySession(ctx, "hash1", now); err != nil || got.ID != u.ID {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := s.UserBySession(ctx, "hash1", now.Add(2*time.Hour)); err != ErrNotFound {
		t.Fatalf("expired: %v", err)
	}
	_ = s.DeleteSession(ctx, "hash1")
	if _, err := s.UserBySession(ctx, "hash1", now); err != ErrNotFound {
		t.Fatalf("deleted: %v", err)
	}
}
