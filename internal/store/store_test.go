package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	for _, tbl := range []string{"users", "sessions", "jobs", "job_steps", "job_log", "schema_migrations", "secrets", "targets", "target_nodes", "inventory", "settings", "handoff_tokens", "scans", "hosts"} {
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

func TestSettingsAndInstanceID(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if _, err := s.GetSetting(ctx, "x"); err != ErrNotFound {
		t.Fatalf("missing setting: %v", err)
	}
	if err := s.SetSetting(ctx, "x", "1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "x", "2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetSetting(ctx, "x"); v != "2" {
		t.Fatalf("setting = %q", v)
	}
	a, err := s.EnsureInstanceID(ctx)
	if err != nil || len(a) != 32 {
		t.Fatalf("instance id %q %v", a, err)
	}
	if b, _ := s.EnsureInstanceID(ctx); b != a {
		t.Fatal("instance id must be stable")
	}
}

func TestHandoffTokens(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	u, _ := s.CreateFirstUser(ctx, "admin", "h")
	now := time.Now()
	if err := s.CreateHandoff(ctx, "h1", u.ID, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHandoff(ctx, "old", u.ID, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeHandoff(ctx, "old", now); err != ErrNotFound {
		t.Fatalf("expired token: %v", err)
	}
	if _, err := s.ConsumeHandoff(ctx, "nope", now); err != ErrNotFound {
		t.Fatalf("unknown token: %v", err)
	}
	if uid, err := s.ConsumeHandoff(ctx, "h1", now); err != nil || uid != u.ID {
		t.Fatalf("%d %v", uid, err)
	}
	if _, err := s.ConsumeHandoff(ctx, "h1", now); err != ErrNotFound {
		t.Fatalf("a token must work once: %v", err)
	}
	_ = s.CreateHandoff(ctx, "h2", u.ID, now.Add(time.Minute))
	if _, err := s.ConsumeHandoff(ctx, "h2", now.Add(2*time.Minute)); err != ErrNotFound {
		t.Fatalf("token past its TTL: %v", err)
	}
}

func TestSnapshotCopyAndArchive(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.CreateFirstUser(ctx, "admin", "h"); err != nil {
		t.Fatal(err)
	}
	id, _ := s.EnsureInstanceID(ctx)
	tmp := filepath.Join(dir, "tmp-snap")
	path, err := s.SnapshotTo(ctx, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v", st.Mode())
	}
	cp, err := OpenCopy(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := cp.EnsureInstanceID(ctx); got != id {
		t.Fatalf("copy has another instance id: %q", got)
	}
	if n, _ := cp.CountUsers(ctx); n != 1 {
		t.Fatal("copy lost users")
	}
	_ = cp.SetSetting(ctx, "k", "v")
	if err := cp.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 || entries[0].Name() != "hestia.db" {
		t.Fatalf("the copy must be one file: %v", entries)
	}
	if _, err := s.GetSetting(ctx, "k"); err != ErrNotFound {
		t.Fatal("editing the copy changed the original")
	}

	// Archive: files move, the store stays closed (no database is re-created).
	arch := filepath.Join(dir, "archive", "t1")
	if err := s.Archive(ctx, dir, arch); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hestia.db")); !os.IsNotExist(err) {
		t.Fatal("database left in the data directory")
	}
	if st, err := os.Stat(filepath.Join(arch, "hestia.db")); err != nil || st.Size() == 0 {
		t.Fatalf("archived db: %v", err)
	}
	if st, _ := os.Stat(arch); st.Mode().Perm() != 0o700 {
		t.Fatalf("archive mode %v", st.Mode())
	}
	if _, err := s.CountUsers(ctx); err == nil {
		t.Fatal("a store used after Archive must fail, not reopen the path")
	}
	if _, err := os.Stat(filepath.Join(dir, "hestia.db")); !os.IsNotExist(err) {
		t.Fatal("a database was re-created after Archive")
	}
	// the archived database opens again
	re, err := OpenCopy(arch)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if n, _ := re.CountUsers(ctx); n != 1 {
		t.Fatal("archived database lost data")
	}
}

// A database written by a newer Hestia is refused, untouched, with a message
// that names the culprit.
func TestOpenRefusesNewerSchema(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.SetSetting(ctx, SettingWrittenBy, "v9.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, 0)`, KnownSchema()+1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_, err = Open(dir)
	if !errors.Is(err, ErrSchemaNewer) || !strings.Contains(err.Error(), "v9.0.0") {
		t.Fatalf("err = %v", err)
	}
	// the refusal leaves the file as it was: still the same schema
	raw, err := sql.Open("sqlite", filepath.Join(dir, "hestia.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var max int
	_ = raw.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&max)
	if max != KnownSchema()+1 {
		t.Fatalf("schema changed: %d", max)
	}
}

func TestFailUnfinishedKeepsListedJobs(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	for _, id := range []string{"keep", "drop"} {
		if err := s.InsertJob(ctx, Job{ID: id, Kind: "k", Title: id, Status: JobRunning, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := s.InsertStep(ctx, id, Step{Idx: 0, Title: "s", Status: StepRunning, StartedAt: &now}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.FailUnfinished(ctx, "прервано", now, "keep")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	k, _ := s.GetJob(ctx, "keep")
	d, _ := s.GetJob(ctx, "drop")
	if k.Status != JobRunning || k.Steps[0].Status != StepRunning || d.Status != JobFailed || d.Steps[0].Status != StepFailed {
		t.Fatalf("keep=%s/%s drop=%s/%s", k.Status, k.Steps[0].Status, d.Status, d.Steps[0].Status)
	}
}
