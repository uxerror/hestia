// Package store is the SQLite persistence layer (modernc.org/sqlite, no cgo).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

// Sentinel errors returned by store methods.
var (
	ErrNotFound   = errors.New("not found")
	ErrUsersExist = errors.New("users already exist")
	ErrDuplicate  = errors.New("already exists")
)

// Store wraps the database handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) <dir>/hestia.db and applies migrations.
// The directory is created with mode 0700, the database file is 0600.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "hestia.db")
	// Create the file up front so it never exists with a wider mode.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	_ = os.Chmod(path, 0o600)

	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

type migration struct {
	version int
	sql     string
}

// migrations are applied in order of version; never edit an applied one.
var migrations = []migration{
	{1, `
CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE TABLE sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE jobs (
	id          TEXT PRIMARY KEY,
	kind        TEXT NOT NULL,
	title       TEXT NOT NULL,
	status      TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	started_at  INTEGER,
	finished_at INTEGER,
	error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX jobs_created ON jobs(created_at);
CREATE TABLE job_steps (
	job_id      TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
	idx         INTEGER NOT NULL,
	title       TEXT NOT NULL,
	status      TEXT NOT NULL,
	started_at  INTEGER,
	finished_at INTEGER,
	error       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (job_id, idx)
);
CREATE TABLE job_log (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
	at     INTEGER NOT NULL,
	level  TEXT NOT NULL,
	line   TEXT NOT NULL
);
CREATE INDEX job_log_job ON job_log(job_id, id);
`},
	{2, `
CREATE TABLE secrets (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	purpose    TEXT NOT NULL,
	nonce      BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX secrets_purpose ON secrets(purpose);
CREATE TABLE targets (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	kind             TEXT NOT NULL CHECK (kind IN ('proxmox', 'ssh')),
	name             TEXT NOT NULL UNIQUE,
	host             TEXT NOT NULL,
	port             INTEGER NOT NULL,
	ssh_user         TEXT NOT NULL,
	host_key_fp      TEXT NOT NULL,
	api_cert_fp      TEXT NOT NULL DEFAULT '',
	cluster          TEXT NOT NULL DEFAULT '',
	token_id         TEXT NOT NULL DEFAULT '',
	token_secret_ref INTEGER REFERENCES secrets(id),
	created_at       INTEGER NOT NULL,
	UNIQUE (host, port)
);
CREATE TABLE target_nodes (
	target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
	name      TEXT NOT NULL,
	ip        TEXT NOT NULL DEFAULT '',
	online    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (target_id, name)
);
`},
	{3, `
ALTER TABLE target_nodes ADD COLUMN host_key_fp   TEXT NOT NULL DEFAULT '';
ALTER TABLE target_nodes ADD COLUMN host_key_type TEXT NOT NULL DEFAULT '';
`},
}

// SchemaVersion returns the highest applied migration number.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	for _, m := range migrations {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, m.version, ms(time.Now())); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ms converts a time to unix milliseconds for storage.
func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func fromNullMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMS(v.Int64)
	return &t
}

func nullMS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ms(*t)
}

// DB exposes the underlying handle for tests and low-level inspection.
func (s *Store) DB() *sql.DB { return s.db }
