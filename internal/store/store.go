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
	if err := s.checkSchemaNotNewer(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
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
	{4, `
CREATE TABLE inventory (
	target_id    INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
	collected_at INTEGER NOT NULL DEFAULT 0,
	data         TEXT NOT NULL DEFAULT '',
	error        TEXT NOT NULL DEFAULT ''
);
`},
	{5, `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE handoff_tokens (
	hash       TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
`},
	{6, `
CREATE TABLE scans (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	started_at  INTEGER NOT NULL,
	finished_at INTEGER,
	subnets     TEXT NOT NULL DEFAULT '[]',
	stats       TEXT NOT NULL DEFAULT '{}',
	error       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE hosts (
	ip           TEXT PRIMARY KEY,
	mac          TEXT NOT NULL DEFAULT '',
	vendor       TEXT NOT NULL DEFAULT '',
	random_mac   INTEGER NOT NULL DEFAULT 0,
	names        TEXT NOT NULL DEFAULT '[]',
	first_seen   INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL,
	last_scan_id INTEGER NOT NULL DEFAULT 0,
	alive        INTEGER NOT NULL DEFAULT 0,
	source       TEXT NOT NULL DEFAULT 'scan',
	ports        TEXT NOT NULL DEFAULT '[]',
	services     TEXT NOT NULL DEFAULT '[]',
	link         TEXT NOT NULL DEFAULT 'null'
);
`},
	{7, `
CREATE TABLE integrations (
	id         INTEGER PRIMARY KEY,
	kind       TEXT NOT NULL,
	name       TEXT NOT NULL,
	base_url   TEXT NOT NULL,
	tls_pin    TEXT NOT NULL DEFAULT '',
	username   TEXT NOT NULL,
	secret_id  INTEGER NOT NULL REFERENCES secrets(id),
	version    TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE dns_names (
	id             INTEGER PRIMARY KEY,
	integration_id INTEGER NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
	domain         TEXT NOT NULL UNIQUE,
	answer         TEXT NOT NULL,
	status         TEXT NOT NULL DEFAULT 'ok',
	status_detail  TEXT NOT NULL DEFAULT '',
	verified_at    INTEGER,
	checked_at     INTEGER,
	created_at     INTEGER NOT NULL
);
`},
}

// KnownSchema is the newest schema version this binary can work with.
func KnownSchema() int {
	n := 0
	for _, m := range migrations {
		if m.version > n {
			n = m.version
		}
	}
	return n
}

// ErrSchemaNewer is returned by Open for a database written by a newer Hestia.
var ErrSchemaNewer = errors.New("база создана более новой версией Hestia")

// checkSchemaNotNewer refuses a database with a schema newer than this binary
// knows: an old binary left running after a failed upgrade must not touch it.
func (s *Store) checkSchemaNotNewer(ctx context.Context) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&n); err != nil || n == 0 {
		return err
	}
	have, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if have <= KnownSchema() {
		return nil
	}
	by := ""
	if v, err := s.GetSetting(ctx, SettingWrittenBy); err == nil && v != "" {
		by = " " + v
	}
	return fmt.Errorf("%w%s (схема %d, эта версия знает %d): запустите более новую Hestia", ErrSchemaNewer, by, have, KnownSchema())
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
