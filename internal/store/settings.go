package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Setting keys.
const (
	SettingInstanceID         = "instance_id"
	SettingControllerLocation = "controller_location"
)

// GetSetting returns a setting value, or ErrNotFound.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting stores a setting value.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// EnsureInstanceID returns the id of this Hestia instance, creating it on the
// first call. The id lives in the database, so it travels with a moved
// database: the new controller answers with the same id.
func (s *Store) EnsureInstanceID(ctx context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// INSERT OR IGNORE makes concurrent first calls agree on one value.
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)`,
		SettingInstanceID, hex.EncodeToString(b)); err != nil {
		return "", err
	}
	return s.GetSetting(ctx, SettingInstanceID)
}

// CreateHandoff stores a one-time login token by its hash.
func (s *Store) CreateHandoff(ctx context.Context, hash string, userID int64, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO handoff_tokens(hash, user_id, expires_at) VALUES (?, ?, ?)`,
		hash, userID, ms(expires))
	return err
}

// ConsumeHandoff deletes the token and returns its user. A missing or expired
// token is ErrNotFound; expired ones are purged on the way.
func (s *Store) ConsumeHandoff(ctx context.Context, hash string, now time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM handoff_tokens WHERE expires_at <= ?`, ms(now)); err != nil {
		return 0, err
	}
	var uid int64
	err = tx.QueryRowContext(ctx, `DELETE FROM handoff_tokens WHERE hash = ? RETURNING user_id`, hash).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return uid, tx.Commit()
}

// SnapshotTo writes a consistent copy of the database to <dir>/hestia.db
// (VACUUM INTO) as a single file in rollback-journal mode, so it can be
// shipped as is. dir is created with mode 0700 and must not hold a database.
func (s *Store) SnapshotTo(ctx context.Context, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "hestia.db")
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO `+quoteSQL(path)); err != nil {
		return "", fmt.Errorf("снимок базы: %w", err)
	}
	return path, os.Chmod(path, 0o600)
}

// OpenCopy opens a database file produced by SnapshotTo for editing. The
// returned store runs without WAL, so Close leaves exactly one file behind.
func OpenCopy(dir string) (*Store, error) {
	path := filepath.Join(dir, "hestia.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode = DELETE`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Archive checkpoints the database, closes it and moves hestia.db (and any
// -wal/-shm leftovers) into dir. The store is unusable afterwards; further
// calls fail with "database is closed" instead of re-creating a database at
// the old path.
func (s *Store) Archive(ctx context.Context, dataDir, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	if err := s.db.Close(); err != nil {
		return err
	}
	for _, name := range []string{"hestia.db", "hestia.db-wal", "hestia.db-shm"} {
		err := os.Rename(filepath.Join(dataDir, name), filepath.Join(dir, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func quoteSQL(s string) string {
	out := []byte{'\''}
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'')
		}
		out = append(out, s[i])
	}
	return string(append(out, '\''))
}
