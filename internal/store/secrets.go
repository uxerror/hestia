package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SecretRow is an encrypted secret as stored; encryption lives in package secrets.
type SecretRow struct {
	ID         int64
	Purpose    string
	Nonce      []byte
	Ciphertext []byte
	CreatedAt  time.Time
}

// InsertSecret stores an encrypted secret and returns its id.
func (s *Store) InsertSecret(ctx context.Context, purpose string, nonce, ciphertext []byte) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO secrets(purpose, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?)`,
		purpose, nonce, ciphertext, ms(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetSecret returns a secret by id.
func (s *Store) GetSecret(ctx context.Context, id int64) (SecretRow, error) {
	return scanSecret(s.db.QueryRowContext(ctx, `SELECT id, purpose, nonce, ciphertext, created_at FROM secrets WHERE id = ?`, id))
}

// GetSecretByPurpose returns the oldest secret with the given purpose.
func (s *Store) GetSecretByPurpose(ctx context.Context, purpose string) (SecretRow, error) {
	return scanSecret(s.db.QueryRowContext(ctx, `SELECT id, purpose, nonce, ciphertext, created_at FROM secrets
		WHERE purpose = ? ORDER BY id LIMIT 1`, purpose))
}

// DeleteSecret removes a secret; a missing row is not an error.
func (s *Store) DeleteSecret(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
	return err
}

func scanSecret(row *sql.Row) (SecretRow, error) {
	var r SecretRow
	var at int64
	err := row.Scan(&r.ID, &r.Purpose, &r.Nonce, &r.Ciphertext, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return SecretRow{}, ErrNotFound
	}
	if err != nil {
		return SecretRow{}, err
	}
	r.CreatedAt = fromMS(at)
	return r, nil
}
