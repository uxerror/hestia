package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// InventoryRow is the stored inventory snapshot of a target. Data is the JSON
// produced by package inventory (empty if nothing was collected yet); Error is
// the failure of the last collection (the previous Data is kept).
type InventoryRow struct {
	TargetID    int64
	CollectedAt time.Time // zero if never collected
	Data        []byte
	Error       string
}

// PutInventory stores a fresh snapshot and clears the error.
func (s *Store) PutInventory(ctx context.Context, targetID int64, at time.Time, data []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO inventory(target_id, collected_at, data, error) VALUES (?,?,?, '')
		ON CONFLICT(target_id) DO UPDATE SET collected_at = excluded.collected_at, data = excluded.data, error = ''`,
		targetID, ms(at), string(data))
	return err
}

// SetInventoryError records a failed collection and keeps the last snapshot.
func (s *Store) SetInventoryError(ctx context.Context, targetID int64, msg string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO inventory(target_id, error) VALUES (?,?)
		ON CONFLICT(target_id) DO UPDATE SET error = excluded.error`, targetID, msg)
	return err
}

// GetInventory returns the row of a target; ErrNotFound if there is none.
func (s *Store) GetInventory(ctx context.Context, targetID int64) (InventoryRow, error) {
	r, err := scanInventory(s.db.QueryRowContext(ctx, `SELECT target_id, collected_at, data, error FROM inventory WHERE target_id = ?`, targetID))
	return r, err
}

// ListInventory returns all rows.
func (s *Store) ListInventory(ctx context.Context) ([]InventoryRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id, collected_at, data, error FROM inventory ORDER BY target_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryRow
	for rows.Next() {
		r, err := scanInventory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanInventory(row scanner) (InventoryRow, error) {
	var r InventoryRow
	var at int64
	var data string
	err := row.Scan(&r.TargetID, &at, &data, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return InventoryRow{}, ErrNotFound
	}
	if err != nil {
		return InventoryRow{}, err
	}
	if at > 0 {
		r.CollectedAt = fromMS(at)
	}
	r.Data = []byte(data)
	return r, nil
}
