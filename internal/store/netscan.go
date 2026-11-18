package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// KeepScans is how many scan records are kept.
const KeepScans = 50

// ScanRow is a scan run record; Subnets and Stats are JSON.
type ScanRow struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt *time.Time
	Subnets    []byte
	Stats      []byte
	Error      string
}

// NetHost is a stored network host; the JSON columns are opaque to the store.
type NetHost struct {
	IP         string
	MAC        string
	Vendor     string
	RandomMAC  bool
	Names      json.RawMessage
	FirstSeen  time.Time
	LastSeen   time.Time
	LastScanID int64
	Alive      bool
	Source     string
	Ports      json.RawMessage
	Services   json.RawMessage
	Link       json.RawMessage
}

// BeginScan records the start of a scan and drops records beyond KeepScans.
func (s *Store) BeginScan(ctx context.Context, at time.Time, subnets []byte) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if len(subnets) == 0 {
		subnets = []byte("[]")
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO scans(started_at, subnets) VALUES (?, ?)`, ms(at), string(subnets))
	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)`, KeepScans); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// FinishScan closes a scan record with its statistics and error ("" if fine).
func (s *Store) FinishScan(ctx context.Context, id int64, at time.Time, stats []byte, errMsg string) error {
	if len(stats) == 0 {
		stats = []byte("{}")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE scans SET finished_at = ?, stats = ?, error = ? WHERE id = ?`, ms(at), string(stats), errMsg, id)
	return err
}

// LastScan returns the newest scan record that has finished (ErrNotFound if
// none did).
func (s *Store) LastScan(ctx context.Context) (ScanRow, error) {
	rows, err := s.ListScans(ctx, 1, true)
	if err != nil {
		return ScanRow{}, err
	}
	if len(rows) == 0 {
		return ScanRow{}, ErrNotFound
	}
	return rows[0], nil
}

// ListScans returns scan records, newest first.
func (s *Store) ListScans(ctx context.Context, limit int, finishedOnly bool) ([]ScanRow, error) {
	q := `SELECT id, started_at, finished_at, subnets, stats, error FROM scans`
	if finishedOnly {
		q += ` WHERE finished_at IS NOT NULL`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanRow
	for rows.Next() {
		var r ScanRow
		var st int64
		var fin sql.NullInt64
		var sub, stats string
		if err := rows.Scan(&r.ID, &st, &fin, &sub, &stats, &r.Error); err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt = fromMS(st), fromNullMS(fin)
		r.Subnets, r.Stats = []byte(sub), []byte(stats)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveScanHosts stores the hosts a scan found (first_seen and a known MAC are
// kept) and marks every other scanned host as not alive; their data stays.
func (s *Store) SaveScanHosts(ctx context.Context, scanID int64, hosts []NetHost) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, h := range hosts {
		_, err := tx.ExecContext(ctx, `INSERT INTO hosts(ip, mac, vendor, random_mac, names, first_seen, last_seen, last_scan_id, alive, source, ports, services, link)
			VALUES (?,?,?,?,?,?,?,?,1,?,?,?,?)
			ON CONFLICT(ip) DO UPDATE SET
				mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE hosts.mac END,
				vendor = CASE WHEN excluded.mac != '' THEN excluded.vendor ELSE hosts.vendor END,
				random_mac = CASE WHEN excluded.mac != '' THEN excluded.random_mac ELSE hosts.random_mac END,
				names = excluded.names, last_seen = excluded.last_seen, last_scan_id = excluded.last_scan_id,
				alive = 1, source = excluded.source, ports = excluded.ports, services = excluded.services, link = excluded.link`,
			h.IP, h.MAC, h.Vendor, b2i(h.RandomMAC), string(orJSON(h.Names, "[]")), ms(h.FirstSeen), ms(h.LastSeen), scanID, h.Source,
			string(orJSON(h.Ports, "[]")), string(orJSON(h.Services, "[]")), string(orJSON(h.Link, "null")))
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET alive = 0 WHERE last_scan_id != ? AND source = 'scan'`, scanID); err != nil {
		return err
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func orJSON(b json.RawMessage, def string) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage(def)
	}
	return b
}

// ListHosts returns all stored hosts (unordered).
func (s *Store) ListHosts(ctx context.Context) ([]NetHost, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ip, mac, vendor, random_mac, names, first_seen, last_seen, last_scan_id, alive, source, ports, services, link FROM hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetHost
	for rows.Next() {
		var h NetHost
		var rnd, alive int
		var fs, ls int64
		var names, ports, services, link string
		if err := rows.Scan(&h.IP, &h.MAC, &h.Vendor, &rnd, &names, &fs, &ls, &h.LastScanID, &alive, &h.Source, &ports, &services, &link); err != nil {
			return nil, err
		}
		h.RandomMAC, h.Alive = rnd != 0, alive != 0
		h.FirstSeen, h.LastSeen = fromMS(fs), fromMS(ls)
		h.Names, h.Ports, h.Services, h.Link = json.RawMessage(names), json.RawMessage(ports), json.RawMessage(services), json.RawMessage(link)
		out = append(out, h)
	}
	return out, rows.Err()
}

// DeleteHost forgets a host; ErrNotFound if it is not stored.
func (s *Store) DeleteHost(ctx context.Context, ip string) error {
	r, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE ip = ?`, ip)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
