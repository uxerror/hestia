package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Target kinds.
const (
	KindProxmox = "proxmox"
	KindSSH     = "ssh"
)

// Node is a cluster member (or the single node) of a Proxmox target.
type Node struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Online bool   `json:"online"`
	// Pinned SSH host key of the node (known_hosts type, SHA256 fingerprint).
	HostKeyFP   string `json:"host_key_fp"`
	HostKeyType string `json:"host_key_type"`
}

// Target is a connected system. It never carries secrets, only a reference
// to the encrypted API token.
type Target struct {
	ID             int64     `json:"id"`
	Kind           string    `json:"kind"`
	Name           string    `json:"name"`
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	SSHUser        string    `json:"ssh_user"`
	HostKeyFP      string    `json:"host_key_fp"`
	APICertFP      string    `json:"api_cert_fp"`
	Cluster        string    `json:"cluster"`
	TokenID        string    `json:"token_id"`
	TokenSecretRef int64     `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	Nodes          []Node    `json:"nodes"`
}

const targetCols = `id, kind, name, host, port, ssh_user, host_key_fp, api_cert_fp, cluster, token_id, token_secret_ref, created_at`

// CreateTarget inserts the target and its nodes atomically and sets t.ID.
// A duplicate name or host:port yields ErrDuplicate.
func (s *Store) CreateTarget(ctx context.Context, t *Target) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var ref any
	if t.TokenSecretRef != 0 {
		ref = t.TokenSecretRef
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO targets(kind, name, host, port, ssh_user, host_key_fp, api_cert_fp,
		cluster, token_id, token_secret_ref, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		t.Kind, t.Name, t.Host, t.Port, t.SSHUser, t.HostKeyFP, t.APICertFP, t.Cluster, t.TokenID, ref, ms(t.CreatedAt))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	if t.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	for _, n := range t.Nodes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO target_nodes(target_id, name, ip, online, host_key_fp, host_key_type) VALUES (?,?,?,?,?,?)`,
			t.ID, n.Name, n.IP, boolInt(n.Online), n.HostKeyFP, n.HostKeyType); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetTarget returns a target with its nodes.
func (s *Store) GetTarget(ctx context.Context, id int64) (Target, error) {
	t, err := scanTarget(s.db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE id = ?`, id))
	if err != nil {
		return Target{}, err
	}
	if t.Nodes, err = s.nodes(ctx, t.ID); err != nil {
		return Target{}, err
	}
	return t, nil
}

// FindTargetByAddr returns the target with the given host and port.
func (s *Store) FindTargetByAddr(ctx context.Context, host string, port int) (Target, error) {
	return scanTarget(s.db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE host = ? AND port = ?`, host, port))
}

// ListTargets returns all targets (with nodes), oldest first.
func (s *Store) ListTargets(ctx context.Context) ([]Target, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+targetCols+` FROM targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	for i := range out {
		if out[i].Nodes, err = s.nodes(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DeleteTarget removes the target, its nodes and its token secret.
func (s *Store) DeleteTarget(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var ref sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT token_secret_ref FROM targets WHERE id = ?`, id).Scan(&ref)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id); err != nil {
		return err
	}
	if ref.Valid {
		if _, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, ref.Int64); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) nodes(ctx context.Context, id int64) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, ip, online, host_key_fp, host_key_type FROM target_nodes WHERE target_id = ? ORDER BY name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		var n Node
		var on int
		if err := rows.Scan(&n.Name, &n.IP, &on, &n.HostKeyFP, &n.HostKeyType); err != nil {
			return nil, err
		}
		n.Online = on != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanTarget(row scanner) (Target, error) {
	var t Target
	var ref sql.NullInt64
	var at int64
	err := row.Scan(&t.ID, &t.Kind, &t.Name, &t.Host, &t.Port, &t.SSHUser, &t.HostKeyFP, &t.APICertFP,
		&t.Cluster, &t.TokenID, &ref, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, err
	}
	t.TokenSecretRef = ref.Int64
	t.CreatedAt = fromMS(at)
	t.Nodes = []Node{}
	return t, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
