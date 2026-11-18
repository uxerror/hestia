package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Integration kinds.
const KindAdGuard = "adguard"

// Integration is a saved connection to a service of the network (AdGuard
// Home). It never carries the password, only a reference to the encrypted
// secret.
type Integration struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	BaseURL   string    `json:"base_url"`
	TLSPin    string    `json:"tls_pin"`
	Username  string    `json:"username"`
	SecretID  int64     `json:"-"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DNSName is the DNS name given to the controller through an integration.
type DNSName struct {
	ID            int64      `json:"id"`
	IntegrationID int64      `json:"integration_id"`
	Domain        string     `json:"domain"`
	Answer        string     `json:"answer"`
	Status        string     `json:"status"`
	StatusDetail  string     `json:"status_detail"`
	VerifiedAt    *time.Time `json:"verified_at"`
	CheckedAt     *time.Time `json:"checked_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

const integrationCols = `id, kind, name, base_url, tls_pin, username, secret_id, version, created_at, updated_at`

// NextIntegrationID returns the id the next integration will get. The id is
// needed before the insert: it is part of the purpose its secret is bound to.
// Callers serialize creation.
func (s *Store) NextIntegrationID(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(id) FROM integrations`).Scan(&n); err != nil {
		return 0, err
	}
	return n.Int64 + 1, nil
}

// CreateIntegration inserts the integration with the id already set.
func (s *Store) CreateIntegration(ctx context.Context, in *Integration) error {
	now := time.Now().UTC()
	in.CreatedAt, in.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx, `INSERT INTO integrations(`+integrationCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.Kind, in.Name, in.BaseURL, in.TLSPin, in.Username, in.SecretID, in.Version, ms(now), ms(now))
	return err
}

// UpdateIntegration rewrites the editable fields (connection, secret
// reference, version).
func (s *Store) UpdateIntegration(ctx context.Context, in *Integration) error {
	in.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE integrations SET name = ?, base_url = ?, tls_pin = ?, username = ?,
		secret_id = ?, version = ?, updated_at = ? WHERE id = ?`,
		in.Name, in.BaseURL, in.TLSPin, in.Username, in.SecretID, in.Version, ms(in.UpdatedAt), in.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetIntegrationByKind returns the oldest integration of a kind.
func (s *Store) GetIntegrationByKind(ctx context.Context, kind string) (Integration, error) {
	var in Integration
	var c, u int64
	err := s.db.QueryRowContext(ctx, `SELECT `+integrationCols+` FROM integrations WHERE kind = ? ORDER BY id LIMIT 1`, kind).
		Scan(&in.ID, &in.Kind, &in.Name, &in.BaseURL, &in.TLSPin, &in.Username, &in.SecretID, &in.Version, &c, &u)
	if errors.Is(err, sql.ErrNoRows) {
		return Integration{}, ErrNotFound
	}
	if err != nil {
		return Integration{}, err
	}
	in.CreatedAt, in.UpdatedAt = fromMS(c), fromMS(u)
	return in, nil
}

// DeleteIntegration removes the integration, its names (cascade) and its secret.
func (s *Store) DeleteIntegration(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var secret int64
	err = tx.QueryRowContext(ctx, `DELETE FROM integrations WHERE id = ? RETURNING secret_id`, id).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, secret); err != nil {
		return err
	}
	return tx.Commit()
}

const dnsNameCols = `id, integration_id, domain, answer, status, status_detail, verified_at, checked_at, created_at`

// GetDNSName returns the name of the controller (one per controller in this
// stage), or ErrNotFound.
func (s *Store) GetDNSName(ctx context.Context) (DNSName, error) {
	var n DNSName
	var v, c sql.NullInt64
	var cr int64
	err := s.db.QueryRowContext(ctx, `SELECT `+dnsNameCols+` FROM dns_names ORDER BY id LIMIT 1`).
		Scan(&n.ID, &n.IntegrationID, &n.Domain, &n.Answer, &n.Status, &n.StatusDetail, &v, &c, &cr)
	if errors.Is(err, sql.ErrNoRows) {
		return DNSName{}, ErrNotFound
	}
	if err != nil {
		return DNSName{}, err
	}
	n.VerifiedAt, n.CheckedAt, n.CreatedAt = fromNullMS(v), fromNullMS(c), fromMS(cr)
	return n, nil
}

// SaveDNSName replaces the controller's name with n (one name per controller).
func (s *Store) SaveDNSName(ctx context.Context, n *DNSName) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_names`); err != nil {
		return err
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	if n.Status == "" {
		n.Status = "ok"
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO dns_names(integration_id, domain, answer, status, status_detail, verified_at, checked_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		n.IntegrationID, n.Domain, n.Answer, n.Status, n.StatusDetail, nullMS(n.VerifiedAt), nullMS(n.CheckedAt), ms(n.CreatedAt))
	if err != nil {
		return err
	}
	if n.ID, err = r.LastInsertId(); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDNSNameStatus records the result of a check. A nil verified keeps the
// stored verification time; answer "" keeps the stored answer.
func (s *Store) UpdateDNSNameStatus(ctx context.Context, id int64, status, detail, answer string, checked time.Time, verified *time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE dns_names SET status = ?, status_detail = ?, checked_at = ?,
		answer = CASE WHEN ? = '' THEN answer ELSE ? END,
		verified_at = COALESCE(?, verified_at) WHERE id = ?`,
		status, detail, ms(checked), answer, answer, nullMS(verified), id)
	return err
}

// DeleteDNSName removes the controller's name.
func (s *Store) DeleteDNSName(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_names WHERE id = ?`, id)
	return err
}
