package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

// Link statuses beyond the health of an active link (ok, degraded, down,
// unknown).
const (
	LinkDraft    = "draft"    // created by a plan, not applied yet (hidden)
	LinkApplying = "applying" // being created by a job
	LinkRemoving = "removing" // being removed by a job
	LinkOrphaned = "orphaned" // removal failed on a side; only the record can go
)

// Link kinds.
const (
	LinkKindService = "service"
	LinkKindDevice  = "device"
)

// PluginLink connects a provides port of an instance to a requires port of
// another instance (service) or to a device. Binding never holds secret
// values, only references.
type PluginLink struct {
	ID               int64
	Kind             string
	ProviderInstance int64
	ProviderPort     string
	ConsumerInstance int64 // 0 for a device link
	ConsumerPort     string
	DeviceRef        string // "" for a service link
	Config           string
	Binding          string
	Status           string
	Detail           string
	CreatedAt        time.Time
	CheckedAt        *time.Time
	// Request is what the consumer asked for (types with a request, e.g.
	// tls.cert: the CSR and the names); "{}" otherwise.
	Request string
	// Renewal of renewable types: when the binding expires, when to renew
	// it, the last renewal error and when to retry.
	ExpiresAt    *time.Time
	RenewAfter   *time.Time
	RenewError   string
	RenewRetryAt *time.Time
}

// Active reports whether the link is in use (not a draft, not being
// removed, not orphaned).
func (l PluginLink) Active() bool {
	switch l.Status {
	case LinkDraft, LinkRemoving, LinkOrphaned:
		return false
	}
	return true
}

const linkCols = `id, kind, provider_instance, provider_port, consumer_instance, consumer_port, device_ref, config, binding,
	status, detail, created_at, checked_at, request, expires_at, renew_after, renew_error, renew_retry_at`

func scanLink(sc interface{ Scan(...any) error }) (PluginLink, error) {
	var (
		l       PluginLink
		cons    sql.NullInt64
		cport   sql.NullString
		dev     sql.NullString
		created int64
		checked sql.NullInt64

		expires, renew, retry sql.NullInt64
	)
	err := sc.Scan(&l.ID, &l.Kind, &l.ProviderInstance, &l.ProviderPort, &cons, &cport, &dev, &l.Config, &l.Binding,
		&l.Status, &l.Detail, &created, &checked, &l.Request, &expires, &renew, &l.RenewError, &retry)
	if errors.Is(err, sql.ErrNoRows) {
		return l, ErrNotFound
	}
	l.ConsumerInstance, l.ConsumerPort, l.DeviceRef = cons.Int64, cport.String, dev.String
	l.CreatedAt, l.CheckedAt = fromMS(created), fromNullMS(checked)
	l.ExpiresAt, l.RenewAfter, l.RenewRetryAt = fromNullMS(expires), fromNullMS(renew), fromNullMS(retry)
	return l, err
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullStr(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// CreateLink inserts a link and sets l.ID; a link that already exists
// (same ports or the same device) yields ErrDuplicate.
func (s *Store) CreateLink(ctx context.Context, l *PluginLink) error {
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	if l.Config == "" {
		l.Config = "{}"
	}
	if l.Binding == "" {
		l.Binding = "{}"
	}
	if l.Status == "" {
		l.Status = LinkDraft
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO plugin_links(kind, provider_instance, provider_port, consumer_instance, consumer_port,
		device_ref, config, binding, status, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.Kind, l.ProviderInstance, l.ProviderPort, nullInt(l.ConsumerInstance), nullStr(l.ConsumerPort), nullStr(l.DeviceRef),
		l.Config, l.Binding, l.Status, l.Detail, ms(l.CreatedAt))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	l.ID, err = res.LastInsertId()
	return err
}

// GetLink returns a link.
func (s *Store) GetLink(ctx context.Context, id int64) (PluginLink, error) {
	return scanLink(s.db.QueryRowContext(ctx, `SELECT `+linkCols+` FROM plugin_links WHERE id = ?`, id))
}

func (s *Store) queryLinks(ctx context.Context, where string, args ...any) ([]PluginLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+linkCols+` FROM plugin_links WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PluginLink{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListLinks returns every link except drafts.
func (s *Store) ListLinks(ctx context.Context) ([]PluginLink, error) {
	return s.queryLinks(ctx, `status != ?`, LinkDraft)
}

// LinksOfInstance returns the links (not drafts) where the instance is the
// provider or the consumer.
func (s *Store) LinksOfInstance(ctx context.Context, iid int64) ([]PluginLink, error) {
	return s.queryLinks(ctx, `status != ? AND (provider_instance = ? OR consumer_instance = ?)`, LinkDraft, iid, iid)
}

// DuplicateLink returns an existing link (draft or not) with the same ends.
func (s *Store) DuplicateLink(ctx context.Context, l PluginLink) (PluginLink, error) {
	var (
		list []PluginLink
		err  error
	)
	if l.Kind == LinkKindDevice {
		list, err = s.queryLinks(ctx, `kind = ? AND provider_instance = ? AND provider_port = ? AND device_ref = ?`,
			LinkKindDevice, l.ProviderInstance, l.ProviderPort, l.DeviceRef)
	} else {
		list, err = s.queryLinks(ctx, `kind = ? AND provider_instance = ? AND provider_port = ? AND consumer_instance = ? AND consumer_port = ?`,
			LinkKindService, l.ProviderInstance, l.ProviderPort, l.ConsumerInstance, l.ConsumerPort)
	}
	if err != nil {
		return PluginLink{}, err
	}
	if len(list) == 0 {
		return PluginLink{}, ErrNotFound
	}
	return list[0], nil
}

// CountPortLinks counts the links (not drafts) on a port: as provider
// (provides) or as consumer.
func (s *Store) CountPortLinks(ctx context.Context, iid int64, port string, provides bool) (int, error) {
	q := `SELECT COUNT(*) FROM plugin_links WHERE status != ? AND consumer_instance = ? AND consumer_port = ?`
	if provides {
		q = `SELECT COUNT(*) FROM plugin_links WHERE status != ? AND provider_instance = ? AND provider_port = ?`
	}
	var n int
	err := s.db.QueryRowContext(ctx, q, LinkDraft, iid, port).Scan(&n)
	return n, err
}

// ActivateLink turns a draft into a link being applied; a device link gets
// its grant (the device becomes a target of the provider instance through
// the link). It fails with ErrNotFound if the draft is gone.
func (s *Store) ActivateLink(ctx context.Context, id int64, deviceKind string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Write first: a read would have to upgrade its lock (SQLITE_BUSY).
	res, err := tx.ExecContext(ctx, `UPDATE plugin_links SET status = ?, created_at = ? WHERE id = ? AND status = ?`,
		LinkApplying, ms(time.Now()), id, LinkDraft)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_grants(instance_id, target_kind, target_ref, via_link)
		SELECT provider_instance, ?, device_ref, id FROM plugin_links WHERE id = ? AND kind = ?`, deviceKind, id, LinkKindDevice); err != nil {
		return err
	}
	return tx.Commit()
}

// SetLinkStatus records the state of a link (checkedAt nil keeps the time).
func (s *Store) SetLinkStatus(ctx context.Context, id int64, status, detail string, checkedAt *time.Time) error {
	if checkedAt == nil {
		_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET status = ?, detail = ? WHERE id = ?`, status, detail, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET status = ?, detail = ?, checked_at = ? WHERE id = ?`,
		status, detail, ms(*checkedAt), id)
	return err
}

// SetLinkHealth records the result of a status check unless the link is
// being changed (applying, removing) or is orphaned meanwhile.
func (s *Store) SetLinkHealth(ctx context.Context, id int64, status, detail string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET status = ?, detail = ?, checked_at = ?
		WHERE id = ? AND status NOT IN (?, ?, ?, ?)`, status, detail, ms(at), id, LinkDraft, LinkApplying, LinkRemoving, LinkOrphaned)
	return err
}

// SetLinkBinding stores the binding of a link (references only).
func (s *Store) SetLinkBinding(ctx context.Context, id int64, binding string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET binding = ? WHERE id = ?`, binding, id)
	return err
}

// SetLinkRequest stores the request of a link (what the consumer asked).
func (s *Store) SetLinkRequest(ctx context.Context, id int64, request string) error {
	if request == "" {
		request = "{}"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET request = ? WHERE id = ?`, request, id)
	return err
}

// SetLinkRenewal records a renewed (or first) binding of a renewable link:
// the expiry, when to renew and a cleared renewal error.
func (s *Store) SetLinkRenewal(ctx context.Context, id int64, expires, renewAfter time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET expires_at = ?, renew_after = ?, renew_error = '', renew_retry_at = NULL
		WHERE id = ?`, ms(expires), ms(renewAfter), id)
	return err
}

// SetLinkRenewError records a failed renewal and when to try again.
func (s *Store) SetLinkRenewError(ctx context.Context, id int64, msg string, retryAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_links SET renew_error = ?, renew_retry_at = ? WHERE id = ?`, msg, ms(retryAt), id)
	return err
}

// DueRenewals returns the active links whose renewal is due at now (and
// whose retry time, if any, has come).
func (s *Store) DueRenewals(ctx context.Context, now time.Time) ([]PluginLink, error) {
	return s.queryLinks(ctx, `renew_after IS NOT NULL AND renew_after <= ? AND (renew_retry_at IS NULL OR renew_retry_at <= ?)
		AND status NOT IN (?, ?, ?, ?)`, ms(now), ms(now), LinkDraft, LinkApplying, LinkRemoving, LinkOrphaned)
}

// DeleteLink removes a link; its grants go with it.
func (s *Store) DeleteLink(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM plugin_links WHERE id = ?`, id)
	return err
}

// ---- map positions ----

// Position is where the user put a node of the map.
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// MaxPositions bounds the stored positions.
const MaxPositions = 2000

// Positions returns the saved positions of map nodes.
func (s *Store) Positions(ctx context.Context) (map[string]Position, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, x, y FROM map_positions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Position{}
	for rows.Next() {
		var id string
		var p Position
		if err := rows.Scan(&id, &p.X, &p.Y); err != nil {
			return nil, err
		}
		out[id] = p
	}
	return out, rows.Err()
}

// SavePositions upserts positions; beyond MaxPositions the oldest go.
func (s *Store) SavePositions(ctx context.Context, ps map[string]Position) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := ms(time.Now())
	for id, p := range ps {
		if math.IsNaN(p.X) || math.IsNaN(p.Y) || math.IsInf(p.X, 0) || math.IsInf(p.Y, 0) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO map_positions(node_id, x, y, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(node_id) DO UPDATE SET x = excluded.x, y = excluded.y, updated_at = excluded.updated_at`, id, p.X, p.Y, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM map_positions WHERE node_id NOT IN
		(SELECT node_id FROM map_positions ORDER BY updated_at DESC, node_id LIMIT ?)`, MaxPositions); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearPositions forgets every saved position.
func (s *Store) ClearPositions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM map_positions`)
	return err
}
