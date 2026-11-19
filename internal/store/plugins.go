package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Plugin sources.
const (
	PluginSourceCatalog = "catalog"
	PluginSourceFile    = "file"
	PluginSourceDev     = "dev"
	// URL sources are "url:<address>".
)

// DevAuthorKey is the pseudo author of plugins started with --plugin-dev
// (never a real base64 key, so it cannot collide with a pinned one).
const DevAuthorKey = "dev"

// Instance statuses beyond the plugin's own (ok/degraded/down/unknown).
const InstanceDraft = "draft" // created by a plan of "create", not applied yet

// PluginAuthor is a pinned author key.
type PluginAuthor struct {
	Key      string    `json:"key"`
	Name     string    `json:"name"`
	Official bool      `json:"official"`
	PinnedAt time.Time `json:"pinned_at"`
}

// Plugin is an installed plugin. TokenHash is the sha256 (hex) of its token.
type Plugin struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	PrevVersion string    `json:"prev_version"`
	AuthorKey   string    `json:"author_key"`
	Manifest    string    `json:"-"`
	Source      string    `json:"source"`
	Enabled     bool      `json:"enabled"`
	TokenHash   string    `json:"-"`
	Readme      string    `json:"-"`
	Icon        string    `json:"-"`
	InstalledAt time.Time `json:"installed_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PluginInstance is a configuration of a plugin. Config never holds secret
// values, only references.
type PluginInstance struct {
	ID        int64  `json:"id"`
	PluginID  string `json:"plugin_id"`
	Name      string `json:"name"`
	Config    string `json:"-"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Endpoints string `json:"-"`
	// Containers is the last known list of the instance's containers
	// (JSON, recorded from deploy.* answers).
	Containers string     `json:"-"`
	CheckedAt  *time.Time `json:"checked_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

// PluginGrant gives an instance access to a target.
type PluginGrant struct {
	Kind string `json:"kind"` // ssh | lxc
	Ref  string `json:"ref"`  // ssh:<target> | lxc:<target>:<node>:<vmid>
}

// PinAuthor stores an author key unless it is already pinned.
func (s *Store) PinAuthor(ctx context.Context, a PluginAuthor) error {
	if a.PinnedAt.IsZero() {
		a.PinnedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO plugin_authors(key, name, official, pinned_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO NOTHING`, a.Key, a.Name, boolInt(a.Official), ms(a.PinnedAt))
	return err
}

// GetAuthor returns a pinned author.
func (s *Store) GetAuthor(ctx context.Context, key string) (PluginAuthor, error) {
	var a PluginAuthor
	var off int
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT key, name, official, pinned_at FROM plugin_authors WHERE key = ?`, key).
		Scan(&a.Key, &a.Name, &off, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.Official, a.PinnedAt = off != 0, fromMS(at)
	return a, err
}

// ListAuthors returns pinned authors (without the dev pseudo author).
func (s *Store) ListAuthors(ctx context.Context) ([]PluginAuthor, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, name, official, pinned_at FROM plugin_authors WHERE key != ? ORDER BY pinned_at`, DevAuthorKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PluginAuthor{}
	for rows.Next() {
		var a PluginAuthor
		var off int
		var at int64
		if err := rows.Scan(&a.Key, &a.Name, &off, &at); err != nil {
			return nil, err
		}
		a.Official, a.PinnedAt = off != 0, fromMS(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAuthor forgets an author key; it fails with ErrDuplicate while a
// plugin of the author is installed.
func (s *Store) DeleteAuthor(ctx context.Context, key string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugins WHERE author_key = ?`, key).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrDuplicate
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM plugin_authors WHERE key = ?`, key)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	return nil
}

const pluginCols = `id, version, prev_version, author_key, manifest, source, enabled, token_hash, readme, icon, installed_at, updated_at`

func scanPlugin(sc interface{ Scan(...any) error }) (Plugin, error) {
	var p Plugin
	var en int
	var inst, upd int64
	err := sc.Scan(&p.ID, &p.Version, &p.PrevVersion, &p.AuthorKey, &p.Manifest, &p.Source, &en, &p.TokenHash,
		&p.Readme, &p.Icon, &inst, &upd)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	p.Enabled, p.InstalledAt, p.UpdatedAt = en != 0, fromMS(inst), fromMS(upd)
	return p, err
}

// SavePlugin inserts or replaces an installed plugin (and pins its author
// in the same transaction when author is not nil).
func (s *Store) SavePlugin(ctx context.Context, p Plugin, author *PluginAuthor) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	if author != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_authors(key, name, official, pinned_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO NOTHING`, author.Key, author.Name, boolInt(author.Official), ms(now)); err != nil {
			return err
		}
	}
	if p.InstalledAt.IsZero() {
		p.InstalledAt = now
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO plugins(`+pluginCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET version = excluded.version, prev_version = excluded.prev_version,
		author_key = excluded.author_key, manifest = excluded.manifest, source = excluded.source,
		enabled = excluded.enabled, token_hash = excluded.token_hash, readme = excluded.readme,
		icon = excluded.icon, updated_at = excluded.updated_at`,
		p.ID, p.Version, p.PrevVersion, p.AuthorKey, p.Manifest, p.Source, boolInt(p.Enabled), p.TokenHash,
		p.Readme, p.Icon, ms(p.InstalledAt), ms(now))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// GetPlugin returns an installed plugin.
func (s *Store) GetPlugin(ctx context.Context, id string) (Plugin, error) {
	return scanPlugin(s.db.QueryRowContext(ctx, `SELECT `+pluginCols+` FROM plugins WHERE id = ?`, id))
}

// ListPlugins returns installed plugins by id.
func (s *Store) ListPlugins(ctx context.Context) ([]Plugin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+pluginCols+` FROM plugins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Plugin{}
	for rows.Next() {
		p, err := scanPlugin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPluginEnabled switches a plugin on or off.
func (s *Store) SetPluginEnabled(ctx context.Context, id string, on bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugins SET enabled = ?, updated_at = ? WHERE id = ?`, boolInt(on), ms(time.Now()), id)
	return err
}

// DeletePlugin removes a plugin with its (draft) instances; it fails with
// ErrDuplicate while real instances exist.
func (s *Store) DeletePlugin(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_instances WHERE plugin_id = ? AND status != ?`, id, InstanceDraft).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrDuplicate
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_links WHERE status = ? AND (provider_instance IN (SELECT id FROM plugin_instances WHERE plugin_id = ?)
		OR consumer_instance IN (SELECT id FROM plugin_instances WHERE plugin_id = ?))`, LinkDraft, id, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_instances WHERE plugin_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugins WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

const instanceCols = `id, plugin_id, name, config, status, detail, endpoints, containers, checked_at, created_at`

func scanInstance(sc interface{ Scan(...any) error }) (PluginInstance, error) {
	var in PluginInstance
	var checked sql.NullInt64
	var created int64
	err := sc.Scan(&in.ID, &in.PluginID, &in.Name, &in.Config, &in.Status, &in.Detail, &in.Endpoints, &in.Containers, &checked, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return in, ErrNotFound
	}
	in.CheckedAt, in.CreatedAt = fromNullMS(checked), fromMS(created)
	return in, err
}

// CreateInstance inserts an instance with its grants and sets in.ID. A
// duplicate name within the plugin yields ErrDuplicate.
func (s *Store) CreateInstance(ctx context.Context, in *PluginInstance, grants []PluginGrant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	if in.Status == "" {
		in.Status = "unknown"
	}
	if in.Endpoints == "" {
		in.Endpoints = "[]"
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO plugin_instances(plugin_id, name, config, status, detail, endpoints, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, in.PluginID, in.Name, in.Config, in.Status, in.Detail, in.Endpoints, ms(in.CreatedAt))
	if err != nil {
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	if in.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	if err := replaceGrants(ctx, tx, in.ID, grants); err != nil {
		return err
	}
	return tx.Commit()
}

// replaceGrants replaces the instance's own grants (grants through links
// stay).
func replaceGrants(ctx context.Context, tx *sql.Tx, id int64, grants []PluginGrant) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_grants WHERE instance_id = ? AND via_link IS NULL`, id); err != nil {
		return err
	}
	for _, g := range grants {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO plugin_grants(instance_id, target_kind, target_ref) VALUES (?, ?, ?)`,
			id, g.Kind, g.Ref); err != nil {
			return err
		}
	}
	return nil
}

// UpdateInstanceConfig replaces the configuration and grants of an instance
// (and its status, e.g. draft → unknown).
func (s *Store) UpdateInstanceConfig(ctx context.Context, id int64, config, status string, grants []PluginGrant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE plugin_instances SET config = ?, status = ? WHERE id = ?`, config, status, id); err != nil {
		return err
	}
	if err := replaceGrants(ctx, tx, id, grants); err != nil {
		return err
	}
	return tx.Commit()
}

// SetInstanceStatus records the last status of an instance.
func (s *Store) SetInstanceStatus(ctx context.Context, id int64, status, detail, endpoints string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_instances SET status = ?, detail = ?, endpoints = ?, checked_at = ?
		WHERE id = ? AND status != ?`, status, detail, endpoints, ms(at), id, InstanceDraft)
	return err
}

// GetInstance returns an instance.
func (s *Store) GetInstance(ctx context.Context, id int64) (PluginInstance, error) {
	return scanInstance(s.db.QueryRowContext(ctx, `SELECT `+instanceCols+` FROM plugin_instances WHERE id = ?`, id))
}

// ListInstances returns the instances of a plugin ("" for all plugins),
// drafts only when withDrafts.
func (s *Store) ListInstances(ctx context.Context, pluginID string, withDrafts bool) ([]PluginInstance, error) {
	q := `SELECT ` + instanceCols + ` FROM plugin_instances WHERE (? = '' OR plugin_id = ?)`
	if !withDrafts {
		q += ` AND status != '` + InstanceDraft + `'`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY id`, pluginID, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PluginInstance{}
	for rows.Next() {
		in, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// DeleteInstance removes an instance (grants and draft links go with it).
// It fails while real links of the instance exist (they are removed first).
func (s *Store) DeleteInstance(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_links WHERE status = ? AND (provider_instance = ? OR consumer_instance = ?)`,
		LinkDraft, id, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_instances WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDrafts removes draft instances (all of them when pluginID is "",
// otherwise those of the plugin with the given name) and draft links.
func (s *Store) DeleteDrafts(ctx context.Context, pluginID, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	cond := `status = ? AND (? = '' OR (plugin_id = ? AND name = ?))`
	args := []any{InstanceDraft, pluginID, pluginID, name}
	sel := `SELECT id FROM plugin_instances WHERE ` + cond
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_links WHERE status = ? AND (provider_instance IN (`+sel+`) OR consumer_instance IN (`+sel+`))`,
		append(append([]any{LinkDraft}, args...), args...)...); err != nil {
		return err
	}
	if pluginID == "" {
		// Draft links of real instances (a plan of a link) go too.
		if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_links WHERE status = ?`, LinkDraft); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_instances WHERE `+cond, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// SetInstanceContainers records the last known containers of an instance.
func (s *Store) SetInstanceContainers(ctx context.Context, id int64, containers string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE plugin_instances SET containers = ? WHERE id = ?`, containers, id)
	return err
}

// Grants returns the instance's own grants (not those through links).
func (s *Store) Grants(ctx context.Context, instanceID int64) ([]PluginGrant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_kind, target_ref FROM plugin_grants WHERE instance_id = ? AND via_link IS NULL ORDER BY target_ref`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PluginGrant{}
	for rows.Next() {
		var g PluginGrant
		if err := rows.Scan(&g.Kind, &g.Ref); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// HasGrant reports whether the target is granted to the instance directly
// (grants through links count only within calls of their link, see
// HasLinkGrant).
func (s *Store) HasGrant(ctx context.Context, instanceID int64, ref string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_grants WHERE instance_id = ? AND target_ref = ? AND via_link IS NULL`, instanceID, ref).Scan(&n)
	return n > 0, err
}

// HasLinkGrant reports whether the target is granted to the instance
// through the given link.
func (s *Store) HasLinkGrant(ctx context.Context, instanceID int64, ref string, link int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plugin_grants WHERE instance_id = ? AND target_ref = ? AND via_link = ?`,
		instanceID, ref, link).Scan(&n)
	return n > 0, err
}

// SecretIDsByPrefix returns the ids of secrets whose purpose starts with
// prefix (compared literally, not as a LIKE pattern).
func (s *Store) SecretIDsByPrefix(ctx context.Context, prefix string) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM secrets WHERE substr(purpose, 1, ?) = ? ORDER BY id`, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DeleteSecretsByPrefix removes every secret whose purpose starts with prefix.
func (s *Store) DeleteSecretsByPrefix(ctx context.Context, prefix string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE substr(purpose, 1, ?) = ?`, len(prefix), prefix)
	return err
}

// DeleteSecretsByPurpose removes every secret with exactly this purpose.
func (s *Store) DeleteSecretsByPurpose(ctx context.Context, purpose string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE purpose = ?`, purpose)
	return err
}

// PluginCatalog is the cached official catalog: IndexJSON is set only after
// its signature was verified; Error is the last failure ("" after success).
type PluginCatalog struct {
	FetchedAt *time.Time
	IndexJSON string
	Error     string
}

// GetPluginCatalog returns the cached catalog (zero value if never fetched).
func (s *Store) GetPluginCatalog(ctx context.Context) (PluginCatalog, error) {
	var (
		c   PluginCatalog
		at  sql.NullInt64
		idx sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `SELECT fetched_at, index_json, error FROM plugin_catalog WHERE id = 1`).Scan(&at, &idx, &c.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return PluginCatalog{}, nil
	}
	if err != nil {
		return c, err
	}
	if at.Valid {
		t := fromMS(at.Int64)
		c.FetchedAt = &t
	}
	c.IndexJSON = idx.String
	return c, nil
}

// SetPluginCatalog stores the catalog state.
func (s *Store) SetPluginCatalog(ctx context.Context, c PluginCatalog) error {
	var idx any
	if c.IndexJSON != "" {
		idx = c.IndexJSON
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO plugin_catalog(id, fetched_at, index_json, error) VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET fetched_at = excluded.fetched_at, index_json = excluded.index_json, error = excluded.error`,
		nullMS(c.FetchedAt), idx, c.Error)
	return err
}
