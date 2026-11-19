package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

// Connection states of a plugin.
const (
	StateConnected    = "connected"
	StateDisconnected = "disconnected"
	StateUnresponsive = "unresponsive"
	StateDisabled     = "disabled"
)

// PluginView is an installed plugin as the API shows it.
type PluginView struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Version       string      `json:"version"`
	PrevVersion   string      `json:"prev_version"`
	Description   string      `json:"description"`
	Homepage      string      `json:"homepage"`
	Author        AuthorView  `json:"author"`
	Source        string      `json:"source"`
	Dev           bool        `json:"dev"`
	Enabled       bool        `json:"enabled"`
	State         string      `json:"state"`
	Permissions   []string    `json:"permissions"`
	Provides      []sdk.Port  `json:"provides"`
	Requires      []sdk.Port  `json:"requires"`
	MultiInstance bool        `json:"multi_instance"`
	Instances     int         `json:"instances"`
	HasIcon       bool        `json:"has_icon"`
	Update        *UpdateDiff `json:"update"`
	InstalledAt   time.Time   `json:"installed_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// PluginDetail adds the manifest and README.
type PluginDetail struct {
	PluginView
	Manifest json.RawMessage `json:"manifest"`
	Readme   string          `json:"readme"`
	Unit     *UnitView       `json:"unit,omitempty"`
}

// UnitView is the systemd state of the plugin's unit.
type UnitView struct {
	Active string `json:"active"`
	Error  string `json:"error"`
}

// List is GET /plugins.
type List struct {
	Available bool         `json:"available"`
	Reason    string       `json:"reason"`
	DevError  string       `json:"dev_error,omitempty"`
	Plugins   []PluginView `json:"plugins"`
}

// List returns the installed plugins with their connection state.
func (m *Manager) List(ctx context.Context) (List, error) {
	ok, reason := m.Availability(ctx)
	out := List{Available: ok, Reason: reason, DevError: m.DevError(), Plugins: []PluginView{}}
	ps, err := m.Store.ListPlugins(ctx)
	if err != nil {
		return out, err
	}
	insts, err := m.Store.ListInstances(ctx, "", false)
	if err != nil {
		return out, err
	}
	updates := m.catalogUpdates(ctx, ps)
	for _, p := range ps {
		v := m.view(p)
		v.Update = updates[p.ID]
		for _, in := range insts {
			if in.PluginID == p.ID {
				v.Instances++
			}
		}
		out.Plugins = append(out.Plugins, v)
	}
	return out, nil
}

func (m *Manager) view(p store.Plugin) PluginView {
	man, _ := ParseManifest([]byte(p.Manifest))
	v := PluginView{
		ID: p.ID, Name: man.Name, Version: p.Version, PrevVersion: p.PrevVersion, Description: man.Description,
		Homepage: man.Homepage, Source: p.Source, Dev: p.Source == store.PluginSourceDev, Enabled: p.Enabled,
		Permissions: nonNil(man.Permissions), Provides: nonNilPorts(man.Provides), Requires: nonNilPorts(man.Requires),
		MultiInstance: man.MultiInstance, HasIcon: p.Icon != "", InstalledAt: p.InstalledAt, UpdatedAt: p.UpdatedAt,
		Author: AuthorView{Name: man.Author.Name, Key: man.Author.Key, Fingerprint: Fingerprint(man.Author.Key),
			Official: p.Source != store.PluginSourceDev && IsOfficialKey(p.AuthorKey)},
	}
	if v.Name == "" {
		v.Name = p.ID
	}
	switch s := m.conn(p.ID); {
	case !p.Enabled:
		v.State = StateDisabled
	case s == nil:
		v.State = StateDisconnected
	default:
		s.mu.Lock()
		un := s.unresponsive
		s.mu.Unlock()
		v.State = StateConnected
		if un {
			v.State = StateUnresponsive
		}
	}
	return v
}

// Get returns one plugin; withUnit asks systemd (root path) about its unit.
func (m *Manager) Get(ctx context.Context, id string, withUnit bool) (*PluginDetail, error) {
	p, err := m.Store.GetPlugin(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, newErr(http.StatusNotFound, "плагин не найден")
	}
	if err != nil {
		return nil, err
	}
	insts, err := m.Store.ListInstances(ctx, id, false)
	if err != nil {
		return nil, err
	}
	d := &PluginDetail{PluginView: m.view(p), Manifest: json.RawMessage(p.Manifest), Readme: p.Readme}
	d.Update = m.catalogUpdates(ctx, []store.Plugin{p})[p.ID]
	d.Instances = len(insts)
	if withUnit && p.Source != store.PluginSourceDev {
		st, err := m.UnitState(ctx, id)
		d.Unit = &UnitView{Active: st}
		if err != nil {
			d.Unit.Error = err.Error()
		}
	}
	return d, nil
}

// Icon returns the sanitised icon of a plugin.
func (m *Manager) Icon(ctx context.Context, id string) ([]byte, error) {
	p, err := m.Store.GetPlugin(ctx, id)
	if err != nil {
		return nil, err
	}
	if p.Icon == "" {
		return nil, store.ErrNotFound
	}
	return []byte(p.Icon), nil
}

// InstanceView is an instance as the API shows it.
type InstanceView struct {
	ID        int64          `json:"id"`
	PluginID  string         `json:"plugin_id"`
	Name      string         `json:"name"`
	Config    map[string]any `json:"config"`
	Targets   []string       `json:"targets"`
	Status    string         `json:"status"`
	Detail    string         `json:"detail"`
	Endpoints []sdk.Endpoint `json:"endpoints"`
	CheckedAt *time.Time     `json:"checked_at"`
	CreatedAt time.Time      `json:"created_at"`
}

func (m *Manager) instanceView(ctx context.Context, in store.PluginInstance) (InstanceView, error) {
	v := InstanceView{ID: in.ID, PluginID: in.PluginID, Name: in.Name, Status: in.Status, Detail: in.Detail,
		CheckedAt: in.CheckedAt, CreatedAt: in.CreatedAt, Targets: []string{}, Endpoints: []sdk.Endpoint{}}
	cfg := map[string]any{}
	_ = json.Unmarshal([]byte(in.Config), &cfg)
	for k, val := range cfg {
		if ref, ok := val.(map[string]any); ok {
			if name, ok := ref["secret"].(string); ok {
				_, err := m.Store.GetSecretByPurpose(ctx, SecretPurpose(in.PluginID, in.ID, name))
				cfg[k] = map[string]any{"secret": name, "set": err == nil}
			}
		}
	}
	v.Config = cfg
	_ = json.Unmarshal([]byte(in.Endpoints), &v.Endpoints)
	v.Endpoints = safeEndpoints(v.Endpoints)
	gs, err := m.Store.Grants(ctx, in.ID)
	if err != nil {
		return v, err
	}
	for _, g := range gs {
		v.Targets = append(v.Targets, g.Ref)
	}
	return v, nil
}

// Instances lists the instances of a plugin.
func (m *Manager) Instances(ctx context.Context, pid string) ([]InstanceView, error) {
	if _, err := m.Store.GetPlugin(ctx, pid); errors.Is(err, store.ErrNotFound) {
		return nil, newErr(http.StatusNotFound, "плагин не найден")
	} else if err != nil {
		return nil, err
	}
	list, err := m.Store.ListInstances(ctx, pid, false)
	if err != nil {
		return nil, err
	}
	out := []InstanceView{}
	for _, in := range list {
		v, err := m.instanceView(ctx, in)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Instance returns one instance; refresh asks the plugin for its status
// first (a failure is shown in the detail, not as an error).
func (m *Manager) Instance(ctx context.Context, iid int64, refresh bool) (InstanceView, error) {
	in, err := m.Store.GetInstance(ctx, iid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && in.Status == store.InstanceDraft) {
		return InstanceView{}, newErr(http.StatusNotFound, "экземпляр не найден")
	}
	if err != nil {
		return InstanceView{}, err
	}
	if refresh {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, serr := m.instanceStatus(cctx, in.PluginID, in)
		cancel()
		if in, err = m.Store.GetInstance(ctx, iid); err != nil {
			return InstanceView{}, err
		}
		if serr != nil {
			v, err := m.instanceView(ctx, in)
			v.Detail = "Не удалось проверить: " + serr.Error()
			return v, err
		}
	}
	return m.instanceView(ctx, in)
}

// AuthorEntry is a pinned author with its plugins.
type AuthorEntry struct {
	store.PluginAuthor
	Fingerprint string   `json:"fingerprint"`
	Plugins     []string `json:"plugins"`
}

// Authors lists pinned author keys.
func (m *Manager) Authors(ctx context.Context) ([]AuthorEntry, error) {
	as, err := m.Store.ListAuthors(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := m.Store.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	out := []AuthorEntry{}
	for _, a := range as {
		e := AuthorEntry{PluginAuthor: a, Fingerprint: Fingerprint(a.Key), Plugins: []string{}}
		for _, p := range ps {
			if p.AuthorKey == a.Key {
				e.Plugins = append(e.Plugins, p.ID)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// ForgetAuthor removes a pinned key that no plugin uses.
func (m *Manager) ForgetAuthor(ctx context.Context, key string) error {
	if key == store.DevAuthorKey {
		return newErr(http.StatusNotFound, "автор не найден")
	}
	switch err := m.Store.DeleteAuthor(ctx, key); {
	case errors.Is(err, store.ErrDuplicate):
		return newErr(http.StatusConflict, "от этого автора есть установленные плагины")
	case errors.Is(err, store.ErrNotFound):
		return newErr(http.StatusNotFound, "автор не найден")
	default:
		return err
	}
}
