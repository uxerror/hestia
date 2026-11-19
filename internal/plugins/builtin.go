package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

// The built-in pseudo plugin "hestia": code of the controller itself (the
// consumer of its own HTTPS certificate, internal/tlsself) served in-process
// on the same sdk and RPC layer as any plugin. It has no process, no
// package and one instance "Hestia"; it is not listed among plugins and
// cannot be disabled, removed or configured.

// BuiltinID is the reserved id of the built-in pseudo plugin.
const BuiltinID = "hestia"

// BuiltinInstanceName is the name of its only instance.
const BuiltinInstanceName = "Hestia"

// builtinSupervisor is the third kind of Supervisor: an in-process pair of
// pipes instead of a unit or a child.
type builtinSupervisor struct{ m *Manager }

var _ Supervisor = builtinSupervisor{}

var errBuiltin = errors.New("встроенный компонент Hestia не включается и не отключается")

func (builtinSupervisor) Enable(context.Context, string) error  { return errBuiltin }
func (builtinSupervisor) Disable(context.Context, string) error { return errBuiltin }
func (builtinSupervisor) Restart(context.Context, string) error { return errBuiltin }
func (b builtinSupervisor) Active(_ context.Context, id string) (string, error) {
	if b.m.conn(id) != nil {
		return "active", nil
	}
	return "inactive", nil
}

// StartBuiltin records the pseudo plugin (manifest rewritten with the
// current one) and its instance, and serves p in-process. It returns the
// instance. The manifest's id must be BuiltinID.
func (m *Manager) StartBuiltin(ctx context.Context, manifest []byte, p sdk.Plugin) (store.PluginInstance, error) {
	man, err := sdk.ParseManifest(manifest)
	if err != nil {
		return store.PluginInstance{}, err
	}
	if man.ID != BuiltinID {
		return store.PluginInstance{}, fmt.Errorf("встроенный плагин: id %q", man.ID)
	}
	if err := validatePorts(man, false); err != nil {
		return store.PluginInstance{}, err
	}
	rec := store.Plugin{ID: BuiltinID, Version: man.Version, AuthorKey: store.BuiltinAuthorKey, Manifest: string(manifest),
		Source: store.PluginSourceBuiltin, Enabled: true}
	if cur, err := m.Store.GetPlugin(ctx, BuiltinID); err == nil {
		if cur.Source != store.PluginSourceBuiltin {
			return store.PluginInstance{}, fmt.Errorf("id %s занят плагином из пакета — удалите его", BuiltinID)
		}
		rec.InstalledAt = cur.InstalledAt
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.PluginInstance{}, err
	}
	if err := m.Store.SavePlugin(ctx, rec, &store.PluginAuthor{Key: store.BuiltinAuthorKey, Name: "Hestia"}); err != nil {
		return store.PluginInstance{}, err
	}
	insts, err := m.Store.ListInstances(ctx, BuiltinID, false)
	if err != nil {
		return store.PluginInstance{}, err
	}
	var inst store.PluginInstance
	if len(insts) > 0 {
		inst = insts[0]
	} else {
		inst = store.PluginInstance{PluginID: BuiltinID, Name: BuiltinInstanceName, Config: "{}", Status: sdk.StateUnknown}
		if err := m.Store.CreateInstance(ctx, &inst, nil); err != nil {
			return inst, err
		}
	}
	tok := newToken()
	a, b := net.Pipe()
	m.mu.Lock()
	m.builtinToken = tok
	m.mu.Unlock()
	m.attach(a, tok)
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		if err := sdk.Run(m.ctx, manifest, p, b, tok); err != nil && m.ctx.Err() == nil {
			slog.Error("встроенный плагин остановился", "err", err)
		}
	}()
	return inst, nil
}

// isBuiltinToken reports whether a connection token is the built-in one.
func (m *Manager) isBuiltinToken(tok string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return tok != "" && m.builtinToken == tok
}

// BuiltinInstance returns the instance "Hestia" (ErrNotFound before
// StartBuiltin).
func (m *Manager) BuiltinInstance(ctx context.Context) (store.PluginInstance, error) {
	insts, err := m.Store.ListInstances(ctx, BuiltinID, false)
	if err != nil {
		return store.PluginInstance{}, err
	}
	if len(insts) == 0 {
		return store.PluginInstance{}, store.ErrNotFound
	}
	return insts[0], nil
}

// BuiltinLink is the active link on a requires port of the instance
// "Hestia" (ErrNotFound if none).
func (m *Manager) BuiltinLink(ctx context.Context, port string) (store.PluginLink, error) {
	inst, err := m.BuiltinInstance(ctx)
	if err != nil {
		return store.PluginLink{}, err
	}
	return m.BuiltinLinkOf(ctx, inst.ID, port)
}

// BuiltinLinkOf is the link on a requires port of a consumer instance
// (ErrNotFound if none).
func (m *Manager) BuiltinLinkOf(ctx context.Context, iid int64, port string) (store.PluginLink, error) {
	links, err := m.Store.LinksOfInstance(ctx, iid)
	if err != nil {
		return store.PluginLink{}, err
	}
	for _, l := range links {
		if l.Kind == store.LinkKindService && l.ConsumerInstance == iid && l.ConsumerPort == port && l.Status != store.LinkDraft {
			return l, nil
		}
	}
	return store.PluginLink{}, store.ErrNotFound
}

// errBuiltinChange refuses changes of the built-in pseudo plugin.
func errBuiltinChange() error {
	return newErr(http.StatusConflict, "Встроенный компонент Hestia не настраивается и не удаляется")
}

// isBuiltinManifest: a stored manifest of the pseudo plugin.
func isBuiltinManifest(raw string) bool {
	var m struct {
		ID string `json:"id"`
	}
	return json.Unmarshal([]byte(raw), &m) == nil && m.ID == BuiltinID
}
