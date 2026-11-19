package plugins

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

// devPlugin is the child-process supervisor of `serve --plugin-dev`: the
// plugin runs without a sandbox, over stdin/stdout, with a token in
// HESTIA_PLUGIN_TOKEN. Nothing about the flag is stored; the plugin itself
// is recorded with source "dev" so that its instances have a home.
type devPlugin struct {
	m    *Manager
	path string

	mu      sync.Mutex
	cmd     *exec.Cmd
	token   string // of the running child
	id      string // plugin id once registered
	stopped bool
	err     string
}

// StartDev starts the plugin binary at path as a child process; it may be
// called for several binaries (one plugin each).
func (m *Manager) StartDev(path string) error {
	abs, err := exec.LookPath(path)
	if err != nil {
		return err
	}
	d := &devPlugin{m: m, path: abs}
	m.mu.Lock()
	for _, o := range m.devs {
		if o.path == abs {
			m.mu.Unlock()
			return errors.New("плагин " + path + " указан дважды")
		}
	}
	m.devs = append(m.devs, d)
	m.mu.Unlock()
	return d.spawn()
}

// DevError returns why dev plugins could not be registered ("" if fine).
func (m *Manager) DevError() string {
	m.mu.Lock()
	devs := append([]*devPlugin(nil), m.devs...)
	m.mu.Unlock()
	var errs []string
	for _, d := range devs {
		d.mu.Lock()
		if d.err != "" {
			errs = append(errs, d.err)
		}
		d.mu.Unlock()
	}
	return strings.Join(errs, "; ")
}

// devFor returns the dev plugin whose child holds the token.
func (m *Manager) devFor(token string) *devPlugin {
	m.mu.Lock()
	devs := append([]*devPlugin(nil), m.devs...)
	m.mu.Unlock()
	for _, d := range devs {
		d.mu.Lock()
		ok := token != "" && d.token == token
		d.mu.Unlock()
		if ok {
			return d
		}
	}
	return nil
}

type childPipe struct {
	io.Reader
	w    io.WriteCloser
	kill func()
}

func (c childPipe) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c childPipe) Close() error {
	err := c.w.Close()
	c.kill()
	return err
}

func (d *devPlugin) spawn() error {
	tok := newToken()
	cmd := exec.Command(d.path)
	env := []string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, sdk.EnvSocket+"=") || strings.HasPrefix(kv, sdk.EnvCredentials+"=") || strings.HasPrefix(kv, sdk.EnvToken+"=") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, sdk.EnvToken+"="+tok)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	d.mu.Lock()
	d.cmd, d.token = cmd, tok
	d.mu.Unlock()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			slog.Info("plugin-dev", "line", truncate(sc.Text(), 2000))
		}
	}()
	var once sync.Once
	kill := func() {
		once.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(os.Interrupt)
				done := make(chan struct{})
				go func() { _ = cmd.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = cmd.Process.Kill()
					<-done
				}
			}
		})
	}
	s := d.m.attach(childPipe{Reader: stdout, w: stdin, kill: kill}, tok)
	go func() {
		<-s.conn.Done()
		kill()
		d.mu.Lock()
		stopped := d.stopped
		d.mu.Unlock()
		if !stopped {
			slog.Warn("dev-плагин остановился", "path", d.path)
		}
	}()
	return nil
}

func (d *devPlugin) stop() {
	d.mu.Lock()
	d.stopped = true
	id := d.id
	d.mu.Unlock()
	if s := d.m.conn(id); s != nil && s.devToken != "" {
		_ = s.conn.Close()
	}
	d.mu.Lock()
	cmd := d.cmd
	d.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
	}
}

func (d *devPlugin) fail(msg string) {
	d.mu.Lock()
	d.err = msg
	d.mu.Unlock()
	slog.Error("dev-плагин", "err", msg)
}

// registerDev takes the manifest from the dev process and records the
// plugin with source "dev" (no signature: the flag is the trust).
func (m *Manager) registerDev(s *session, h sdk.Hello) {
	d := m.devFor(s.devToken)
	fail := func(msg string) {
		if d != nil {
			d.fail(msg)
		}
		_ = s.conn.Close()
	}
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()
	var raw json.RawMessage
	if err := s.conn.Call(ctx, sdk.MethodManifest, struct{}{}, &raw); err != nil {
		fail("манифест dev-плагина: " + err.Error())
		return
	}
	man, err := ParseManifest(raw)
	if err != nil {
		fail(err.Error())
		return
	}
	if man.ID != h.ID || man.Version != h.Version {
		fail("id или версия в hello не совпадают с манифестом")
		return
	}
	if man.ID == BuiltinID {
		fail("id " + BuiltinID + " зарезервирован за Hestia")
		return
	}
	cur, err := m.Store.GetPlugin(ctx, man.ID)
	switch {
	case err == nil && cur.Source != store.PluginSourceDev:
		fail("плагин " + man.ID + " установлен из пакета — dev-режим для него недоступен (удалите его или смените id)")
		return
	case err != nil && !errors.Is(err, store.ErrNotFound):
		fail(err.Error())
		return
	}
	p := store.Plugin{
		ID: man.ID, Version: man.Version, AuthorKey: store.DevAuthorKey, Manifest: string(raw),
		Source: store.PluginSourceDev, Enabled: true, TokenHash: HashToken(s.devToken),
	}
	if err == nil {
		p.InstalledAt = cur.InstalledAt
	}
	if err := m.Store.SavePlugin(ctx, p, &store.PluginAuthor{Key: store.DevAuthorKey, Name: "dev"}); err != nil {
		fail(err.Error())
		return
	}
	ps := map[string]bool{}
	for _, p := range man.Permissions {
		ps[p] = true
	}
	s.mu.Lock()
	s.perms = ps
	s.mu.Unlock()
	if d != nil {
		d.mu.Lock()
		d.err, d.id = "", man.ID
		d.mu.Unlock()
	}
	slog.Info("dev-плагин зарегистрирован", "id", man.ID, "version", man.Version)
	go m.refreshPlugin(m.ctx, man.ID)
}

// devPlugin is the child-process Supervisor.
var _ Supervisor = (*devPlugin)(nil)

func (d *devPlugin) Enable(ctx context.Context, id string) error {
	d.mu.Lock()
	d.stopped = false
	d.mu.Unlock()
	if d.m.conn(id) != nil {
		return nil
	}
	return d.spawn()
}

func (d *devPlugin) Disable(ctx context.Context, id string) error {
	d.stop()
	return nil
}

func (d *devPlugin) Restart(ctx context.Context, id string) error {
	d.stop()
	d.mu.Lock()
	d.stopped = false
	d.mu.Unlock()
	return d.spawn()
}

func (d *devPlugin) Active(ctx context.Context, id string) (string, error) {
	if d.m.conn(id) != nil {
		return "active", nil
	}
	return "inactive", nil
}
