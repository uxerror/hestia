package plugins

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/netscan"
	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/update"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// DefaultSocket is where the controller listens for plugins in production.
const DefaultSocket = "/run/hestia/plugins.sock"

// Timeouts and periods.
const (
	HelloTimeout   = 20 * time.Second
	StatusInterval = 5 * time.Minute
	planTTL        = 15 * time.Minute
	uploadTTL      = time.Hour
)

// Messages for the user.
const (
	msgDesktop    = "Плагины доступны после переноса Hestia на сервер."
	msgNoLocation = "Плагины ставятся только на контроллер, установленный через Hestia: нужен root-доступ к его машине."
	msgRestarted  = "Плагин перезапустился"
	// msgFirstRestart: the first plugin on a controller installed before
	// plugins existed.
	msgFirstRestart = "Сокет плагинов пока закрыт для процесса Hestia: контроллер перезапустится один раз (через 5 секунд). Повторите установку через минуту."
)

// Error is a failure with a user-facing message and the HTTP status to use.
type Error struct {
	Status int
	Msg    string
	// Fields are per-field validation errors (422).
	Fields []sdk.FieldError
	// Instances are listed when a plugin cannot be removed (409).
	Instances []string
}

func (e *Error) Error() string { return e.Msg }

func newErr(status int, format string, args ...any) *Error {
	return &Error{Status: status, Msg: fmt.Sprintf(format, args...)}
}

// Shell runs commands as root on the machine hosting the controller;
// *selfinstall.ControllerShell implements it.
type Shell interface {
	Exec(ctx context.Context, script string, stdin []byte) (sshx.Result, error)
	PutFile(ctx context.Context, log func(string), path string, data []byte, mode, owner string) error
	Close() error
}

// Manager installs and supervises plugins and serves their calls.
type Manager struct {
	Store    *store.Store
	Secrets  *secrets.Service
	Runner   *jobs.Runner
	Identity secrets.Identity
	Version  string
	DataDir  string
	Mode     string // serve | desktop

	// Inventory and Netscan feed inventory.get and the target candidates
	// (both optional).
	Inventory *inventory.Service
	Netscan   *netscan.Manager

	// SocketPath is the unix socket for plugins in production (default
	// DefaultSocket; "-" disables it). It is opened only when its directory
	// exists.
	SocketPath string
	// Root prefixes every path on the controller's machine (tests).
	Root string
	// Location returns where the controller was installed (nil: it was
	// not); Open connects to that machine as root.
	Location func(ctx context.Context) (*selfinstall.Location, error)
	Open     func(ctx context.Context, loc selfinstall.Location) (Shell, error)
	// Targets runs commands on targets granted to instances.
	Targets TargetExec
	// PVE reads container configs through the Proxmox API (default: a
	// client built from the stored target, on PVEPort).
	PVE     func(ctx context.Context, t store.Target) (LXCConfigAPI, error)
	PVEPort int
	// HTTP downloads packages by URL and from the catalog.
	HTTP *http.Client
	// GitHub serves the official catalog (release "plugins-catalog");
	// CatalogChecks refreshes it a minute after Start and then daily.
	GitHub        *update.GitHub
	CatalogChecks bool
	Now           func() time.Time

	HelloTimeout      time.Duration
	HeartbeatInterval time.Duration
	StatusInterval    time.Duration
	// RenewInterval is how often due renewals of links are looked for
	// (default RenewInterval).
	RenewInterval time.Duration

	// Timeouts of deploy.* (defaults in deploy.go).
	DeployPoll           time.Duration
	DeployWaitRunning    time.Duration
	DeployProbeTimeout   time.Duration
	DeployInstallTimeout time.Duration
	DeployUpTimeout      time.Duration
	DeployDownTimeout    time.Duration
	DeployCTTimeout      time.Duration

	mu       sync.Mutex
	conns    map[string]*session // plugin id → authenticated connection
	waiters  map[string][]chan struct{}
	pending  map[string]*pendingInstall
	uploads  map[string]*upload
	plans    map[string]*planState
	applying map[string]*applyJob // job id → running apply
	planning map[string]planGrant // grants of plan calls in flight
	busy     map[string]bool      // plugin id → install/enable/... job running
	// composites are link, compose and removal plans (several steps).
	composites map[string]*compositePlan
	// linkCalls are link.* calls in flight (device grants act during them).
	linkCalls map[string]linkCall
	// instJobs are the instances an apply/link/compose job works on.
	instJobs map[int64]bool
	// renewFails counts failed renewals in a row (link id → n) for the
	// backoff; actionsOn are the actions enabled by the last status
	// (instance id → names; missing: all).
	renewFails     map[int64]int
	actionsOn      map[int64][]string
	linksCheckedAt time.Time
	builtinToken   string // of the in-process pseudo plugin
	devs           []*devPlugin
	cacheMu        sync.Mutex // containers cache
	ln             net.Listener
	bg             sync.WaitGroup
	ctx            context.Context
	stop           context.CancelFunc
}

// pendingInstall is a version being installed: its process may connect
// with the new token before the database knows about it.
type pendingInstall struct {
	version   string
	tokenHash string
	perms     []string
}

// Init fills in defaults and cleans the temporary uploads; call it once.
func (m *Manager) Init() *Manager {
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.SocketPath == "" {
		m.SocketPath = DefaultSocket
	}
	if m.HelloTimeout <= 0 {
		m.HelloTimeout = HelloTimeout
	}
	if m.HeartbeatInterval <= 0 {
		m.HeartbeatInterval = rpc.HeartbeatInterval
	}
	if m.StatusInterval <= 0 {
		m.StatusInterval = StatusInterval
	}
	if m.RenewInterval <= 0 {
		m.RenewInterval = RenewInterval
	}
	if m.HTTP == nil {
		m.HTTP = defaultHTTP()
	}
	if m.Targets == nil {
		m.Targets = &SSHTargets{Store: m.Store, Identity: m.Identity}
	}
	if m.GitHub == nil {
		m.GitHub = &update.GitHub{HTTP: m.HTTP}
	}
	if m.PVE == nil {
		m.PVE = m.defaultPVE
	}
	if m.PVEPort == 0 {
		m.PVEPort = proxmox.APIPort
	}
	for _, d := range []struct {
		p *time.Duration
		v time.Duration
	}{
		{&m.DeployPoll, 2 * time.Second}, {&m.DeployWaitRunning, DeployWaitRunning}, {&m.DeployProbeTimeout, deployProbeT},
		{&m.DeployInstallTimeout, deployInstallT}, {&m.DeployUpTimeout, deployUpT}, {&m.DeployDownTimeout, deployDownT},
		{&m.DeployCTTimeout, deployCTT},
	} {
		if *d.p <= 0 {
			*d.p = d.v
		}
	}
	m.conns = map[string]*session{}
	m.waiters = map[string][]chan struct{}{}
	m.pending = map[string]*pendingInstall{}
	m.uploads = map[string]*upload{}
	m.plans = map[string]*planState{}
	m.applying = map[string]*applyJob{}
	m.planning = map[string]planGrant{}
	m.busy = map[string]bool{}
	m.composites = map[string]*compositePlan{}
	m.linkCalls = map[string]linkCall{}
	m.instJobs = map[int64]bool{}
	m.renewFails = map[int64]int{}
	m.actionsOn = map[int64][]string{}
	m.ctx, m.stop = context.WithCancel(context.Background())
	_ = os.RemoveAll(m.uploadDir())
	// Drafts belong to plans, which live in memory only.
	_ = m.Store.DeleteDrafts(context.Background(), "", "")
	return m
}

// Start opens the plugin socket (if its directory exists) and runs the
// periodic status checks until Close.
func (m *Manager) Start() {
	m.ensureListener()
	if m.CatalogChecks && m.Mode != "desktop" {
		m.startCatalogChecks()
	}
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		t := time.NewTicker(m.StatusInterval)
		defer t.Stop()
		r := time.NewTicker(m.RenewInterval)
		defer r.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-t.C:
				m.refreshAll(m.ctx)
				m.refreshLinks(m.ctx)
			case <-r.C:
				m.renewDue(m.ctx)
			}
		}
	}()
}

// Close stops the listener, the dev plugin and every connection.
func (m *Manager) Close() {
	m.stop()
	m.mu.Lock()
	ln := m.ln
	m.ln = nil
	devs := m.devs
	var conns []*session
	for _, s := range m.conns {
		conns = append(conns, s)
	}
	m.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, s := range conns {
		_ = s.conn.Close()
	}
	for _, d := range devs {
		d.stop()
	}
	m.bg.Wait()
}

// ensureListener opens the unix socket once its directory exists (it is
// created by tmpfiles when the first plugin is installed).
func (m *Manager) ensureListener() {
	if m.Mode == "desktop" || m.SocketPath == "-" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ln != nil || m.ctx.Err() != nil {
		return
	}
	if st, err := os.Stat(filepath.Dir(m.SocketPath)); err != nil || !st.IsDir() {
		return
	}
	_ = os.Remove(m.SocketPath) // a stale socket of a previous process
	ln, err := net.Listen("unix", m.SocketPath)
	if err != nil {
		slog.Warn("сокет плагинов", "path", m.SocketPath, "err", err)
		return
	}
	// Any local process may connect; the token in hello authenticates.
	_ = os.Chmod(m.SocketPath, 0o666)
	m.ln = ln
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			m.attach(c, "")
		}
	}()
}

// Listening reports whether the plugin socket is open.
func (m *Manager) Listening() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ln != nil
}

// session is one plugin connection.
type session struct {
	m        *Manager
	conn     *rpc.Conn
	devToken string // the dev child's token ("" for the socket)

	mu           sync.Mutex
	pluginID     string
	version      string
	dev          bool
	perms        map[string]bool
	unresponsive bool
	authed       bool
}

func (s *session) id() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pluginID
}

func (s *session) can(perm string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.perms[perm]
}

// attach serves a new connection: it must say hello within HelloTimeout.
func (m *Manager) attach(rwc io.ReadWriteCloser, devToken string) *session {
	s := &session{m: m, devToken: devToken}
	s.conn = rpc.New(rwc, s.handle, rpc.Options{OnClose: func(error) { m.detach(s) }})
	s.conn.Start()
	go func() {
		t := time.NewTimer(m.HelloTimeout)
		defer t.Stop()
		select {
		case <-t.C:
			s.mu.Lock()
			ok := s.authed
			s.mu.Unlock()
			if !ok {
				_ = s.conn.Close()
			}
		case <-s.conn.Done():
		}
	}()
	return s
}

func (m *Manager) detach(s *session) {
	id := s.id()
	if id == "" {
		return
	}
	m.mu.Lock()
	if m.conns[id] == s {
		delete(m.conns, id)
	}
	m.mu.Unlock()
}

func (s *session) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	s.mu.Lock()
	authed := s.authed
	s.mu.Unlock()
	if method == sdk.MethodHello {
		if authed {
			return nil, rpc.Errorf(rpc.CodeProtocol, "hello уже был")
		}
		w, err := s.m.hello(ctx, s, params)
		if err != nil {
			// Answer first, then drop the connection.
			time.AfterFunc(200*time.Millisecond, func() { _ = s.conn.Close() })
			return nil, err
		}
		return w, nil
	}
	if !authed {
		return nil, rpc.Errorf(rpc.CodeProtocol, "первым сообщением должен быть hello")
	}
	return s.m.hostCall(ctx, s, method, params)
}

// HashToken is how plugin tokens are stored.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func tokenEqual(tok, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashToken(tok)), []byte(hash)) == 1
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) hello(ctx context.Context, s *session, params json.RawMessage) (*sdk.Welcome, error) {
	var h sdk.Hello
	if err := json.Unmarshal(params, &h); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "неверный hello")
	}
	if h.Protocol != sdk.Protocol {
		e := rpc.Errorf(rpc.CodeProtocol, "протокол %d не поддерживается: Hestia поддерживает %d–%d", h.Protocol, sdk.Protocol, sdk.Protocol)
		e.Data, _ = json.Marshal(map[string]int{"min": sdk.Protocol, "max": sdk.Protocol})
		return nil, e
	}
	denied := rpc.Errorf(rpc.CodeProtocol, "неверный токен, id или версия плагина")
	var perms []string
	dev := false
	switch {
	case s.devToken != "" && m.isBuiltinToken(s.devToken):
		// The in-process pseudo plugin (StartBuiltin): no permissions.
		if subtle.ConstantTimeCompare([]byte(h.Token), []byte(s.devToken)) != 1 || h.ID != BuiltinID {
			return nil, denied
		}
	case s.devToken != "":
		if subtle.ConstantTimeCompare([]byte(h.Token), []byte(s.devToken)) != 1 || !reID.MatchString(h.ID) {
			return nil, denied
		}
		dev = true
	default:
		p, err := m.Store.GetPlugin(ctx, h.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		ok := false
		m.mu.Lock()
		pend := m.pending[h.ID]
		m.mu.Unlock()
		// Compare against both candidates to keep the timing independent of
		// which one matches.
		okDB := err == nil && p.Source != store.PluginSourceDev && p.Enabled && tokenEqual(h.Token, p.TokenHash) && p.Version == h.Version
		okPend := pend != nil && tokenEqual(h.Token, pend.tokenHash) && pend.version == h.Version
		ok = okDB || okPend
		if !ok {
			slog.Warn("плагин: отказ в подключении", "id", h.ID, "version", h.Version)
			return nil, denied
		}
		if okDB {
			if man, err := storedManifest(p.Manifest); err == nil {
				perms = man.Permissions
			}
		}
		// A pending version gets its permissions from the package once the
		// installer has compared the manifest (see install.go).
		if okPend && !okDB {
			perms = m.pendingPerms(h.ID)
		}
	}
	ps := map[string]bool{}
	for _, p := range perms {
		ps[p] = true
	}
	s.mu.Lock()
	s.pluginID, s.version, s.dev, s.perms, s.authed = h.ID, h.Version, dev, ps, true
	s.mu.Unlock()

	m.mu.Lock()
	old := m.conns[h.ID]
	m.conns[h.ID] = s
	ws := m.waiters[h.ID]
	delete(m.waiters, h.ID)
	m.mu.Unlock()
	if old != nil && old != s {
		_ = old.conn.Close() // a reconnect replaces the old connection
	}
	for _, ch := range ws {
		close(ch)
	}
	go s.conn.Heartbeat(m.ctx, m.HeartbeatInterval, rpc.HeartbeatMisses, func() {
		s.mu.Lock()
		s.unresponsive = true
		s.mu.Unlock()
		slog.Warn("плагин не отвечает", "id", h.ID)
	}, func() {
		s.mu.Lock()
		s.unresponsive = false
		s.mu.Unlock()
	})
	if dev {
		go m.registerDev(s, h)
	}
	insts, err := m.welcomeInstances(ctx, h.ID)
	if err != nil {
		return nil, err
	}
	slog.Info("плагин подключён", "id", h.ID, "version", h.Version, "dev", dev)
	return &sdk.Welcome{Protocol: sdk.Protocol, HestiaVersion: m.Version, Instances: insts, Links: m.welcomeLinks(ctx, h.ID)}, nil
}

func (m *Manager) welcomeInstances(ctx context.Context, id string) ([]sdk.Instance, error) {
	list, err := m.Store.ListInstances(ctx, id, false)
	if err != nil {
		return nil, err
	}
	out := []sdk.Instance{}
	for _, in := range list {
		out = append(out, sdkInstance(in))
	}
	return out, nil
}

func sdkInstance(in store.PluginInstance) sdk.Instance {
	cfg := sdk.Config{}
	_ = json.Unmarshal([]byte(in.Config), &cfg)
	return sdk.Instance{ID: in.ID, Name: in.Name, Config: cfg}
}

// conn returns the live connection of a plugin or nil.
func (m *Manager) conn(id string) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns[id]
}

// waitHello waits until the plugin connects (or is connected already).
func (m *Manager) waitHello(ctx context.Context, id string) (*session, error) {
	m.mu.Lock()
	if s := m.conns[id]; s != nil {
		m.mu.Unlock()
		return s, nil
	}
	ch := make(chan struct{})
	m.waiters[id] = append(m.waiters[id], ch)
	m.mu.Unlock()
	select {
	case <-ch:
		if s := m.conn(id); s != nil {
			return s, nil
		}
		return nil, errors.New("плагин отключился сразу после подключения")
	case <-ctx.Done():
		return nil, fmt.Errorf("плагин не подключился за %s", m.HelloTimeout)
	}
}

// dropConn closes the connection of a plugin (disable, remove, rollback).
func (m *Manager) dropConn(id string) {
	if s := m.conn(id); s != nil {
		_ = s.conn.Close()
	}
}

// call invokes a plugin method with the default timeout.
func (m *Manager) call(ctx context.Context, id, method string, params, result any) error {
	s := m.conn(id)
	if s == nil {
		return newErr(http.StatusConflict, "плагин %s не подключён", id)
	}
	err := s.conn.Call(ctx, method, params, result)
	return pluginErr(err)
}

// pluginErr turns RPC failures into messages for the user.
func pluginErr(err error) error {
	var re *rpc.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, rpc.ErrClosed):
		return errors.New(msgRestarted)
	case errors.Is(err, context.DeadlineExceeded):
		return errors.New("плагин не ответил вовремя")
	case errors.As(err, &re):
		return fmt.Errorf("плагин: %s", truncate(re.Message, 500))
	}
	return err
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Availability says whether plugins can be installed here.
func (m *Manager) Availability(ctx context.Context) (bool, string) {
	if m.Mode == "desktop" {
		loc, err := m.location(ctx)
		if err != nil || loc == nil {
			return false, msgDesktop
		}
	}
	loc, err := m.location(ctx)
	if err != nil || loc == nil {
		return false, msgNoLocation
	}
	return true, ""
}

func (m *Manager) location(ctx context.Context) (*selfinstall.Location, error) {
	if m.Location == nil {
		return nil, nil
	}
	return m.Location(ctx)
}

func (m *Manager) uploadDir() string { return filepath.Join(m.DataDir, "tmp", "plugins") }

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
