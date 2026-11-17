// Package selfinstall moves the Hestia controller from the PC (bootstrap)
// to a connected target: an unprivileged LXC on Proxmox or a systemd service
// on a standalone server. Everything created on the target is shown as a plan
// first and rolled back on failure; the state (database + master key) is
// copied and the PC becomes a client of the remote controller.
package selfinstall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/sshx"
	"hestia/internal/store"
)

// Kinds of installation.
const (
	KindLXC    = "lxc"
	KindServer = "ssh"
)

// SessionTTL is how long a probe result can be confirmed.
const SessionTTL = 10 * time.Minute

const maxSessions = 20

// JobKind is the kind of the installation job.
const JobKind = "selfinstall"

// Error is a failure with a user-facing message and the HTTP status to use.
type Error struct {
	Status int
	Msg    string
	Err    error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

func newErr(status int, msg string, err error) *Error {
	return &Error{Status: status, Msg: msg, Err: err}
}

var (
	errGone      = newErr(http.StatusGone, "проверка истекла или не найдена — выполните её заново", nil)
	errBusy      = newErr(http.StatusConflict, "эта проверка уже выполняется — дождитесь завершения задачи", nil)
	errInstalled = newErr(http.StatusConflict, "Hestia уже перенесена на сервер", nil)
	errRunning   = newErr(http.StatusConflict, "установка уже идёт", nil)
)

// API is the part of the Proxmox API the installer uses; *proxmox.Client
// implements it.
type API interface {
	ClusterResources(ctx context.Context) ([]proxmox.Resource, error)
	NodeStorage(ctx context.Context, node string) ([]proxmox.NodeStorageEntry, error)
	Network(ctx context.Context, node string) ([]proxmox.NetIface, error)
	AplInfo(ctx context.Context, node string) ([]proxmox.AplTemplate, error)
	StorageContent(ctx context.Context, node, storage, content string) ([]proxmox.Volume, error)
	DownloadTemplate(ctx context.Context, node, storage, template string) (string, error)
	DeleteVolume(ctx context.Context, node, storage, volid string) (string, error)
	CreateLXC(ctx context.Context, node string, params url.Values) (string, error)
	StartLXC(ctx context.Context, node string, vmid int) (string, error)
	StopLXC(ctx context.Context, node string, vmid int) (string, error)
	DeleteLXC(ctx context.Context, node string, vmid int) (string, error)
	LXCStatus(ctx context.Context, node string, vmid int) (string, error)
	LXCConfig(ctx context.Context, node string, vmid int) (map[string]string, error)
	LXCInterfaces(ctx context.Context, node string, vmid int) ([]proxmox.Iface, error)
	WaitTask(ctx context.Context, node, upid string, interval time.Duration, onLog func(string)) error
}

// Service holds the dependencies of the installer. Hook fields default to
// the real implementations and exist so tests never touch a real network.
type Service struct {
	Store    *store.Store
	Secrets  *secrets.Service
	Runner   *jobs.Runner
	Identity secrets.Identity
	Gate     *Gate
	DataDir  string
	Version  string

	Dial    func(ctx context.Context, cfg sshx.Config) (*sshx.Client, error)
	NewAPI  func(cfg proxmox.ClientConfig) API
	APIPort int
	Now     func() time.Time
	// Binary returns the static linux/amd64 server binary (default: the
	// embedded payload or this executable).
	Binary func() ([]byte, error)
	// HealthBase maps the controller's address and port on the target to the
	// base URL used for the health check (default http://host[:port]).
	HealthBase func(host string, port int) string
	HTTP       *http.Client
	// OnSwitched is called once the local controller has handed over.
	OnSwitched func()

	PollInterval  time.Duration // Proxmox task polling
	IPTimeout     time.Duration // wait for the container's DHCP address
	HealthTimeout time.Duration // wait for the new controller to answer

	mu       sync.Mutex
	sessions map[string]*session
	running  bool
	bin      []byte
}

// Init fills in defaults and returns s; call it once after building the struct.
func (s *Service) Init() *Service {
	if s.Dial == nil {
		s.Dial = sshx.Dial
	}
	if s.NewAPI == nil {
		s.NewAPI = func(cfg proxmox.ClientConfig) API { return proxmox.NewClient(cfg) }
	}
	if s.APIPort == 0 {
		s.APIPort = proxmox.APIPort
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Gate == nil {
		s.Gate = &Gate{}
	}
	if s.HealthBase == nil {
		s.HealthBase = func(host string, port int) string { return hostURL(host, port) }
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{Transport: &http.Transport{Proxy: nil}}
	}
	if s.PollInterval <= 0 {
		s.PollInterval = time.Second
	}
	if s.IPTimeout <= 0 {
		s.IPTimeout = 90 * time.Second
	}
	if s.HealthTimeout <= 0 {
		s.HealthTimeout = 30 * time.Second
	}
	s.sessions = map[string]*session{}
	return s
}

// State is the answer of GET /selfinstall.
type State struct {
	State        string    `json:"state"` // local | installed
	Location     *Location `json:"location,omitempty"`
	Transferring bool      `json:"transferring"`
}

// State reports whether this controller still runs on the PC or was
// installed on a server (its database says where it lives).
func (s *Service) State(ctx context.Context) (State, error) {
	st := State{State: "local", Transferring: s.Gate.Transferring()}
	v, err := s.Store.GetSetting(ctx, store.SettingControllerLocation)
	if errors.Is(err, store.ErrNotFound) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	var loc Location
	if err := json.Unmarshal([]byte(v), &loc); err != nil {
		return st, fmt.Errorf("controller_location: %w", err)
	}
	st.State, st.Location = "installed", &loc
	return st, nil
}

func (s *Service) requireLocal(ctx context.Context) error {
	st, err := s.State(ctx)
	if err != nil {
		return err
	}
	if st.State != "local" {
		return errInstalled
	}
	return nil
}

// session is an in-memory probe result waiting for confirmation.
type session struct {
	result  ProbeResult
	expires time.Time
	busy    bool
}

func (s *Service) putSession(res *ProbeResult) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	res.ProbeID = hex.EncodeToString(b)
	res.ExpiresAt = s.Now().Add(SessionTTL).UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	for len(s.sessions) >= maxSessions {
		var oldest string
		for k, v := range s.sessions {
			if oldest == "" || v.expires.Before(s.sessions[oldest].expires) {
				oldest = k
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[res.ProbeID] = &session{result: *res, expires: res.ExpiresAt}
}

func (s *Service) purgeLocked() {
	now := s.Now()
	for k, v := range s.sessions {
		if !v.busy && now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
}

// SessionCount is the number of live probe sessions (tests).
func (s *Service) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	return len(s.sessions)
}

func (s *Service) acquire(id string) (ProbeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	ss, ok := s.sessions[id]
	if !ok {
		return ProbeResult{}, errGone
	}
	if ss.busy {
		return ProbeResult{}, errBusy
	}
	if s.running {
		return ProbeResult{}, errRunning
	}
	ss.busy, s.running = true, true
	return ss.result, nil
}

// release lets a failed session be confirmed again (until it expires).
func (s *Service) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss, ok := s.sessions[id]; ok {
		ss.busy = false
	}
	s.running = false
}

func (s *Service) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	s.running = false
}
