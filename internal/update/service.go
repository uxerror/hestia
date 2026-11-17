package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/selfinstall"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/version"
)

// JobKind is the kind of the update job.
const JobKind = "update"

// Check schedule: the first one a minute after start, then every day.
const (
	FirstCheck    = time.Minute
	CheckInterval = 24 * time.Hour
)

// Error is a failure with a user-facing message and the HTTP status to use.
type Error struct {
	Status int
	Msg    string
	// Confirm is set when the request is refused only until the user
	// confirms Msg (an unknown or dirty version).
	Confirm bool
}

func (e *Error) Error() string { return e.Msg }

func newErr(status int, msg string) *Error { return &Error{Status: status, Msg: msg} }

// Shell runs commands as root on the machine hosting the controller;
// *selfinstall.ControllerShell implements it.
type Shell interface {
	Exec(ctx context.Context, script string, stdin []byte) (sshx.Result, error)
	PutFile(ctx context.Context, log func(string), path string, data []byte, mode, owner string) error
	Close() error
}

// Service updates the installed controller.
type Service struct {
	Store   *store.Store
	Runner  *jobs.Runner
	DataDir string
	Version string // version of this (running) controller
	Self    *selfinstall.Service

	GitHub *GitHub // default: the real API
	// PubKey is the release key; nil means the embedded one.
	PubKey ed25519.PublicKey
	// Location returns where the controller was installed (nil: it was not).
	Location func(ctx context.Context) (*selfinstall.Location, error)
	// Open connects to the controller's machine.
	Open func(ctx context.Context, loc selfinstall.Location) (Shell, error)
	Now  func() time.Time

	mu      sync.Mutex
	running bool
	state   Check
	uploads map[string]*upload
	started bool
}

// Check is the state of the GitHub channel.
type Check struct {
	Latest    string    `json:"latest"`
	CheckedAt time.Time `json:"checked_at"`
	Error     string    `json:"error"`
	NotesURL  string    `json:"notes_url"`
}

// Init fills in the defaults and loads the saved check state.
func (s *Service) Init() *Service {
	if s.GitHub == nil {
		s.GitHub = &GitHub{}
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Location == nil {
		s.Location = func(ctx context.Context) (*selfinstall.Location, error) {
			st, err := s.Self.State(ctx)
			return st.Location, err
		}
	}
	if s.Open == nil {
		s.Open = func(ctx context.Context, loc selfinstall.Location) (Shell, error) {
			return s.Self.OpenShell(ctx, loc)
		}
	}
	if s.PubKey == nil {
		if k, err := EmbeddedKey(); err == nil {
			s.PubKey = k
		}
	}
	s.uploads = map[string]*upload{}
	if v, err := s.Store.GetSetting(context.Background(), store.SettingUpdateCheck); err == nil {
		_ = json.Unmarshal([]byte(v), &s.state)
	}
	return s
}

// Configured reports whether the GitHub channel can be used.
func (s *Service) Configured() bool { return len(s.PubKey) == ed25519.PublicKeySize }

// GitHubState is the "github" part of GET /update.
type GitHubState struct {
	Configured bool      `json:"configured"`
	Latest     string    `json:"latest"`
	Available  bool      `json:"available"`
	CheckedAt  time.Time `json:"checked_at"`
	Error      string    `json:"error"`
	NotesURL   string    `json:"notes_url"`
}

// Status is the answer of GET /update.
type Status struct {
	Current    string         `json:"current"`
	LocationOK bool           `json:"location_ok"`
	Reason     string         `json:"reason,omitempty"`
	Where      *LocationBrief `json:"where,omitempty"`
	GitHub     GitHubState    `json:"github"`
	RunningJob string         `json:"running_job,omitempty"`
}

// LocationBrief is where the controller lives, for display.
type LocationBrief struct {
	Kind string `json:"kind"`
	Node string `json:"node,omitempty"`
	VMID int    `json:"vmid,omitempty"`
	Host string `json:"host,omitempty"`
	IP   string `json:"ip"`
}

const noLocationReason = "Контроллер установлен не через Hestia (или работает на этом ПК): обновление из интерфейса недоступно."

// Status reports the current version, whether the update is possible and the
// state of the GitHub channel.
func (s *Service) Status(ctx context.Context) (Status, error) {
	st := Status{Current: s.Version}
	loc, err := s.Location(ctx)
	if err != nil {
		return st, err
	}
	if loc == nil {
		st.Reason = noLocationReason
	} else {
		st.LocationOK = true
		st.Where = &LocationBrief{Kind: loc.Kind, Node: loc.Node, VMID: loc.VMID, Host: loc.Host, IP: loc.IP}
	}
	s.mu.Lock()
	c := s.state
	st.GitHub = GitHubState{Configured: s.Configured(), Latest: c.Latest, CheckedAt: c.CheckedAt, Error: c.Error, NotesURL: c.NotesURL}
	st.GitHub.Available = c.Latest != "" && version.Offer(s.Version, c.Latest)
	s.mu.Unlock()
	if !st.GitHub.Configured {
		st.GitHub.Latest, st.GitHub.Available = "", false
	}
	if jobs, err := s.Store.ListJobs(ctx, 20); err == nil {
		for _, j := range jobs {
			if j.Kind == JobKind && (j.Status == store.JobRunning || j.Status == store.JobQueued) {
				st.RunningJob = j.ID
				break
			}
		}
	}
	return st, nil
}

// CheckNow asks GitHub for the latest release and remembers the answer. A
// network failure is not an error of the call: it is recorded as the state.
func (s *Service) CheckNow(ctx context.Context) (GitHubState, error) {
	if !s.Configured() {
		return GitHubState{}, newErr(http.StatusConflict, ErrNotConfigured.Error())
	}
	rel, err := s.GitHub.Latest(ctx)
	c := Check{CheckedAt: s.Now().UTC()}
	if err != nil {
		c.Error = "не удалось проверить: " + err.Error()
		s.mu.Lock()
		prev := s.state
		s.state = Check{Latest: prev.Latest, NotesURL: prev.NotesURL, CheckedAt: c.CheckedAt, Error: c.Error}
		s.mu.Unlock()
	} else {
		c.Latest, c.NotesURL = rel.Tag, rel.NotesURL
		if _, ok := version.Parse(rel.Tag); !ok {
			c.Error = "не удалось проверить: у релиза необычный тег " + rel.Tag
		}
		s.mu.Lock()
		s.state = c
		s.mu.Unlock()
	}
	if b, err := json.Marshal(s.snapshot()); err == nil {
		_ = s.Store.SetSetting(context.Background(), store.SettingUpdateCheck, string(b))
	}
	st, err := s.Status(ctx)
	return st.GitHub, err
}

func (s *Service) snapshot() Check {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// StartChecks runs the periodic GitHub check until ctx is cancelled.
func (s *Service) StartChecks(ctx context.Context) {
	s.mu.Lock()
	if s.started || !s.Configured() {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	go func() {
		d := FirstCheck
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
			}
			_, _ = s.CheckNow(ctx)
			d = CheckInterval
		}
	}()
}

func randID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- uploads (path 1: the binary comes from the desktop app) ----

// MaxUpload is the size limit of an uploaded binary.
var MaxUpload int64 = MaxBinary

const uploadTTL = time.Hour

type upload struct {
	path    string
	version string
	sha     string
	expires time.Time
}

func (s *Service) uploadDir() string { return filepath.Join(s.DataDir, "update-tmp") }

// Uploaded describes a stored upload.
type Uploaded struct {
	UploadID string `json:"upload_id"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	Dirty    bool   `json:"dirty"`
	// Warning is set when the update needs an explicit confirmation.
	Warning string `json:"warning,omitempty"`
}

// purgeLocked drops expired uploads and leftovers of earlier runs.
func (s *Service) purgeLocked() {
	now := s.Now()
	for id, u := range s.uploads {
		if now.After(u.expires) {
			_ = os.Remove(u.path)
			delete(s.uploads, id)
		}
	}
}

var errNoUpload = errors.New("загруженный файл не найден или устарел — загрузите его заново")
