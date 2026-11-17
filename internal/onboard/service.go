// Package onboard connects targets: it probes a host (no changes), builds a
// plan, and applies it as a job with rollback. Credentials typed by the user
// live only in memory ("probe sessions") and are never persisted or logged.
package onboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/sshx"
	"hestia/internal/store"
)

// SessionTTL is how long probe credentials stay in memory.
const SessionTTL = 10 * time.Minute

const maxSessions = 50

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

// Service holds the dependencies of onboarding. Hook fields default to the
// real implementations and exist so tests never touch a real network.
type Service struct {
	Store    *store.Store
	Secrets  *secrets.Service
	Runner   *jobs.Runner
	Identity secrets.Identity

	Dial        func(ctx context.Context, cfg sshx.Config) (*sshx.Client, error)
	FetchCertFP func(ctx context.Context, host string, port int) (string, error)
	APIPort     int
	Now         func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
}

// Init fills in defaults for unset hooks and returns s; call it once after
// constructing the struct literal.
func (s *Service) Init() *Service {
	if s.Dial == nil {
		s.Dial = sshx.Dial
	}
	if s.FetchCertFP == nil {
		s.FetchCertFP = proxmox.FetchCertFP
	}
	if s.APIPort == 0 {
		s.APIPort = proxmox.APIPort
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.sessions == nil {
		s.sessions = map[string]*session{}
	}
	return s
}

// session is an in-memory probe session: what the probe found plus the
// credentials needed to apply the plan.
type session struct {
	result  ProbeResult
	cfg     sshx.Config // contains the password or the user's key
	expires time.Time
	busy    bool
}

func (s *Service) putSession(res *ProbeResult, cfg sshx.Config) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	res.ProbeID = id
	res.ExpiresAt = s.Now().Add(SessionTTL).UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	for len(s.sessions) >= maxSessions { // drop the oldest
		var oldest string
		for k, v := range s.sessions {
			if oldest == "" || v.expires.Before(s.sessions[oldest].expires) {
				oldest = k
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[id] = &session{result: *res, cfg: cfg, expires: res.ExpiresAt}
}

func (s *Service) purgeLocked() {
	now := s.Now()
	for k, v := range s.sessions {
		if !v.busy && now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
}

var errGone = newErr(410, "сессия проверки истекла или не найдена — проверьте подключение заново", nil)
var errBusy = newErr(409, "эта проверка уже выполняется — дождитесь завершения задачи", nil)

// acquire marks the session busy and returns a copy.
func (s *Service) acquire(id string) (session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	ss, ok := s.sessions[id]
	if !ok {
		return session{}, errGone
	}
	if ss.busy {
		return session{}, errBusy
	}
	ss.busy = true
	return *ss, nil
}

// release makes a failed session usable again (until it expires).
func (s *Service) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss, ok := s.sessions[id]; ok {
		ss.busy = false
	}
}

// drop forgets the session and with it the credentials.
func (s *Service) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// SessionCount is the number of live probe sessions (tests).
func (s *Service) SessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	return len(s.sessions)
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
