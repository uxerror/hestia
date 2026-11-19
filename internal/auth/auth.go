// Package auth implements the first administrator, password login and
// cookie sessions. Only the sha256 of a session token is stored in the DB.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/uxerror/hestia/internal/store"
)

// CookieName is the session cookie name.
const CookieName = "hestia_session"

// SessionTTL is how long a session stays valid.
const SessionTTL = 30 * 24 * time.Hour

// Errors; messages are user-facing (Russian).
var (
	ErrInvalidUsername = errors.New("логин: 2–32 символа, допустимы a-z, 0-9, _ . -")
	ErrWeakPassword    = errors.New("пароль должен быть от 8 до 72 байт")
	ErrSetupDone       = errors.New("администратор уже создан")
	ErrBadCredentials  = errors.New("неверный логин или пароль")
	ErrUnauthorized    = errors.New("требуется вход")
)

var usernameRe = regexp.MustCompile(`^[a-z0-9_.-]{2,32}$`)

// dummyHash is compared against when the user is unknown, to even out timing.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("hestia-dummy-password"), bcrypt.DefaultCost)

// Service wraps the store with auth logic.
type Service struct {
	store *store.Store
	now   func() time.Time
}

// New creates a Service.
func New(s *store.Store) *Service { return &Service{store: s, now: time.Now} }

// NeedsAdmin reports whether no user exists yet.
func (s *Service) NeedsAdmin(ctx context.Context) (bool, error) {
	n, err := s.store.CountUsers(ctx)
	return n == 0, err
}

// CreateAdmin creates the first administrator atomically and opens a session.
// It returns ErrSetupDone for every caller after the first.
func (s *Service) CreateAdmin(ctx context.Context, username, password string) (store.User, string, error) {
	if !usernameRe.MatchString(username) {
		return store.User{}, "", ErrInvalidUsername
	}
	if len(password) < 8 || len(password) > 72 {
		return store.User{}, "", ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return store.User{}, "", err
	}
	u, err := s.store.CreateFirstUser(ctx, username, string(hash))
	if errors.Is(err, store.ErrUsersExist) {
		return store.User{}, "", ErrSetupDone
	}
	if err != nil {
		return store.User{}, "", err
	}
	tok, err := s.newSession(ctx, u.ID)
	return u, tok, err
}

// Login checks credentials and opens a session.
func (s *Service) Login(ctx context.Context, username, password string) (store.User, string, error) {
	u, err := s.store.UserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return store.User{}, "", ErrBadCredentials
	}
	if err != nil {
		return store.User{}, "", err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return store.User{}, "", ErrBadCredentials
	}
	tok, err := s.newSession(ctx, u.ID)
	return u, tok, err
}

// Logout deletes the session behind a token.
func (s *Service) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.store.DeleteSession(ctx, hashToken(token))
}

// Authenticate resolves a token to its user, or returns ErrUnauthorized.
func (s *Service) Authenticate(ctx context.Context, token string) (store.User, error) {
	if token == "" {
		return store.User{}, ErrUnauthorized
	}
	u, err := s.store.UserBySession(ctx, hashToken(token), s.now())
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, ErrUnauthorized
	}
	return u, err
}

// HandoffTTL is how long a handoff token can be used.
const HandoffTTL = 10 * time.Minute

// ErrBadHandoff means the handoff token is unknown, used or expired.
var ErrBadHandoff = errors.New("ссылка для входа недействительна или устарела")

// NewHandoff returns a random one-time login token and the hash to store.
func NewHandoff() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

// Handoff exchanges a one-time token (made by NewHandoff, stored in the
// database that was moved to this controller) for a session token.
func (s *Service) Handoff(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrBadHandoff
	}
	uid, err := s.store.ConsumeHandoff(ctx, hashToken(token), s.now())
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrBadHandoff
	}
	if err != nil {
		return "", err
	}
	return s.newSession(ctx, uid)
}

func (s *Service) newSession(ctx context.Context, userID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	if err := s.store.CreateSession(ctx, hashToken(tok), userID, s.now().Add(SessionTTL)); err != nil {
		return "", err
	}
	return tok, nil
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// SetCookie writes the session cookie.
func SetCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionTTL.Seconds()),
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// TokenFromRequest returns the session token from the cookie, or "".
func TokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
