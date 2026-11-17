// Package api wires the HTTP router: JSON API under /api/v1 and the SPA.
package api

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"hestia/internal/auth"
	"hestia/internal/jobs"
	"hestia/internal/store"
)

// Config holds the dependencies of the HTTP handler.
type Config struct {
	Store   *store.Store
	Auth    *auth.Service
	Runner  *jobs.Runner
	Web     fs.FS  // built frontend rooted at index.html
	Mode    string // "serve" or "desktop"
	Version string
}

type server struct {
	Config
}

// New returns the full handler (API + SPA) shared by serve and desktop.
func New(cfg Config) http.Handler {
	s := &server{cfg}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/setup", s.setupStatus)
	mux.HandleFunc("POST /api/v1/setup/admin", s.setupAdmin)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)

	mux.HandleFunc("POST /api/v1/auth/logout", s.requireAuth(s.logout))
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.me))
	mux.HandleFunc("GET /api/v1/jobs", s.requireAuth(s.listJobs))
	mux.HandleFunc("POST /api/v1/jobs/demo", s.requireAuth(s.demoJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.requireAuth(s.getJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.requireAuth(s.jobEvents))

	// Unknown API paths must not fall through to the SPA.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "не найдено")
	})
	mux.Handle("/", spaHandler(cfg.Web))
	return recoverMiddleware(mux)
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p == http.ErrAbortHandler {
				panic(p)
			}
			slog.Error("panic in handler", "path", r.URL.Path, "panic", p)
			writeError(w, http.StatusInternalServerError, "внутренняя ошибка")
		}()
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

// requireAuth rejects requests without a valid session cookie with 401.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.Auth.Authenticate(r.Context(), auth.TokenFromRequest(r))
		if errors.Is(err, auth.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, auth.ErrUnauthorized.Error())
			return
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}

func userFrom(r *http.Request) store.User {
	u, _ := r.Context().Value(ctxKey{}).(store.User)
	return u
}

func (s *server) internal(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "внутренняя ошибка")
}

// spaHandler serves static files and falls back to index.html for any other
// path (client-side routing).
func spaHandler(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(fsys, name); err == nil && !st.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		b, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.Error(w, "frontend not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	})
}
