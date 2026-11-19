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

	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/dnsname"
	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/netscan"
	"github.com/uxerror/hestia/internal/onboard"
	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/tlsself"
	"github.com/uxerror/hestia/internal/update"
)

// Config holds the dependencies of the HTTP handler.
type Config struct {
	Store   *store.Store
	Auth    *auth.Service
	Runner  *jobs.Runner
	Onboard *onboard.Service
	// Inventory serves /inventory; it must be started by the caller.
	Inventory *inventory.Service
	// Netscan serves /network (optional in tests).
	Netscan *netscan.Manager
	// Identity is the controller's SSH identity (public part is exposed).
	Identity secrets.Identity
	// Selfinstall moves the controller to a server; Gate carries the
	// transfer/moved modes (both optional in tests).
	Selfinstall *selfinstall.Service
	Gate        *selfinstall.Gate
	// DNS gives the controller a name through AdGuard Home (optional in tests).
	DNS *dnsname.Service
	// Update updates the installed controller (optional in tests).
	Update *update.Service
	// Plugins installs and runs plugins (optional in tests).
	Plugins *plugins.Manager
	// TLS is the HTTPS of the controller (optional in tests): /ca.crt, the
	// redirect from HTTP, health.tls and /tls.
	TLS        *tlsself.Service
	InstanceID string
	Web        fs.FS  // built frontend rooted at index.html
	Mode       string // "serve" or "desktop"
	Version    string
}

type server struct {
	Config
}

// New returns the full handler (API + SPA) shared by serve and desktop.
func New(cfg Config) http.Handler {
	if cfg.Gate == nil {
		cfg.Gate = &selfinstall.Gate{}
	}
	s := &server{cfg}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/setup", s.setupStatus)
	mux.HandleFunc("POST /api/v1/setup/admin", s.setupAdmin)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/handoff", s.handoff)

	mux.HandleFunc("POST /api/v1/auth/logout", s.requireAuth(s.logout))
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.me))
	mux.HandleFunc("GET /api/v1/jobs", s.requireAuth(s.listJobs))
	mux.HandleFunc("POST /api/v1/jobs/demo", s.requireAuth(s.demoJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.requireAuth(s.getJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.requireAuth(s.jobEvents))

	mux.HandleFunc("GET /api/v1/identity", s.requireAuth(s.identity))
	mux.HandleFunc("POST /api/v1/targets/probe", s.requireAuth(s.probeTarget))
	mux.HandleFunc("POST /api/v1/targets", s.requireAuth(s.createTarget))
	mux.HandleFunc("GET /api/v1/targets", s.requireAuth(s.listTargets))
	mux.HandleFunc("GET /api/v1/targets/{id}", s.requireAuth(s.getTarget))
	mux.HandleFunc("DELETE /api/v1/targets/{id}", s.requireAuth(s.deleteTarget))

	mux.HandleFunc("GET /api/v1/inventory", s.requireAuth(s.listInventory))
	mux.HandleFunc("GET /api/v1/inventory/events", s.requireAuth(s.inventoryEvents))
	mux.HandleFunc("GET /api/v1/inventory/{id}", s.requireAuth(s.getInventory))
	mux.HandleFunc("POST /api/v1/inventory/{id}/refresh", s.requireAuth(s.refreshInventory))
	mux.HandleFunc("GET /api/v1/inventory/{id}/role-fix", s.requireAuth(s.rolePlan))
	mux.HandleFunc("POST /api/v1/inventory/{id}/role-fix", s.requireAuth(s.fixRole))

	if cfg.Netscan != nil {
		mux.HandleFunc("GET /api/v1/network", s.requireAuth(s.networkView))
		mux.HandleFunc("POST /api/v1/network/scan", s.requireAuth(s.networkScan))
		mux.HandleFunc("DELETE /api/v1/network/scan", s.requireAuth(s.networkCancel))
		mux.HandleFunc("PUT /api/v1/network/settings", s.requireAuth(s.networkSettings))
		mux.HandleFunc("DELETE /api/v1/network/hosts/{ip}", s.requireAuth(s.networkForget))
	}

	if cfg.DNS != nil {
		mux.HandleFunc("GET /api/v1/dns", s.requireAuth(s.dnsView))
		mux.HandleFunc("POST /api/v1/dns/adguard/probe", s.requireAuth(s.dnsProbe))
		mux.HandleFunc("POST /api/v1/dns/adguard", s.requireAuth(s.dnsConnect(false)))
		mux.HandleFunc("PUT /api/v1/dns/adguard", s.requireAuth(s.dnsConnect(true)))
		mux.HandleFunc("DELETE /api/v1/dns/adguard", s.requireAuth(s.dnsDisconnect))
		mux.HandleFunc("POST /api/v1/dns/plan", s.requireAuth(s.dnsPlan))
		mux.HandleFunc("POST /api/v1/dns/apply", s.requireAuth(s.dnsApply))
		mux.HandleFunc("POST /api/v1/dns/check", s.requireAuth(s.dnsCheck))
	}

	if cfg.Selfinstall != nil {
		mux.HandleFunc("GET /api/v1/selfinstall", s.requireAuth(s.selfinstallState))
		mux.HandleFunc("POST /api/v1/selfinstall/probe", s.requireAuth(s.selfinstallProbe))
		mux.HandleFunc("POST /api/v1/selfinstall", s.requireAuth(s.selfinstallStart))
	}

	if cfg.Update != nil {
		mux.HandleFunc("GET /api/v1/update", s.requireAuth(s.updateStatus))
		mux.HandleFunc("POST /api/v1/update/check", s.requireAuth(s.updateCheck))
		mux.HandleFunc("POST /api/v1/update/upload", s.requireAuth(s.updateUpload))
		mux.HandleFunc("POST /api/v1/update", s.requireAuth(s.updateStart))
	}

	if cfg.Plugins != nil {
		mux.HandleFunc("GET /api/v1/plugins", s.requireAuth(s.pluginsList))
		mux.HandleFunc("GET /api/v1/plugins/catalog", s.requireAuth(s.pluginCatalog))
		mux.HandleFunc("POST /api/v1/plugins/catalog/refresh", s.requireAuth(s.pluginCatalogRefresh))
		mux.HandleFunc("POST /api/v1/plugins/packages/catalog", s.requireAuth(s.pluginFromCatalog))
		mux.HandleFunc("POST /api/v1/plugins/packages", s.requireAuth(s.pluginUpload))
		mux.HandleFunc("POST /api/v1/plugins/packages/fetch", s.requireAuth(s.pluginFetch))
		mux.HandleFunc("POST /api/v1/plugins/install", s.requireAuth(s.pluginInstall))
		mux.HandleFunc("GET /api/v1/plugins/targets", s.requireAuth(s.pluginTargets))
		mux.HandleFunc("GET /api/v1/plugins/authors", s.requireAuth(s.pluginAuthors))
		mux.HandleFunc("GET /api/v1/graph", s.requireAuth(s.graphView))
		mux.HandleFunc("PUT /api/v1/graph/positions", s.requireAuth(s.graphPositionsSave))
		mux.HandleFunc("DELETE /api/v1/graph/positions", s.requireAuth(s.graphPositionsClear))
		mux.HandleFunc("GET /api/v1/plugins/links/candidates", s.requireAuth(s.linkCandidates))
		mux.HandleFunc("POST /api/v1/plugins/links/plan", s.requireAuth(s.linkPlan))
		mux.HandleFunc("GET /api/v1/plugins/links/{id}", s.requireAuth(s.linkGet))
		mux.HandleFunc("POST /api/v1/plugins/links/{id}/plan", s.requireAuth(s.linkChangePlan))
		mux.HandleFunc("POST /api/v1/plugins/links/{id}/renew", s.requireAuth(s.linkRenew))
		mux.HandleFunc("POST /api/v1/plugins/instances/{iid}/actions/{name}", s.requireAuth(s.instanceAction))
		mux.HandleFunc("POST /api/v1/plugins/compose/plan", s.requireAuth(s.composePlan))
		mux.HandleFunc("DELETE /api/v1/plugins/authors/{key}", s.requireAuth(s.pluginForgetAuthor))
		mux.HandleFunc("GET /api/v1/plugins/{id}", s.requireAuth(s.pluginGet))
		mux.HandleFunc("DELETE /api/v1/plugins/{id}", s.requireAuth(s.pluginRemove))
		mux.HandleFunc("POST /api/v1/plugins/{id}/enable", s.requireAuth(s.pluginEnable(true)))
		mux.HandleFunc("POST /api/v1/plugins/{id}/disable", s.requireAuth(s.pluginEnable(false)))
		mux.HandleFunc("GET /api/v1/plugins/{a}/{b}", s.requireAuth(s.pluginsSub))
		mux.HandleFunc("POST /api/v1/plugins/{a}/{b}/plan", s.requireAuth(s.pluginsPlan))
		mux.HandleFunc("POST /api/v1/plugins/plans/{plan}/apply", s.requireAuth(s.pluginApply))
	}

	if cfg.TLS != nil {
		mux.HandleFunc("GET /api/v1/tls", s.requireAuth(s.tlsState))
	}

	// Unknown API paths must not fall through to the SPA.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "не найдено")
	})
	mux.Handle("/", spaHandler(cfg.Web))
	moved := newMovedHandler(cfg.Gate, cfg.Web, cfg.Version)
	var h http.Handler = mux
	if cfg.TLS != nil {
		h = cfg.TLS.Middleware(mux)
	}
	return recoverMiddleware(modeMiddleware(cfg.Gate, moved, h))
}

// modeMiddleware implements the two process modes: after the controller
// moved, only the "moved" screen is served; while the state is being copied,
// requests that change anything are refused (login and logout still work).
func modeMiddleware(g *selfinstall.Gate, moved, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Moved() != nil {
			moved.ServeHTTP(w, r)
			return
		}
		if g.Transferring() {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
			default:
				if !strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
					writeError(w, http.StatusServiceUnavailable, "идёт перенос Hestia на сервер")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
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
