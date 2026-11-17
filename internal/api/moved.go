package api

import (
	"context"
	"io/fs"
	"net/http"
	"strings"

	"hestia/internal/selfinstall"
)

// NewMoved is the handler of a controller that moved to a server (remote.json
// exists): the database is never opened. It serves the health endpoint
// (status "moved"), /api/v1/remote and the SPA, which shows where Hestia runs.
func NewMoved(gate *selfinstall.Gate, web fs.FS, version string) http.Handler {
	return recoverMiddleware(newMovedHandler(gate, web, version))
}

func newMovedHandler(gate *selfinstall.Gate, web fs.FS, version string) http.Handler {
	spa := spaHandler(web)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rem := gate.Moved()
		if rem == nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/health":
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "moved", "version": version, "remote": rem.URL, "instance_id": rem.InstanceID,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/remote":
			writeJSON(w, http.StatusOK, map[string]any{
				"url": rem.URL, "instance_id": rem.InstanceID, "reachable": checkRemote(r.Context(), *rem),
			})
		case strings.HasPrefix(r.URL.Path, "/api/"):
			writeError(w, http.StatusServiceUnavailable, "Hestia работает на "+rem.URL)
		default:
			spa.ServeHTTP(w, r)
		}
	})
}

func checkRemote(ctx context.Context, r selfinstall.Remote) bool {
	return selfinstall.CheckRemote(ctx, r)
}
