package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/tlsself"
	"github.com/uxerror/hestia/sdk"
)

// tlsView is GET /api/v1/tls.
type tlsView struct {
	Mode       string     `json:"mode"`
	HTTPSPort  int        `json:"https_port"`
	LinkID     *int64     `json:"link_id"`
	CAInstance *int64     `json:"ca_instance"`
	Names      []string   `json:"names"`
	CASHA256   string     `json:"ca_sha256"`
	NotBefore  *time.Time `json:"not_before"`
	NotAfter   *time.Time `json:"not_after"`
	RenewAfter *time.Time `json:"renew_after"`
	RenewError string     `json:"renew_error"`
	Expired    bool       `json:"expired"`
	Listener   string     `json:"listener"`
	Reset      bool       `json:"reset"`
	Error      string     `json:"error,omitempty"`
	LinkStatus string     `json:"link_status,omitempty"`
	LinkDetail string     `json:"link_detail,omitempty"`
	DesktopMin string     `json:"desktop_min"`
}

func (s *server) tlsState(w http.ResponseWriter, r *http.Request) {
	in := s.TLS.Info()
	v := tlsView{Mode: in.Mode, HTTPSPort: in.HTTPSPort, Names: in.Names, CASHA256: in.CASHA256, NotBefore: in.NotBefore,
		NotAfter: in.NotAfter, Expired: in.Expired, Listener: in.Listener, Reset: in.Reset, Error: in.Error, DesktopMin: tlsself.DesktopMin}
	if s.Plugins != nil {
		l, err := s.Plugins.BuiltinLink(r.Context(), tlsself.PortTLS)
		switch {
		case err == nil:
			id, ca := l.ID, l.ProviderInstance
			v.LinkID, v.CAInstance = &id, &ca
			v.RenewAfter, v.RenewError = l.RenewAfter, l.RenewError
			v.LinkStatus, v.LinkDetail = l.Status, l.Detail
		case !errors.Is(err, store.ErrNotFound):
			s.internal(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) linkRenew(w http.ResponseWriter, r *http.Request) {
	id, ok := linkID(w, r)
	if !ok {
		return
	}
	job, err := s.Plugins.RenewLink(r.Context(), id)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": job.ID})
}

// instanceAction is POST /plugins/instances/{iid}/actions/{name}: the
// parameters are passed to the plugin and kept nowhere; a download goes to
// the browser as a file.
func (s *server) instanceAction(w http.ResponseWriter, r *http.Request) {
	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil || iid <= 0 {
		writeError(w, http.StatusBadRequest, "неверный экземпляр")
		return
	}
	var req struct {
		Params   map[string]any `json:"params"`
		Password string         `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	_, def, err := s.Plugins.ActionDef(r.Context(), iid, r.PathValue("name"))
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	if def.Confirm == sdk.ConfirmPassword {
		err := s.Auth.VerifyPassword(r.Context(), userFrom(r).Username, req.Password)
		switch {
		case errors.Is(err, auth.ErrBadCredentials):
			writeError(w, http.StatusForbidden, "неверный пароль администратора")
			return
		case err != nil:
			s.internal(w, r, err)
			return
		}
	}
	res, err := s.Plugins.RunAction(r.Context(), iid, def.Name, req.Params)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	if d := res.Download; d != nil {
		w.Header().Set("Content-Type", d.MIME)
		w.Header().Set("Content-Disposition", `attachment; filename="`+d.Name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if res.Message != "" {
			w.Header().Set("X-Hestia-Message", strconv.Quote(res.Message))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(d.Data)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"message": res.Message})
}
