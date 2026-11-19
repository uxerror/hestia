package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/store"
)

type userDTO struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

func toUser(u store.User) map[string]userDTO {
	return map[string]userDTO{"user": {ID: u.ID, Username: u.Username}}
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	h := map[string]any{
		"status": "ok", "version": s.Version, "instance_id": s.InstanceID, "transferring": s.Gate.Transferring(),
	}
	// The name is public information (the desktop app switches to it); it is
	// only announced while it is verified and healthy.
	if s.DNS != nil {
		if u := s.DNS.PublicURL(r.Context()); u != "" {
			// With HTTPS on and the name in the certificate the name is
			// announced as https.
			if s.TLS != nil && s.TLS.Active() && s.TLS.HasName(strings.TrimPrefix(u, "http://")) {
				u = "https://" + strings.TrimPrefix(u, "http://")
				if p := s.TLS.Port(); p != 443 {
					u += ":" + strconv.Itoa(p)
				}
			}
			h["dns_url"] = u
		}
	}
	if s.TLS != nil {
		h["tls"] = s.TLS.Health()
	} else {
		h["tls"] = map[string]any{"enabled": false, "port": 0, "ca_sha256": "", "expired": false}
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *server) setupStatus(w http.ResponseWriter, r *http.Request) {
	needs, err := s.Auth.NeedsAdmin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"needs_admin": needs, "mode": s.Mode})
}

func (s *server) setupAdmin(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decodeJSON(w, r, &c) {
		return
	}
	u, tok, err := s.Auth.CreateAdmin(r.Context(), c.Username, c.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, auth.ErrSetupDone):
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		s.internal(w, r, err)
	default:
		auth.SetCookie(w, r, tok)
		writeJSON(w, http.StatusCreated, toUser(u))
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decodeJSON(w, r, &c) {
		return
	}
	u, tok, err := s.Auth.Login(r.Context(), c.Username, c.Password)
	switch {
	case errors.Is(err, auth.ErrBadCredentials):
		writeError(w, http.StatusUnauthorized, err.Error())
	case err != nil:
		s.internal(w, r, err)
	default:
		auth.SetCookie(w, r, tok)
		writeJSON(w, http.StatusOK, toUser(u))
	}
}

// handoff signs in with the one-time token that came with the moved database.
func (s *server) handoff(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	tok, err := s.Auth.Handoff(r.Context(), body.Token)
	switch {
	case errors.Is(err, auth.ErrBadHandoff):
		writeError(w, http.StatusUnauthorized, err.Error())
	case err != nil:
		s.internal(w, r, err)
	default:
		auth.SetCookie(w, r, tok)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.Logout(r.Context(), auth.TokenFromRequest(r)); err != nil {
		s.internal(w, r, err)
		return
	}
	auth.ClearCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, toUser(userFrom(r)))
}

func (s *server) listJobs(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListJobs(r.Context(), 50)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": list})
}

func (s *server) getJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.Store.GetJob(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "задача не найдена")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": s.jobView(j)})
}

// jobDTO is a job plus the in-memory result its body reported (if any).
type jobDTO struct {
	store.Job
	Result any `json:"result,omitempty"`
}

func (s *server) jobView(j store.Job) jobDTO {
	d := jobDTO{Job: j}
	if j.Status == store.JobDone {
		d.Result = s.Runner.Result(j.ID)
	}
	return d
}

func (s *server) demoJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.Runner.Demo()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": j})
}

// jobEvents streams a snapshot, then live step/log/status events, and closes
// after the final status.
func (s *server) jobEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "потоковая передача недоступна")
		return
	}
	// Subscribe before reading the snapshot so no event falls in between.
	ch, cancel := s.Runner.Hub().Subscribe(id)
	defer cancel()

	j, err := s.Store.GetJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "задача не найдена")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := sendEvent(w, fl, "snapshot", s.jobView(j)); err != nil || store.IsFinal(j.Status) {
		return
	}

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
		case ev, open := <-ch:
			if !open {
				// Dropped as a slow consumer: resend the state and end;
				// EventSource will reconnect.
				if j, err := s.Store.GetJob(r.Context(), id); err == nil {
					_ = sendEvent(w, fl, "snapshot", s.jobView(j))
				}
				return
			}
			if err := sendEvent(w, fl, ev.Type, ev.Data); err != nil {
				return
			}
			if se, ok := ev.Data.(jobs.StatusEvent); ok && store.IsFinal(se.Status) {
				return
			}
		}
	}
}

func sendEvent(w http.ResponseWriter, fl http.Flusher, name string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b); err != nil {
		return err
	}
	fl.Flush()
	return nil
}
