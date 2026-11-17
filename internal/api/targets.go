package api

import (
	"errors"
	"net/http"
	"strconv"

	"hestia/internal/onboard"
	"hestia/internal/store"
)

func (s *server) identity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"ssh_public_key": s.Identity.AuthorizedKey,
		"fingerprint":    s.Identity.Fingerprint,
	})
}

// onboardError maps service errors to HTTP responses.
func (s *server) onboardError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *onboard.Error
	switch {
	case errors.As(err, &oe):
		writeError(w, oe.Status, oe.Msg)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "цель не найдена")
	default:
		s.internal(w, r, err)
	}
}

// probeTarget never logs the request: it carries passwords and private keys.
func (s *server) probeTarget(w http.ResponseWriter, r *http.Request) {
	var req onboard.ProbeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.Onboard.Probe(r.Context(), req)
	if err != nil {
		s.onboardError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) createTarget(w http.ResponseWriter, r *http.Request) {
	var req onboard.CreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	job, err := s.Onboard.Connect(r.Context(), req)
	if err != nil {
		s.onboardError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *server) listTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Store.ListTargets(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": ts})
}

func targetID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *server) getTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := targetID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	t, err := s.Store.GetTarget(r.Context(), id)
	if err != nil {
		s.onboardError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"target": t})
}

func (s *server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := targetID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	revert := false
	switch r.URL.Query().Get("revert") {
	case "", "false":
	case "true":
		revert = true
	default:
		writeError(w, http.StatusBadRequest, "revert: true или false")
		return
	}
	job, err := s.Onboard.Remove(r.Context(), id, revert)
	if err != nil {
		s.onboardError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}
