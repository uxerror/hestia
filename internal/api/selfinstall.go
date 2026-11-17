package api

import (
	"errors"
	"net/http"

	"hestia/internal/selfinstall"
	"hestia/internal/store"
)

func (s *server) selfinstallError(w http.ResponseWriter, r *http.Request, err error) {
	var se *selfinstall.Error
	if errors.As(err, &se) {
		writeError(w, se.Status, se.Msg)
		return
	}
	s.internal(w, r, err)
}

func (s *server) selfinstallState(w http.ResponseWriter, r *http.Request) {
	st, err := s.Selfinstall.State(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *server) selfinstallProbe(w http.ResponseWriter, r *http.Request) {
	var req selfinstall.ProbeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.Selfinstall.Probe(r.Context(), req)
	if err != nil {
		s.selfinstallError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) selfinstallStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProbeID string `json:"probe_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	var u store.User = userFrom(r)
	job, err := s.Selfinstall.Start(r.Context(), req.ProbeID, u.ID)
	if err != nil {
		s.selfinstallError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}
