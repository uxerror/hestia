package api

import (
	"errors"
	"net/http"

	"hestia/internal/netscan"
	"hestia/internal/store"
)

func (s *server) networkView(w http.ResponseWriter, r *http.Request) {
	v, err := s.Netscan.View(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) networkScan(w http.ResponseWriter, r *http.Request) {
	job, err := s.Netscan.Scan(r.Context())
	if errors.Is(err, netscan.ErrBusy) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "job": job})
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *server) networkCancel(w http.ResponseWriter, r *http.Request) {
	if !s.Netscan.Cancel() {
		writeError(w, http.StatusNotFound, "сканирование не идёт")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) networkSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExtraSubnets []string `json:"extra_subnets"`
		Exclude      []string `json:"exclude"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	extra, excl, err := s.Netscan.SetSettings(r.Context(), req.ExtraSubnets, req.Exclude)
	var ie *netscan.InputError
	if errors.As(err, &ie) {
		writeError(w, http.StatusBadRequest, ie.Msg)
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	subnets, _ := s.Netscan.Subnets(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"extra_subnets": extra, "exclude": excl, "subnets": subnets})
}

func (s *server) networkForget(w http.ResponseWriter, r *http.Request) {
	err := s.Netscan.Forget(r.Context(), r.PathValue("ip"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "хост не найден")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
