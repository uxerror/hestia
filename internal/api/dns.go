package api

import (
	"errors"
	"net/http"

	"github.com/uxerror/hestia/internal/dnsname"
)

// dnsError writes an error of the dnsname service; the body carries a code the
// UI acts on. A failure of AdGuard is never a 401: that would sign the user out.
func (s *server) dnsError(w http.ResponseWriter, r *http.Request, err error) {
	var de *dnsname.Error
	if !errors.As(err, &de) {
		s.internal(w, r, err)
		return
	}
	body := map[string]any{"error": de.Msg, "code": de.Code}
	if de.Fingerprint != "" {
		body["fingerprint"] = de.Fingerprint
	}
	if de.Job != "" {
		body["job_id"] = de.Job
	}
	writeJSON(w, de.HTTP, body)
}

func (s *server) dnsView(w http.ResponseWriter, r *http.Request) {
	v, err := s.DNS.View(r.Context())
	if err != nil {
		s.dnsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *server) dnsProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.DNS.Probe(r.Context(), req.URL)
	if err != nil {
		s.dnsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) dnsConnect(replace bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req dnsname.ConnectRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		res, err := s.DNS.Connect(r.Context(), req, replace)
		if err != nil {
			s.dnsError(w, r, err)
			return
		}
		status := http.StatusCreated
		if replace {
			status = http.StatusOK
		}
		writeJSON(w, status, res)
	}
}

func (s *server) dnsDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.DNS.Disconnect(r.Context()); err != nil {
		s.dnsError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) dnsPlan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Domain string `json:"domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.DNS.MakePlan(r.Context(), req.Action, req.Domain)
	if err != nil {
		s.dnsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *server) dnsApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID string `json:"plan_id"`
		Hash   string `json:"hash"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	job, err := s.DNS.Apply(r.Context(), req.PlanID, req.Hash)
	if err != nil {
		s.dnsError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": job.ID})
}

// dnsCheck refreshes the status of the name now (read-only for AdGuard).
func (s *server) dnsCheck(w http.ResponseWriter, r *http.Request) {
	if err := s.DNS.Check(r.Context()); err != nil {
		s.dnsError(w, r, err)
		return
	}
	s.dnsView(w, r)
}
