package api

import (
	"errors"
	"net/http"
	"net/url"

	"hestia/internal/update"
)

func (s *server) updateError(w http.ResponseWriter, r *http.Request, err error) {
	var ue *update.Error
	if errors.As(err, &ue) {
		if ue.Confirm {
			writeJSON(w, ue.Status, map[string]any{"error": ue.Msg, "confirm": true})
			return
		}
		writeError(w, ue.Status, ue.Msg)
		return
	}
	s.internal(w, r, err)
}

func (s *server) updateStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Update.Status(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *server) updateCheck(w http.ResponseWriter, r *http.Request) {
	gh, err := s.Update.CheckNow(r.Context())
	if err != nil {
		s.updateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, gh)
}

// updateUpload accepts the controller binary as the raw request body; the
// version the sender claims is in the "version" query parameter.
func (s *server) updateUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, update.MaxUpload+1)
	q, _ := url.ParseQuery(r.URL.RawQuery)
	res, err := s.Update.Upload(r.Body, q.Get("version"))
	if err != nil {
		s.updateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) updateStart(w http.ResponseWriter, r *http.Request) {
	var req update.Request
	if !decodeJSON(w, r, &req) {
		return
	}
	job, err := s.Update.Start(r.Context(), req)
	if err != nil {
		s.updateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}
