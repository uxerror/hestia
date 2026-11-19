package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/uxerror/hestia/internal/store"
)

func (s *server) inventoryError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	s.internal(w, r, err)
}

func (s *server) listInventory(w http.ResponseWriter, r *http.Request) {
	es, err := s.Inventory.List(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"inventory": es})
}

func (s *server) getInventory(w http.ResponseWriter, r *http.Request) {
	id, ok := targetID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	e, err := s.Inventory.Get(r.Context(), id)
	if err != nil {
		s.inventoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *server) refreshInventory(w http.ResponseWriter, r *http.Request) {
	id, ok := targetID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	job, err := s.Inventory.Refresh(r.Context(), id)
	if err != nil {
		s.inventoryError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

// rolePlan shows what completing the Hestia role would change; it changes nothing.
func (s *server) rolePlan(w http.ResponseWriter, r *http.Request) {
	id, ok := targetID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	p, err := s.Onboard.RolePlan(r.Context(), id)
	if err != nil {
		s.onboardError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// fixRole applies the plan, only with an explicit confirmation.
func (s *server) fixRole(w http.ResponseWriter, r *http.Request) {
	id, ok := targetID(r)
	if !ok {
		writeError(w, http.StatusNotFound, "цель не найдена")
		return
	}
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "нужно подтверждение: confirm=true")
		return
	}
	job, err := s.Onboard.FixRole(r.Context(), id)
	if err != nil {
		s.onboardError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

// inventoryEvents streams an entry ("snapshot" event) whenever a collection
// starts or ends. While at least one stream is open the service refreshes
// the targets periodically.
func (s *server) inventoryEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "потоковая передача недоступна")
		return
	}
	ch, cancel := s.Inventory.Subscribe()
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(": ok\n\n")); err != nil {
		return
	}
	fl.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			fl.Flush()
		case e, open := <-ch:
			if !open { // dropped as a slow consumer; EventSource reconnects
				return
			}
			if err := sendEvent(w, fl, "snapshot", e); err != nil {
				return
			}
		}
	}
}
