package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/store"
)

func (s *server) pluginError(w http.ResponseWriter, r *http.Request, err error) {
	var pe *plugins.Error
	if errors.As(err, &pe) {
		body := map[string]any{"error": pe.Msg}
		if len(pe.Fields) > 0 {
			body["fields"] = pe.Fields
		}
		if len(pe.Instances) > 0 {
			body["instances"] = pe.Instances
		}
		writeJSON(w, pe.Status, body)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "не найдено")
		return
	}
	s.internal(w, r, err)
}

func (s *server) pluginsList(w http.ResponseWriter, r *http.Request) {
	l, err := s.Plugins.List(r.Context())
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *server) pluginGet(w http.ResponseWriter, r *http.Request) {
	d, err := s.Plugins.Get(r.Context(), r.PathValue("id"), r.URL.Query().Get("unit") == "1")
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// pluginsSub serves GET /plugins/{a}/{b}: /plugins/instances/{iid},
// /plugins/{id}/instances and /plugins/{id}/icon (the first two patterns
// would conflict in the mux).
func (s *server) pluginsSub(w http.ResponseWriter, r *http.Request) {
	a, b := r.PathValue("a"), r.PathValue("b")
	switch {
	case a == "instances":
		iid, err := strconv.ParseInt(b, 10, 64)
		if err != nil {
			writeError(w, http.StatusNotFound, "экземпляр не найден")
			return
		}
		v, err := s.Plugins.Instance(r.Context(), iid, r.URL.Query().Get("status") == "refresh")
		if err != nil {
			s.pluginError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case b == "instances":
		list, err := s.Plugins.Instances(r.Context(), a)
		if err != nil {
			s.pluginError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"instances": list})
	case b == "icon":
		icon, err := s.Plugins.Icon(r.Context(), a)
		if err != nil {
			s.pluginError(w, r, err)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "image/svg+xml")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-cache")
		_, _ = w.Write(icon)
	default:
		writeError(w, http.StatusNotFound, "не найдено")
	}
}

// pluginsPlan serves POST /plugins/{a}/{b}/plan: /plugins/{id}/instances/plan
// (create) and /plugins/instances/{iid}/plan (update/remove).
func (s *server) pluginsPlan(w http.ResponseWriter, r *http.Request) {
	a, b := r.PathValue("a"), r.PathValue("b")
	switch {
	case a == "instances":
		iid, err := strconv.ParseInt(b, 10, 64)
		if err != nil {
			writeError(w, http.StatusNotFound, "экземпляр не найден")
			return
		}
		var req struct {
			Action string         `json:"action"`
			Config map[string]any `json:"config"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		pv, err := s.Plugins.ChangePlan(r.Context(), iid, req.Action, req.Config)
		if err != nil {
			s.pluginError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, pv)
	case b == "instances":
		var req struct {
			Name   string         `json:"name"`
			Config map[string]any `json:"config"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		pv, err := s.Plugins.CreatePlan(r.Context(), a, req.Name, req.Config)
		if err != nil {
			s.pluginError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, pv)
	default:
		writeError(w, http.StatusNotFound, "не найдено")
	}
}

func (s *server) pluginApply(w http.ResponseWriter, r *http.Request) {
	var req plugins.ApplyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	job, err := s.Plugins.Apply(r.Context(), r.PathValue("plan"), req)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *server) pluginUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, plugins.MaxPackage+1<<20)
	f, _, err := r.FormFile("file")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "пакет больше 64 МБ")
			return
		}
		writeError(w, http.StatusBadRequest, "нужен файл пакета (поле file)")
		return
	}
	defer f.Close()
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	res, err := s.Plugins.Upload(r.Context(), f)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) pluginFetch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.Plugins.Fetch(r.Context(), req.URL)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) pluginInstall(w http.ResponseWriter, r *http.Request) {
	var req plugins.InstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	job, err := s.Plugins.Install(r.Context(), req)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *server) pluginEnable(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		job, err := s.Plugins.SetEnabled(r.Context(), r.PathValue("id"), on)
		if err != nil {
			s.pluginError(w, r, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
	}
}

func (s *server) pluginRemove(w http.ResponseWriter, r *http.Request) {
	job, err := s.Plugins.Remove(r.Context(), r.PathValue("id"))
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job})
}

func (s *server) pluginTargets(w http.ResponseWriter, r *http.Request) {
	list, err := s.Plugins.Candidates(r.Context())
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": list})
}

func (s *server) pluginAuthors(w http.ResponseWriter, r *http.Request) {
	list, err := s.Plugins.Authors(r.Context())
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authors": list})
}

func (s *server) pluginForgetAuthor(w http.ResponseWriter, r *http.Request) {
	if err := s.Plugins.ForgetAuthor(r.Context(), r.PathValue("key")); err != nil {
		s.pluginError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) pluginCatalog(w http.ResponseWriter, r *http.Request) {
	v, err := s.Plugins.Catalog(r.Context())
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// pluginCatalogRefresh downloads the catalog now; a download or signature
// failure is part of the answer (error), not an HTTP error.
func (s *server) pluginCatalogRefresh(w http.ResponseWriter, r *http.Request) {
	_ = s.Plugins.RefreshCatalog(r.Context())
	s.pluginCatalog(w, r)
}

func (s *server) pluginFromCatalog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := s.Plugins.FetchFromCatalog(r.Context(), req.ID)
	if err != nil {
		s.pluginError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
