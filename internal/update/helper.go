package update

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"hestia/internal/version"
)

// Helper is the loopback endpoint of the desktop app that hands its embedded
// server binary to the web page of a remote controller (path 1, offline). The
// page of the controller downloads it from here and uploads it to the
// controller. Only the controller's origin may read it, and only with the
// nonce, which lives as long as the app does.
type Helper struct {
	nonce   string
	origin  string
	ver     string
	payload []byte
	sum     string
}

// NewHelper builds the helper for payload (the app's server binary) of the
// given version; remoteURL is the address of the controller whose page may
// fetch it.
func NewHelper(payload []byte, ver, remoteURL string) (*Helper, error) {
	u, err := url.Parse(remoteURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("неверный адрес контроллера")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	return &Helper{
		nonce: hex.EncodeToString(b), origin: u.Scheme + "://" + u.Host,
		ver: ver, payload: payload, sum: hex.EncodeToString(sum[:]),
	}, nil
}

// Nonce is the secret path component.
func (h *Helper) Nonce() string { return h.nonce }

// OfferURL is the address the window opens on the remote controller: its
// update screen, which knows where the helper listens (from) and the nonce.
func OfferURL(remoteURL, helperAddr, appVersion, nonce string) string {
	q := url.Values{"from": {"http://" + helperAddr}, "v": {appVersion}, "n": {nonce}}
	return strings.TrimRight(remoteURL, "/") + "/#/update/offer?" + q.Encode()
}

// OlderURL opens the update screen with the notice that the app is older
// than the controller.
func OlderURL(remoteURL, appVersion string) string {
	q := url.Values{"older": {"1"}, "v": {appVersion}}
	return strings.TrimRight(remoteURL, "/") + "/#/update/offer?" + q.Encode()
}

// Handler serves /payload/<nonce> and /payload/<nonce>/meta; everything else is 404.
func (h *Helper) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, "/payload/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		nonce, sub, _ := strings.Cut(rest, "/")
		if subtle.ConstantTimeCompare([]byte(nonce), []byte(h.nonce)) != 1 || (sub != "" && sub != "meta") {
			http.NotFound(w, r)
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			if o != h.origin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
			w.Header().Set("Vary", "Origin")
		}
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Access-Control-Allow-Methods", "GET")
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodGet:
		default:
			w.Header().Set("Allow", "GET, OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if sub == "meta" {
			v, _ := version.Parse(h.ver)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"version": h.ver, "sha256": h.sum, "size": len(h.payload), "dirty": v.Dirty})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(h.payload)))
		_, _ = w.Write(h.payload)
	})
}
