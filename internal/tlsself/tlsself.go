// Package tlsself is the HTTPS of the controller itself: the built-in
// consumer "Hestia" of a tls.cert link (its key is born and stays in
// <data>/tls), the HTTPS listener with a hot-swapped certificate, the
// redirect from HTTP and the recovery commands (hestia tls status|reset).
//
// It never locks the user out: without a loaded, unexpired certificate and
// a listening HTTPS port HTTP serves everything, no HSTS is ever sent.
package tlsself

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk/types"
)

// Settings of the controller.
const (
	SettingMode  = "tls_mode"  // off | on
	SettingReset = "tls_reset" // "1" after hestia tls reset, until HTTPS is on again
	ModeOn       = "on"
	ModeOff      = "off"
)

// Files under <data>.
const (
	DirName     = "tls"
	ResetMarker = "tls-reset"
	fileKey     = "key.pem"
	fileCert    = "cert.pem"
	fileCA      = "ca.pem"
	filePending = "key.pending.pem"
	fileState   = "state.json"
	keepRemoved = 2
)

// DesktopMin is the oldest desktop app that follows the controller to HTTPS.
const DesktopMin = "v0.4.0"

// Messages.
const (
	msgDisabledFlag = "HTTPS выключен флагом запуска (--https-listen \"\")"
	msgNotLoaded    = "Сертификат HTTPS не найден — Hestia работает по HTTP"
	msgReset        = "HTTPS выключен вручную (hestia tls reset)"
	msgNamesChanged = "Адрес Hestia изменился — обновите сертификат"
)

// State is <data>/tls/state.json.
type State struct {
	Mode      string    `json:"mode"`
	Link      int64     `json:"link"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CASHA256  string    `json:"ca_sha256"`
	DNS       []string  `json:"dns"`
	IPs       []string  `json:"ips"`
}

// Service is the HTTPS of the controller. Fill in the fields, call Init,
// SetHandler and Start; Close at the end.
type Service struct {
	DataDir    string
	Store      *store.Store
	Addr       string // --https-listen; "" disables HTTPS in this run
	InstanceID string
	Version    string
	// Names are the names to ask a certificate for: the verified name of
	// Hestia and the controller's IP.
	Names func(ctx context.Context) (dns, ips []string)
	// PeerZones are the DNS zones of a provider instance (nil: unknown,
	// nothing is filtered): names outside them are not asked for.
	PeerZones func(ctx context.Context, instance int64) []string
	Now       func() time.Time

	handler http.Handler
	cert    atomic.Pointer[tls.Certificate]
	op      sync.Mutex // serialises apply/remove/prepare

	mu      sync.Mutex
	mode    string
	reset   bool
	state   State
	caPEM   []byte
	ln      net.Listener
	srv     *http.Server
	port    int
	loadErr string
}

// Init reads the mode and handles the reset marker of `hestia tls reset`.
func (s *Service) Init(ctx context.Context) error {
	if s.Now == nil {
		s.Now = time.Now
	}
	mode, err := s.Store.GetSetting(ctx, SettingMode)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if mode != ModeOn {
		mode = ModeOff
	}
	marker := filepath.Join(s.DataDir, ResetMarker)
	if _, err := os.Stat(marker); err == nil {
		slog.Warn("найден маркер hestia tls reset: HTTPS выключен")
		mode = ModeOff
		if err := s.Store.SetSetting(ctx, SettingMode, ModeOff); err != nil {
			return err
		}
		if err := s.Store.SetSetting(ctx, SettingReset, "1"); err != nil {
			return err
		}
		if err := os.Remove(marker); err != nil {
			return err
		}
	}
	reset, _ := s.Store.GetSetting(ctx, SettingReset)
	s.mu.Lock()
	s.mode, s.reset = mode, reset == "1"
	s.mu.Unlock()
	return nil
}

// SetHandler is the handler served on HTTPS (the same as on HTTP).
func (s *Service) SetHandler(h http.Handler) { s.handler = h }

// Start opens the HTTPS listener when the mode is on and the files load;
// otherwise HTTP alone serves (the mode stays, so that a renewal or a
// reissue brings HTTPS back).
func (s *Service) Start() {
	s.mu.Lock()
	on := s.mode == ModeOn
	s.mu.Unlock()
	if err := s.loadFiles(); err != nil {
		if on {
			s.setLoadErr(err.Error())
			slog.Warn("HTTPS: сертификат не загружен, Hestia работает по HTTP", "err", err)
		}
		return
	}
	if !on {
		return
	}
	if err := s.listen(); err != nil {
		s.setLoadErr(err.Error())
		slog.Warn("HTTPS: порт не открыт, Hestia работает по HTTP", "addr", s.Addr, "err", err)
		return
	}
	s.setLoadErr("")
}

func (s *Service) setLoadErr(msg string) {
	s.mu.Lock()
	s.loadErr = msg
	s.mu.Unlock()
}

// Close stops the HTTPS listener.
func (s *Service) Close() {
	s.closeListener()
}

func (s *Service) dir() string { return filepath.Join(s.DataDir, DirName) }

func (s *Service) path(name string) string { return filepath.Join(s.dir(), name) }

// loadFiles reads key, certificate, root and state; the key must match.
func (s *Service) loadFiles() error {
	keyPEM, err := os.ReadFile(s.path(fileKey))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(s.path(fileCert))
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(s.path(fileCA))
	if err != nil {
		return err
	}
	var st State
	b, err := os.ReadFile(s.path(fileState))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s: %w", fileState, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("сертификат не подходит к ключу: %w", err)
	}
	if _, err := types.ParseCert(string(caPEM)); err != nil {
		return fmt.Errorf("%s: %w", fileCA, err)
	}
	s.cert.Store(&pair)
	s.mu.Lock()
	s.state, s.caPEM = st, caPEM
	s.mu.Unlock()
	return nil
}

func (s *Service) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := s.cert.Load()
	if c == nil {
		return nil, errors.New("сертификат HTTPS не загружен")
	}
	return c, nil
}

// listen opens the HTTPS listener (if it is not open).
func (s *Service) listen() error {
	if s.Addr == "" {
		return errors.New(msgDisabledFlag)
	}
	s.mu.Lock()
	open := s.ln != nil
	s.mu.Unlock()
	if open {
		return nil
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("порт HTTPS %s: %w", s.Addr, err)
	}
	h := s.handler
	if h == nil {
		h = http.NotFoundHandler()
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.getCert},
		// Handshake errors of scanners and old clients are not news.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	s.mu.Lock()
	s.ln, s.srv, s.port = ln, srv, ln.Addr().(*net.TCPAddr).Port
	s.mu.Unlock()
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	slog.Info("hestia слушает HTTPS", "addr", ln.Addr().String())
	return nil
}

func (s *Service) closeListener() {
	s.mu.Lock()
	srv := s.srv
	s.ln, s.srv, s.port = nil, nil, 0
	s.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		_ = srv.Close()
	}
}

// Port is the HTTPS port of the listener (0 if down).
func (s *Service) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// configuredPort is the port of --https-listen (0 if disabled or unknown).
func (s *Service) configuredPort() int {
	if p := s.Port(); p != 0 {
		return p
	}
	_, ps, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(ps)
	return n
}

// Active reports whether HTTP redirects to HTTPS: the mode is on, the
// listener is up and the certificate is loaded and not expired.
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked()
}

func (s *Service) activeLocked() bool {
	return s.mode == ModeOn && s.ln != nil && s.cert.Load() != nil && s.Now().Before(s.state.NotAfter)
}

// Info is the state of HTTPS for the API.
type Info struct {
	Mode      string     `json:"mode"`
	HTTPSPort int        `json:"https_port"`
	Listener  string     `json:"listener"` // up | down | disabled
	Names     []string   `json:"names"`
	CASHA256  string     `json:"ca_sha256"`
	NotBefore *time.Time `json:"not_before"`
	NotAfter  *time.Time `json:"not_after"`
	Expired   bool       `json:"expired"`
	Reset     bool       `json:"reset"`
	Error     string     `json:"error,omitempty"`
	Link      int64      `json:"-"`
}

// Info describes HTTPS now.
func (s *Service) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := Info{Mode: s.mode, HTTPSPort: s.port, Listener: "down", Names: []string{}, Reset: s.reset, Error: s.loadErr, Link: s.state.Link}
	switch {
	case s.Addr == "":
		in.Listener = "disabled"
	case s.ln != nil:
		in.Listener = "up"
	}
	if in.HTTPSPort == 0 {
		_, ps, _ := net.SplitHostPort(s.Addr)
		in.HTTPSPort, _ = strconv.Atoi(ps)
	}
	if s.cert.Load() != nil && s.mode == ModeOn {
		in.Names = append(slices.Clone(s.state.DNS), s.state.IPs...)
		in.CASHA256 = s.state.CASHA256
		nb, na := s.state.NotBefore, s.state.NotAfter
		in.NotBefore, in.NotAfter = &nb, &na
		in.Expired = !s.Now().Before(na)
	}
	return in
}

// Health is the public "tls" of /api/v1/health.
func (s *Service) Health() map[string]any {
	in := s.Info()
	// Enabled even with an expired certificate: the desktop app accepts it
	// (its chain goes to the pinned root) and shows a banner.
	enabled := in.Mode == ModeOn && in.Listener == "up" && in.NotAfter != nil
	return map[string]any{"enabled": enabled, "port": in.HTTPSPort, "ca_sha256": in.CASHA256, "expired": in.Expired}
}

// HasName reports whether the current certificate covers a DNS name.
func (s *Service) HasName(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cert.Load() != nil && slices.Contains(s.state.DNS, name)
}

// CAPEM is the root of the link while HTTPS is on (nil otherwise).
func (s *Service) CAPEM() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != ModeOn || len(s.caPEM) == 0 {
		return nil
	}
	return slices.Clone(s.caPEM)
}

// Middleware serves /ca.crt and, while Active, redirects HTTP to HTTPS
// with 308 — except GET /api/v1/health and GET /ca.crt (health checks of
// the update and of the DNS name go there over HTTP). HSTS is never set.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ca.crt" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			s.serveCA(w, r)
			return
		}
		if r.TLS == nil && !(r.Method == http.MethodGet && r.URL.Path == "/api/v1/health") && s.Active() {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			if p := s.Port(); p != 443 && p != 0 {
				host += ":" + strconv.Itoa(p)
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) serveCA(w http.ResponseWriter, r *http.Request) {
	ca := s.CAPEM()
	if ca == nil {
		http.Error(w, "HTTPS не включён", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodGet {
		_, _ = w.Write(ca)
	}
}

// writeAtomic writes a file 0600 through a temporary file and rename.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ensureDir creates <data>/tls with mode 0700.
func (s *Service) ensureDir() error {
	if err := os.MkdirAll(s.dir(), 0o700); err != nil {
		return err
	}
	return os.Chmod(s.dir(), 0o700)
}

func (s *Service) setMode(ctx context.Context, mode string) error {
	if err := s.Store.SetSetting(ctx, SettingMode, mode); err != nil {
		return err
	}
	if mode == ModeOn {
		if err := s.Store.SetSetting(ctx, SettingReset, ""); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.mode = mode
	if mode == ModeOn {
		s.reset = false
	}
	s.mu.Unlock()
	return nil
}

// dateText renders a time for messages.
func dateText(t time.Time) string { return t.Local().Format("02.01.2006 15:04") }

// pool is a pool of one root.
func pool(ca *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca)
	return p
}
