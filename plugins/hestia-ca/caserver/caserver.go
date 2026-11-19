// Package caserver is the CA service of HestiaCA (the binary ca-server in
// a container on the CA target): the root key lives only in its data
// directory (/data, 0600, uid 65532); the API is HTTPS with its own
// self-signed key (pinned by the plugin) and a Bearer token whose sha256
// comes in the environment.
package caserver

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
)

// Files in the data directory.
const (
	FileAPIKey  = "api.key"
	FileAPICert = "api.crt"
	FileCAKey   = "ca.key"
	FileCACert  = "ca.crt"
	FileIssued  = "issued.jsonl"
)

// Limits.
const (
	maxBody        = 64 << 10
	DefaultLeafMax = 2160 * time.Hour
	failDelay      = time.Second
	apiYears       = 10
)

// States of the CA.
const (
	StateUninitialized = "uninitialized"
	StateReady         = "ready"
)

// Server is the HTTP API of the CA.
type Server struct {
	Dir      string
	TokenSHA string // hex sha256 of the API token ("" refuses every call)
	LeafMax  time.Duration
	Version  string
	Now      func() time.Time
	// FailDelay is the pause before a 401 (tests shorten it).
	FailDelay time.Duration
	// BackupIter is the PBKDF2 iteration count of exports (default
	// pki.BackupIter; tests lower it).
	BackupIter int
	Log        *slog.Logger

	mu  sync.Mutex
	tmu sync.Mutex // TokenSHA (SetTokenSHA)
}

// SetTokenSHA replaces the sha256 of the API token while serving.
func (s *Server) SetTokenSHA(h string) {
	s.tmu.Lock()
	s.TokenSHA = h
	s.tmu.Unlock()
}

func (s *Server) tokenSHA() string {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return s.TokenSHA
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) path(name string) string { return filepath.Join(s.Dir, name) }

// EnsureDir creates the data directory 0700.
func (s *Server) EnsureDir() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(s.Dir, 0o700)
}

// APICert loads (or creates on the first start) the API key and its
// self-signed certificate; they are not related to the CA key.
func (s *Server) APICert() (tls.Certificate, error) {
	if err := s.EnsureDir(); err != nil {
		return tls.Certificate{}, err
	}
	certPEM, err1 := os.ReadFile(s.path(FileAPICert))
	keyPEM, err2 := os.ReadFile(s.path(FileAPIKey))
	if err1 == nil && err2 == nil {
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := s.now()
	tmpl := &x509.Certificate{
		SerialNumber: serial.Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "HestiaCA API"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(apiYears, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err = pki.EncodeKeyPEM(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := pki.WriteFileAtomic(s.path(FileAPIKey), keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := pki.WriteFileAtomic(s.path(FileAPICert), certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// SPKIPin is the hex sha256 of the SubjectPublicKeyInfo of a certificate.
func SPKIPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// APIPin reads the pin of the API certificate in dir.
func APIPin(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileAPICert))
	if err != nil {
		return "", err
	}
	c, err := pki.ParseCertPEM(b)
	if err != nil {
		return "", err
	}
	return SPKIPin(c), nil
}

// RootSHA256 is the fingerprint of the root in dir.
func RootSHA256(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileCACert))
	if err != nil {
		return "", err
	}
	c, err := pki.ParseCertPEM(b)
	if err != nil {
		return "", err
	}
	return pki.Fingerprint(c.Raw), nil
}

// HashToken is how the token is passed to the server (environment).
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// Handler is the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/init", s.auth(s.init))
	mux.HandleFunc("GET /v1/root", s.auth(s.root))
	mux.HandleFunc("POST /v1/issue", s.auth(s.issue))
	mux.HandleFunc("POST /v1/revoke", s.auth(s.revoke))
	mux.HandleFunc("GET /v1/issued", s.auth(s.issued))
	mux.HandleFunc("POST /v1/export", s.auth(s.export))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fail(w, http.StatusNotFound, "не найдено") })
	return mux
}

// Serve runs the API on ln with TLS until the server is closed.
func (s *Server) Serve(ln net.Listener) error {
	cert, err := s.APICert()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ErrorLog:  slog.NewLogLogger(s.log().Handler(), slog.LevelDebug),
	}
	return srv.ServeTLS(ln, "", "")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "неверный JSON запроса")
		return false
	}
	return true
}

// auth checks the Bearer token (sha256, constant time); a wrong one is
// answered after a pause and logged without its value.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		want, err := hex.DecodeString(s.tokenSHA())
		got := sha256.Sum256([]byte(tok))
		if !ok || err != nil || len(want) != sha256.Size || subtle.ConstantTimeCompare(got[:], want) != 1 {
			s.log().Warn("ca-server: неверный токен", "path", r.URL.Path, "remote", r.RemoteAddr)
			d := s.FailDelay
			if d == 0 {
				d = failDelay
			}
			time.Sleep(d)
			fail(w, http.StatusUnauthorized, "нужен токен API")
			return
		}
		next(w, r)
	}
}

// loadCA reads the root and its key (ErrNotExist before init).
func (s *Server) loadCA() (*x509.Certificate, []byte, crypto.Signer, error) {
	certPEM, err := os.ReadFile(s.path(FileCACert))
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := os.ReadFile(s.path(FileCAKey))
	if err != nil {
		return nil, nil, nil, err
	}
	root, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := pki.ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	if !pki.KeyMatches(root, key) {
		return nil, nil, nil, errors.New("ключ CA не подходит к корневому сертификату")
	}
	return root, certPEM, key, nil
}

func (s *Server) state() string {
	if _, err := os.Stat(s.path(FileCAKey)); err == nil {
		return StateReady
	}
	return StateUninitialized
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := map[string]any{"version": s.Version, "state": s.state()}
	if fp, err := RootSHA256(s.Dir); err == nil {
		h["root_sha256"] = fp
	}
	writeJSON(w, http.StatusOK, h)
}

// InitRequest is POST /v1/init.
type InitRequest struct {
	Mode       string `json:"mode"` // generate | import
	OU         string `json:"ou,omitempty"`
	Zones      string `json:"zones,omitempty"`
	IPRanges   string `json:"ip_ranges,omitempty"`
	RootYears  int    `json:"root_years,omitempty"`
	Backup     string `json:"backup,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

func (s *Server) init(w http.ResponseWriter, r *http.Request) {
	var req InitRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state() != StateUninitialized {
		fail(w, http.StatusConflict, "CA уже создан")
		return
	}
	var (
		certPEM []byte
		key     crypto.Signer
	)
	switch req.Mode {
	case "generate":
		zones, _, err := pki.ParseZones(req.Zones)
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		ranges, err := pki.ParseIPRanges(req.IPRanges)
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		years := req.RootYears
		if years == 0 {
			years = 10
		}
		c, k, err := pki.NewRoot(req.OU, pki.Constraints{Zones: zones, IPRanges: ranges}, years, s.now())
		if err != nil {
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		certPEM, key = c, k
	case "import":
		c, k, err := pki.ImportBackup([]byte(req.Backup), req.Passphrase)
		if err != nil {
			s.log().Warn("ca-server: восстановление из резервной копии не удалось")
			fail(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		certPEM, key = c, k
	default:
		fail(w, http.StatusBadRequest, "mode: generate или import")
		return
	}
	keyPEM, err := pki.EncodeKeyPEM(key)
	if err != nil {
		fail(w, http.StatusInternalServerError, "ключ CA не сохранён")
		return
	}
	// The certificate first: a key without it is never left behind as "ready".
	if err := pki.WriteFileAtomic(s.path(FileCACert), certPEM, 0o600); err != nil {
		fail(w, http.StatusInternalServerError, "корень не сохранён")
		return
	}
	if err := pki.WriteFileAtomic(s.path(FileCAKey), keyPEM, 0o600); err != nil {
		_ = os.Remove(s.path(FileCACert))
		fail(w, http.StatusInternalServerError, "ключ CA не сохранён")
		return
	}
	root, _ := pki.ParseCertPEM(certPEM)
	fp := pki.Fingerprint(root.Raw)
	s.log().Info("ca-server: корень создан", "mode", req.Mode, "sha256", fp)
	writeJSON(w, http.StatusOK, map[string]any{"root_pem": string(certPEM), "root_sha256": fp})
}

// RootInfo is GET /v1/root.
type RootInfo struct {
	RootPEM    string    `json:"root_pem"`
	RootSHA256 string    `json:"root_sha256"`
	NotAfter   time.Time `json:"not_after"`
	Zones      []string  `json:"zones"`
	IPRanges   []string  `json:"ip_ranges"`
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	root, certPEM, _, err := s.loadCA()
	if err != nil {
		fail(w, http.StatusConflict, "CA ещё не создан")
		return
	}
	c := pki.ConstraintsOf(root)
	in := RootInfo{RootPEM: string(certPEM), RootSHA256: pki.Fingerprint(root.Raw), NotAfter: root.NotAfter.UTC(),
		Zones: slices.Clone(c.Zones), IPRanges: []string{}}
	for _, n := range c.IPRanges {
		in.IPRanges = append(in.IPRanges, n.String())
	}
	if in.Zones == nil {
		in.Zones = []string{}
	}
	writeJSON(w, http.StatusOK, in)
}

// IssueRequest is POST /v1/issue.
type IssueRequest struct {
	CSRPEM    string   `json:"csr_pem"`
	DNS       []string `json:"dns"`
	IPs       []string `json:"ips"`
	LifetimeS int64    `json:"lifetime_s"`
	Ref       string   `json:"ref"`
}

// IssueResult is the answer of /v1/issue.
type IssueResult struct {
	CertPEM   string    `json:"cert_pem"`
	RootPEM   string    `json:"root_pem"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// Record is a line of the journal of issued certificates.
type Record struct {
	Serial    string     `json:"serial"`
	DNS       []string   `json:"dns"`
	IPs       []string   `json:"ips"`
	NotAfter  time.Time  `json:"not_after"`
	Ref       string     `json:"ref"`
	IssuedAt  time.Time  `json:"issued_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request) {
	var req IssueRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	root, certPEM, key, err := s.loadCA()
	if err != nil {
		fail(w, http.StatusConflict, "CA ещё не создан")
		return
	}
	max := s.LeafMax
	if max <= 0 {
		max = DefaultLeafMax
	}
	life := time.Duration(req.LifetimeS) * time.Second
	switch {
	case req.LifetimeS < 0:
		fail(w, http.StatusUnprocessableEntity, "lifetime_s не может быть отрицательным")
		return
	case req.LifetimeS == 0:
		life = max
	case life > max:
		fail(w, http.StatusUnprocessableEntity, fmt.Sprintf("срок больше разрешённого (%s)", max))
		return
	}
	if len(req.Ref) > 100 {
		fail(w, http.StatusBadRequest, "ref длиннее 100 символов")
		return
	}
	is, err := pki.Issue(root, key, []byte(req.CSRPEM), req.DNS, req.IPs, life, s.now())
	var ne *pki.NamesErr
	if errors.As(err, &ne) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": ne.Error(), "names": ne.Names})
		return
	}
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rec := Record{Serial: is.Serial, DNS: nonNil(req.DNS), IPs: nonNil(req.IPs), NotAfter: is.NotAfter.UTC(), Ref: req.Ref, IssuedAt: s.now().UTC()}
	if err := s.appendRecord(rec); err != nil {
		fail(w, http.StatusInternalServerError, "журнал выпусков не записан")
		return
	}
	s.log().Info("ca-server: выпущен сертификат", "serial", is.Serial, "ref", req.Ref, "names", strings.Join(append(nonNil(req.DNS), req.IPs...), ","))
	writeJSON(w, http.StatusOK, IssueResult{CertPEM: string(is.CertPEM), RootPEM: string(certPEM), Serial: is.Serial,
		NotBefore: is.NotBefore.UTC(), NotAfter: is.NotAfter.UTC()})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) appendRecord(rec Record) error {
	f, err := os.OpenFile(s.path(FileIssued), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(rec)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// records reads the journal; a revocation line marks an earlier record.
func (s *Server) records() ([]Record, error) {
	f, err := os.Open(s.path(FileIssued))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	idx := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var rec Record
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Serial == "" {
			continue
		}
		if i, ok := idx[rec.Serial]; ok {
			if rec.RevokedAt != nil {
				out[i].RevokedAt, out[i].Reason = rec.RevokedAt, rec.Reason
			}
			continue
		}
		idx[rec.Serial] = len(out)
		out = append(out, rec)
	}
	return out, sc.Err()
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Serial string `json:"serial"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.records()
	if err != nil {
		fail(w, http.StatusInternalServerError, "журнал выпусков не читается")
		return
	}
	serial := strings.ToLower(strings.TrimLeft(req.Serial, "0"))
	i := slices.IndexFunc(list, func(rec Record) bool { return strings.TrimLeft(rec.Serial, "0") == serial })
	if i < 0 {
		fail(w, http.StatusNotFound, "сертификат с таким серийным не выпускался")
		return
	}
	if list[i].RevokedAt == nil {
		now := s.now().UTC()
		if len(req.Reason) > 200 {
			req.Reason = req.Reason[:200]
		}
		if err := s.appendRecord(Record{Serial: list[i].Serial, RevokedAt: &now, Reason: req.Reason}); err != nil {
			fail(w, http.StatusInternalServerError, "журнал выпусков не записан")
			return
		}
		s.log().Info("ca-server: сертификат отозван", "serial", list[i].Serial)
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) issued(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	list, err := s.records()
	s.mu.Unlock()
	if err != nil {
		fail(w, http.StatusInternalServerError, "журнал выпусков не читается")
		return
	}
	active := r.URL.Query().Get("active") == "1"
	ref := r.URL.Query().Get("ref")
	now := s.now()
	out := []Record{}
	for _, rec := range list {
		if active && (rec.RevokedAt != nil || !now.Before(rec.NotAfter)) {
			continue
		}
		if ref != "" && rec.Ref != ref {
			continue
		}
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, certPEM, key, err := s.loadCA()
	if err != nil {
		fail(w, http.StatusConflict, "CA ещё не создан")
		return
	}
	if len([]rune(req.Passphrase)) < pki.MinPassphrase {
		fail(w, http.StatusUnprocessableEntity, "пароль файла — не короче "+strconv.Itoa(pki.MinPassphrase)+" символов")
		return
	}
	iter := s.BackupIter
	if iter <= 0 {
		iter = pki.BackupIter
	}
	b, err := pki.ExportBackup(certPEM, key, req.Passphrase, iter, s.now())
	if err != nil {
		fail(w, http.StatusInternalServerError, "резервная копия не создана")
		return
	}
	s.log().Info("ca-server: выдана резервная копия ключа CA")
	writeJSON(w, http.StatusOK, map[string]any{"backup": string(b)})
}

// HealthCheck asks the local API (compose healthcheck): the certificate
// must be the one in dir.
func HealthCheck(addr, dir string, timeout time.Duration) error {
	pin, err := APIPin(dir)
	if err != nil {
		return err
	}
	cl := Client(addr, pin, "", timeout)
	var h map[string]any
	return cl.Do("GET", "/v1/health", nil, &h)
}

// Client talks to the API of a CA with a pinned API key.
type APIClient struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// Client returns an API client for addr ("host:port") that accepts only the
// certificate whose SPKI sha256 is pin (the name is not checked).
func Client(addr, pin, token string, timeout time.Duration) *APIClient {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: PinnedTLS(pin)}
	return &APIClient{Base: "https://" + addr, Token: token, HTTP: &http.Client{Transport: tr, Timeout: timeout}}
}

// PinnedTLS verifies only the pin of the leaf.
func PinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("нет сертификата")
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if subtle.ConstantTimeCompare([]byte(SPKIPin(c)), []byte(strings.ToLower(pin))) != 1 {
				return ErrPin
			}
			return nil
		},
	}
}

// ErrPin: the CA answered with another API key.
var ErrPin = errors.New("ключ API CA изменился (пин не совпал)")

// APIError is an error answer of the CA.
type APIError struct {
	Code  int
	Msg   string
	Names []pki.NameError
}

func (e *APIError) Error() string { return e.Msg }

// Do calls the API; out receives the JSON answer.
func (c *APIClient) Do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, c.Base+path, body)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, ErrPin) || strings.Contains(err.Error(), ErrPin.Error()) {
			return ErrPin
		}
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string          `json:"error"`
			Names []pki.NameError `json:"names"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("ответ CA %d", resp.StatusCode)
		}
		return &APIError{Code: resp.StatusCode, Msg: e.Error, Names: e.Names}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
