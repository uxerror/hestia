// Package adguard is a small client of the AdGuard Home HTTP API (v0.107):
// the status and the DNS rewrites. HTTPS is only used with a pinned
// certificate fingerprint; the administrator password goes in an HTTP Basic
// header and never into an error, a URL or a log line.
package adguard

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hestia/internal/proxmox"
)

// RequestTimeout bounds one request to AdGuard.
const RequestTimeout = 5 * time.Second

// Errors a caller tells apart.
var (
	// ErrAuth: AdGuard rejected the login or password.
	ErrAuth = errors.New("AdGuard отклонил логин или пароль")
	// ErrNoPin: HTTPS without a pinned certificate fingerprint is refused.
	ErrNoPin = errors.New("для HTTPS нужен отпечаток сертификата AdGuard")
	// ErrNotAdGuard: the endpoint does not answer like AdGuard Home.
	ErrNotAdGuard = errors.New("по этому адресу отвечает не AdGuard Home")
)

// CertChangedError means the certificate presented is not the pinned one.
// No request (and no password) was sent.
type CertChangedError struct {
	// Fingerprint is the fingerprint the server presented now.
	Fingerprint string
}

func (e *CertChangedError) Error() string {
	return "Сертификат AdGuard изменился (новый отпечаток " + e.Fingerprint + ")"
}

// UnreachableError is a transport failure with the URL stripped.
type UnreachableError struct{ Err error }

func (e *UnreachableError) Error() string { return "AdGuard недоступен: " + e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// NormalizeFP turns an SHA-256 fingerprint in any common notation (colons,
// spaces, any case) into upper-case colon hex, or "" if it is not one.
func NormalizeFP(s string) string {
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))
	if len(s) != 64 {
		return ""
	}
	var out []string
	for i := 0; i < 64; i += 2 {
		for _, c := range s[i : i+2] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return ""
			}
		}
		out = append(out, strings.ToUpper(s[i:i+2]))
	}
	return strings.Join(out, ":")
}

// ParseBase validates the address of AdGuard and returns it normalized
// (scheme://host[:port], no userinfo, path, query or fragment).
func ParseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("укажите адрес AdGuard вида http://192.168.1.2:3000 или https://192.168.1.2")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("адрес AdGuard должен начинаться с http:// или https://")
	}
	if u.User != nil {
		return nil, errors.New("логин и пароль вводятся отдельно, не в адресе")
	}
	if p := u.Port(); p != "" {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 65535 {
			return nil, errors.New("порт должен быть от 1 до 65535")
		}
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("укажите только адрес и порт, без пути")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// newTransport builds a transport that does not follow the environment proxy
// and, for HTTPS, accepts exactly the certificate with the given fingerprint.
func newTransport(pin string) *http.Transport {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: RequestTimeout}
	tr.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // chain and name are not checked: the pinned fingerprint is (below)
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("сервер не предъявил сертификат")
			}
			fp := proxmox.CertFingerprint(raw[0])
			if pin != "" && fp != pin {
				return &CertChangedError{Fingerprint: fp}
			}
			return nil
		},
	}
	return tr
}

// Client talks to one AdGuard Home.
type Client struct {
	base     *url.URL
	user     string
	password string
	http     *http.Client
}

// Config configures a Client. PinSHA256 is required for https.
type Config struct {
	BaseURL   string
	Username  string
	Password  string
	PinSHA256 string
}

// NewClient validates the config. For https a valid pin is mandatory.
func NewClient(cfg Config) (*Client, error) {
	base, err := ParseBase(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	pin := ""
	if base.Scheme == "https" {
		if pin = NormalizeFP(cfg.PinSHA256); pin == "" {
			return nil, ErrNoPin
		}
	}
	return &Client{
		base: base, user: cfg.Username, password: cfg.Password,
		http: &http.Client{
			Transport: newTransport(pin),
			Timeout:   RequestTimeout,
			// A redirect is an answer, not something to follow with a password.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// BaseURL returns the normalized address.
func (c *Client) BaseURL() string { return c.base.String() }

// Host returns the host name or address of AdGuard (no port).
func (c *Client) Host() string { return c.base.Hostname() }

// wrap turns a transport error into one that carries neither the URL nor the
// credentials.
func (c *Client) wrap(err error) error {
	var ce *CertChangedError
	if errors.As(err, &ce) {
		return ce
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		err = errors.New("нет ответа за " + RequestTimeout.String())
	}
	msg := err.Error()
	if c.password != "" {
		msg = strings.ReplaceAll(msg, c.password, "***")
	}
	return &UnreachableError{Err: errors.New(msg)}
}

// do sends one authorized request and decodes a JSON answer into out (if not nil).
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+"/control"+path, body)
	if err != nil {
		return c.wrap(err)
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return c.wrap(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrAuth
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotAdGuard
	case resp.StatusCode >= 300:
		return fmt.Errorf("AdGuard ответил %d: %s", resp.StatusCode, c.mask(snippet(data)))
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return ErrNotAdGuard
	}
	return nil
}

func (c *Client) mask(s string) string {
	if c.password != "" {
		s = strings.ReplaceAll(s, c.password, "***")
	}
	return s
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// Status is the part of GET /control/status Hestia uses.
type Status struct {
	Version      string   `json:"version"`
	Running      bool     `json:"running"`
	DNSPort      int      `json:"dns_port"`
	DNSAddresses []string `json:"dns_addresses"`
}

// Status checks the login and returns the state of the server.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	if err := c.do(ctx, http.MethodGet, "/status", nil, &st); err != nil {
		return st, err
	}
	if st.Version == "" && st.DNSPort == 0 {
		return st, ErrNotAdGuard
	}
	return st, nil
}

// RewritesEnabled reports whether AdGuard applies DNS rewrites at all.
func (c *Client) RewritesEnabled(ctx context.Context) (bool, error) {
	var s struct {
		Enabled bool `json:"enabled"`
	}
	err := c.do(ctx, http.MethodGet, "/rewrite/settings", nil, &s)
	return s.Enabled, err
}

// Rewrite is one DNS rewrite.
type Rewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// RewriteList returns all rewrites (GET only).
func (c *Client) RewriteList(ctx context.Context) ([]Rewrite, error) {
	var l []Rewrite
	if err := c.do(ctx, http.MethodGet, "/rewrite/list", nil, &l); err != nil {
		return nil, err
	}
	return l, nil
}

// RewriteAdd adds domain → answer (enabled).
func (c *Client) RewriteAdd(ctx context.Context, domain, answer string) error {
	return c.do(ctx, http.MethodPost, "/rewrite/add", map[string]any{"domain": domain, "answer": answer, "enabled": true}, nil)
}

// RewriteDelete deletes exactly domain → answer.
func (c *Client) RewriteDelete(ctx context.Context, domain, answer string) error {
	return c.do(ctx, http.MethodPost, "/rewrite/delete", map[string]any{"domain": domain, "answer": answer}, nil)
}

// RewriteUpdate replaces target (domain, answer) with domain → answer.
func (c *Client) RewriteUpdate(ctx context.Context, domain, oldAnswer, newAnswer string) error {
	return c.do(ctx, http.MethodPut, "/rewrite/update", map[string]any{
		"target": map[string]any{"domain": domain, "answer": oldAnswer},
		"update": map[string]any{"domain": domain, "answer": newAnswer, "enabled": true},
	}, nil)
}

// LocalIP returns the address the controller reaches AdGuard from: the local
// address of a TCP connection to the endpoint.
func LocalIP(ctx context.Context, baseURL string) (string, error) {
	u, err := ParseBase(baseURL)
	if err != nil {
		return "", err
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return "", &UnreachableError{Err: errors.New("не удалось подключиться к " + net.JoinHostPort(u.Hostname(), port))}
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return "", errors.New("не удалось определить свой адрес")
	}
	return addr.IP.String(), nil
}

// CertInfo describes the certificate shown to the user before it is trusted.
type CertInfo struct {
	SHA256   string    `json:"sha256"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	SAN      []string  `json:"san"`
	NotAfter time.Time `json:"not_after"`
}

// ProbeResult is the answer of Probe.
type ProbeResult struct {
	URL        string    `json:"url"`
	TLS        *CertInfo `json:"tls"`
	StatusCode int       `json:"status_code"`
	Location   string    `json:"location"`
	Warning    string    `json:"warning"`
}

// Probe looks at an endpoint without a password: the certificate (HTTPS) and
// the answer of GET /control/status (401 is what AdGuard with a password
// gives). Nothing is changed and no credentials are sent; the certificate is
// not verified, it is only shown.
func Probe(ctx context.Context, raw string) (*ProbeResult, error) {
	base, err := ParseBase(raw)
	if err != nil {
		return nil, err
	}
	res := &ProbeResult{URL: base.String()}
	tr := newTransport("")
	var leaf *x509.Certificate
	tr.TLSClientConfig.VerifyPeerCertificate = nil
	tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) > 0 {
			leaf = cs.PeerCertificates[0]
		}
		return nil
	}
	cl := &http.Client{Transport: tr, Timeout: RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/control/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		u := &UnreachableError{Err: errors.New("нет ответа")}
		var ue *url.Error
		if errors.As(err, &ue) {
			u.Err = ue.Err
		}
		if errors.Is(err, context.DeadlineExceeded) {
			u.Err = errors.New("нет ответа за " + RequestTimeout.String())
		}
		return nil, u
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	res.StatusCode = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	if leaf != nil {
		res.TLS = &CertInfo{
			SHA256: proxmox.CertFingerprint(leaf.Raw), Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
			SAN: sans(leaf), NotAfter: leaf.NotAfter.UTC(),
		}
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		res.Warning = "AdGuard отвечает без пароля: вход не защищён"
	case resp.StatusCode == http.StatusUnauthorized:
	default:
		res.Warning = fmt.Sprintf("по этому адресу отвечает не AdGuard Home (ответ %d)", resp.StatusCode)
	}
	if base.Scheme == "http" {
		w := "Пароль пойдёт по сети открытым текстом"
		if res.Warning != "" {
			w = res.Warning + ". " + w
		}
		res.Warning = w
	}
	return res, nil
}

func sans(c *x509.Certificate) []string {
	out := []string{}
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
