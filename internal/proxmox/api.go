package proxmox

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// APIPort is the default Proxmox API port.
const APIPort = 8006

// ErrCertChanged means the API certificate no longer matches the pinned fingerprint.
var ErrCertChanged = errors.New("отпечаток TLS-сертификата Proxmox API изменился: подключение отклонено")

// CertFingerprint formats a certificate's SHA-256 as upper-case colon hex,
// the way the Proxmox UI shows it.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// FetchCertFP connects over TLS (no verification: this is trust on first use)
// and returns the fingerprint of the presented leaf certificate.
func FetchCertFP(ctx context.Context, host string, port int) (string, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // TOFU, fingerprint is shown to the user
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", fmt.Errorf("API Proxmox на порту %d недоступен: %w", port, err)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("сервер не предъявил TLS-сертификат")
	}
	return CertFingerprint(certs[0].Raw), nil
}

// Client calls the Proxmox API with an API token.
type Client struct {
	base    string
	auth    string
	http    *http.Client
	tokenID string
}

// ClientConfig configures a Client. PinFP must be set.
type ClientConfig struct {
	Host    string
	Port    int
	TokenID string
	Secret  string
	PinFP   string
}

// NewClient builds a client that only accepts the pinned certificate.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Port == 0 {
		cfg.Port = APIPort
	}
	pin := cfg.PinFP
	tr := &http.Transport{
		Proxy: nil, // never route controller → Proxmox through a proxy from the environment
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 || CertFingerprint(raw[0]) != pin {
					return ErrCertChanged
				}
				return nil
			},
		},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
	}
	return &Client{
		base:    "https://" + net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)) + "/api2/json",
		auth:    "PVEAPIToken=" + cfg.TokenID + "=" + cfg.Secret,
		http:    &http.Client{Transport: tr, Timeout: 20 * time.Second},
		tokenID: cfg.TokenID,
	}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrCertChanged) {
			return ErrCertChanged
		}
		return fmt.Errorf("запрос к API Proxmox: %w", sanitizeURLErr(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return &APIError{Status: resp.StatusCode, Detail: errorDetail(body)}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("разбор ответа API Proxmox: %w", err)
	}
	return json.Unmarshal(env.Data, out)
}

// APIError is a non-200 answer of the API. Detail is the server's message
// (it never contains the token).
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string {
	switch {
	case e.Status == http.StatusUnauthorized:
		return fmt.Sprintf("API Proxmox отклонил токен (%d)", e.Status)
	case e.Status == http.StatusForbidden:
		if e.Detail != "" {
			return fmt.Sprintf("API Proxmox отклонил токен (%d): %s", e.Status, e.Detail)
		}
		return fmt.Sprintf("API Proxmox отклонил токен (%d)", e.Status)
	case e.Detail != "":
		return fmt.Sprintf("API Proxmox вернул %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("API Proxmox вернул %d", e.Status)
}

// errorDetail extracts the "message" of a Proxmox error body ({"data":null,
// "message":"..."}) as one short line.
func errorDetail(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	msg := strings.Join(strings.Fields(m.Message), " ")
	if r := []rune(msg); len(r) > 200 {
		msg = string(r[:200]) + "…"
	}
	return msg
}

// sanitizeURLErr drops the URL from *url.Error (it carries no secrets, but
// keeps messages short).
func sanitizeURLErr(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) && ue.Unwrap() != nil {
		return ue.Unwrap()
	}
	return err
}

// Version returns the Proxmox version (GET /version).
func (c *Client) Version(ctx context.Context) (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	if err := c.get(ctx, "/version", &v); err != nil {
		return "", err
	}
	return v.Version, nil
}

// APINode is an entry of GET /nodes.
type APINode struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

// Nodes lists cluster nodes (GET /nodes).
func (c *Client) Nodes(ctx context.Context) ([]APINode, error) {
	var n []APINode
	if err := c.get(ctx, "/nodes", &n); err != nil {
		return nil, err
	}
	return n, nil
}
