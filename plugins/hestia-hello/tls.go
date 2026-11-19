package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// The "tls" port: hello asks for a certificate by CSR (its key is born in
// the plugin's StateDirectory and goes only into the project files on the
// target) and runs a second whoami on HTTPS.

const portTLS = "tls"

// Project files of the HTTPS service.
const (
	fileTLSCert = "tls-cert.pem"
	fileTLSKey  = "tls-key.pem"
)

var _ sdk.Preparer = (*hello)(nil)

// tlsRecord is the applied certificate of a link (tls-<link>.json).
type tlsRecord struct {
	Instance int64  `json:"instance"`
	Link     int64  `json:"link"`
	CertPEM  string `json:"cert_pem"`
	CAPEM    string `json:"ca_pem"`
}

func (h *hello) stateFile(name string) string { return filepath.Join(h.StateDir, name) }

func keyFile(link int64) string     { return fmt.Sprintf("tls-%d.key", link) }
func pendingFile(link int64) string { return fmt.Sprintf("tls-%d.key.pending", link) }
func recordFile(link int64) string  { return fmt.Sprintf("tls-%d.json", link) }

func tlsPort(cfg sdk.Config) int64 {
	if p := cfg.Int("tls_port"); p > 0 {
		return p
	}
	return 8443
}

// writeState writes a file of the StateDirectory 0600 atomically.
func (h *hello) writeState(name string, data []byte) error {
	if h.StateDir == "" {
		return errors.New("нет каталога состояния плагина ($STATE_DIRECTORY)")
	}
	if err := os.MkdirAll(h.StateDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(h.StateDir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), h.stateFile(name))
}

// activeTLS is the applied certificate of an instance (nil if none).
func (h *hello) activeTLS(inst int64) (*tlsRecord, []byte) {
	if h.StateDir == "" {
		return nil, nil
	}
	list, _ := filepath.Glob(h.stateFile("tls-*.json"))
	for _, f := range list {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var rec tlsRecord
		if json.Unmarshal(b, &rec) != nil || rec.Instance != inst {
			continue
		}
		key, err := os.ReadFile(h.stateFile(keyFile(rec.Link)))
		if err != nil {
			continue
		}
		return &rec, key
	}
	return nil, nil
}

// deployRequest is the deploy of the instance, with the HTTPS service when
// a certificate is applied.
func (h *hello) deployRequest(inst int64, tgt string, cfg sdk.Config, jobID string) sdk.DeployRequest {
	req := sdk.DeployRequest{JobID: jobID, Instance: inst, Target: tgt, Project: project, Compose: compose(port(cfg), cfg.String("message"))}
	if rec, key := h.activeTLS(inst); rec != nil {
		req.Compose = compose(port(cfg), cfg.String("message"), tlsPort(cfg))
		req.Files = []sdk.DeployFile{{Name: fileTLSCert, Data: []byte(rec.CertPEM)}, {Name: fileTLSKey, Data: key}}
	}
	return req
}

// tlsNames are the names hello asks for: the IP of its target and tls_name.
func (h *hello) tlsNames(ctx context.Context, host *sdk.Host, inst sdk.Instance) (types.TLSRequest, error) {
	t, err := target(ctx, host, inst.ID, inst.Config.String("target"))
	if err != nil {
		return types.TLSRequest{}, err
	}
	ip := net.ParseIP(t.Address)
	if ip == nil {
		return types.TLSRequest{}, fmt.Errorf("у цели %s нет IP-адреса для сертификата", t.Name)
	}
	r := types.TLSRequest{IPs: []string{ip.String()}}
	if n := inst.Config.String("tls_name"); n != "" {
		r.DNS = []string{n}
	}
	return r, nil
}

func (h *hello) tlsPlan(ctx context.Context, host *sdk.Host, req sdk.LinkRequest) (sdk.Plan, error) {
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	p := tlsPort(req.Instance.Config)
	if req.Action == sdk.ActionRemove {
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Остановить HTTPS-whoami на :%d, удалить ключ", p), Risk: sdk.RiskChange})
		return pl, nil
	}
	r, err := h.tlsNames(ctx, host, req.Instance)
	if err != nil {
		return pl, err
	}
	pl.Request, _ = json.Marshal(r)
	pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Поднять HTTPS-whoami на :%d", p),
		Detail: "Ключ создаётся плагином и кладётся только в файлы проекта на цели (0640, root)", Risk: sdk.RiskChange})
	return pl, nil
}

func (h *hello) LinkPrepare(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	if req.Port != portTLS || req.Role != sdk.RoleConsumer {
		return nil, fmt.Errorf("порт %s не запрашивает сертификаты", req.Port)
	}
	r, err := h.tlsNames(ctx, sdk.HostFrom(ctx), req.Instance)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := h.writeState(pendingFile(req.Link), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: r.Names()[0]}, DNSNames: r.DNS}
	for _, ip := range r.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	r.CSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	return json.Marshal(r)
}

// tlsApply deploys the HTTPS service with the new certificate and the
// pending key; only then the key replaces the previous one.
func (h *hello) tlsApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	var b types.TLSCert
	if err := json.Unmarshal(req.Binding, &b); err != nil {
		return fmt.Errorf("данные связи: %w", err)
	}
	key, err := os.ReadFile(h.stateFile(pendingFile(req.Link)))
	if err != nil {
		return errors.New("нет ключа из link.prepare")
	}
	if _, err := tls.X509KeyPair([]byte(b.CertPEM), key); err != nil {
		return fmt.Errorf("сертификат не подходит к ключу: %w", err)
	}
	cfg := req.Instance.Config
	dreq := sdk.DeployRequest{JobID: req.JobID, Instance: req.Instance.ID, Target: cfg.String("target"), Project: project,
		Compose: compose(port(cfg), cfg.String("message"), tlsPort(cfg)),
		Files:   []sdk.DeployFile{{Name: fileTLSCert, Data: []byte(b.CertPEM)}, {Name: fileTLSKey, Data: key}}}
	if _, err := job.Host().DeployUp(ctx, dreq); err != nil {
		return err
	}
	rec, _ := json.Marshal(tlsRecord{Instance: req.Instance.ID, Link: req.Link, CertPEM: b.CertPEM, CAPEM: b.CAPEM})
	if err := h.writeState(keyFile(req.Link), key); err != nil {
		return err
	}
	if err := h.writeState(recordFile(req.Link), rec); err != nil {
		return err
	}
	_ = os.Remove(h.stateFile(pendingFile(req.Link)))
	job.Logf("HTTPS-whoami на :%d, сертификат %s", tlsPort(cfg), b.Serial)
	return nil
}

// tlsRemove stops the HTTPS service (when this link's certificate is in
// use) and removes the keys of the link.
func (h *hello) tlsRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	_ = os.Remove(h.stateFile(pendingFile(req.Link)))
	if _, err := os.Stat(h.stateFile(recordFile(req.Link))); err != nil {
		return nil // never applied (a rollback)
	}
	cfg := req.Instance.Config
	if _, err := job.Host().DeployUp(ctx, sdk.DeployRequest{JobID: req.JobID, Instance: req.Instance.ID, Target: cfg.String("target"),
		Project: project, Compose: compose(port(cfg), cfg.String("message"))}); err != nil {
		return err
	}
	_ = os.Remove(h.stateFile(keyFile(req.Link)))
	_ = os.Remove(h.stateFile(recordFile(req.Link)))
	job.Log("info", "HTTPS-whoami остановлен, ключ удалён")
	return nil
}

// tlsStatus checks HTTPS-whoami trusting only the root of the link.
func (h *hello) tlsStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	var b types.TLSCert
	if err := json.Unmarshal(req.Binding, &b); err != nil || b.CAPEM == "" {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "нет данных связи"}, nil
	}
	t, err := target(ctx, sdk.HostFrom(ctx), req.Instance.ID, req.Instance.Config.String("target"))
	if err != nil || t.Address == "" {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "у цели нет адреса"}, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(b.CAPEM)) {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "корень не разбирается"}, nil
	}
	cl := &http.Client{Timeout: statusTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	if h.HTTP != nil && h.HTTP.Transport != nil {
		cl.Transport = h.HTTP.Transport
	}
	u := "https://" + net.JoinHostPort(t.Address, strconv.FormatInt(tlsPort(req.Instance.Config), 10)) + "/"
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := cl.Do(r)
	if err != nil {
		return sdk.LinkStatus{State: sdk.StateDown, Detail: "HTTPS-whoami не отвечает: " + err.Error()}, nil
	}
	resp.Body.Close()
	if !time.Now().Before(b.NotAfter) {
		return sdk.LinkStatus{State: sdk.StateDown, Detail: "сертификат истёк"}, nil
	}
	return sdk.LinkStatus{State: sdk.StateOK, Detail: "HTTPS: " + u}, nil
}
