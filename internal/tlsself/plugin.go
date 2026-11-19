package tlsself

import (
	"bytes"
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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// PortTLS is the requires port of the instance "Hestia".
const PortTLS = "tls"

// Manifest is the manifest of the built-in pseudo plugin "hestia".
func Manifest(version string) []byte {
	multi := false
	m := sdk.Manifest{
		Protocol: sdk.Protocol, ID: "hestia", Name: "Hestia", Version: version,
		Description: "Контроллер Hestia (встроенный компонент)", Permissions: []string{}, Provides: []sdk.Port{},
		Requires: []sdk.Port{{Name: PortTLS, Type: types.TLSCertType, Label: "Сертификат HTTPS", Optional: true, Multi: &multi}},
		Schema:   sdk.Schema{Fields: []sdk.Field{}},
	}
	b, _ := json.Marshal(m)
	return b
}

// Plugin is the sdk side of the built-in consumer.
func (s *Service) Plugin() sdk.Plugin { return plugin{s} }

type plugin struct{ s *Service }

var (
	_ sdk.Linker   = plugin{}
	_ sdk.Preparer = plugin{}
)

var errNotConfigurable = errors.New("встроенный компонент Hestia не настраивается")

func (plugin) Validate(context.Context, sdk.Config) []sdk.FieldError { return nil }

func (plugin) Plan(context.Context, sdk.PlanRequest) (sdk.Plan, error) {
	return sdk.Plan{}, errNotConfigurable
}

func (plugin) Apply(context.Context, sdk.ApplyRequest, *sdk.Job) error { return errNotConfigurable }

func (p plugin) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	in := p.s.Info()
	st := sdk.Status{State: sdk.StateOK, Endpoints: []sdk.Endpoint{}, ActionsEnabled: []string{}}
	switch {
	case in.Mode != ModeOn:
		st.Detail = "HTTPS выключен"
	case in.Listener != "up" || in.NotAfter == nil:
		st.State, st.Detail = sdk.StateDegraded, msgNotLoaded
	case in.Expired:
		st.State, st.Detail = sdk.StateDegraded, "Сертификат HTTPS истёк "+dateText(*in.NotAfter)
	default:
		st.Detail = "HTTPS включён, сертификат до " + dateText(*in.NotAfter)
	}
	return st, nil
}

// names are the names to ask for, without the DNS names outside the zones
// of the provider (it would refuse them).
func (s *Service) names(ctx context.Context, peer *sdk.LinkPeer) ([]string, []string) {
	var dns, ips []string
	if s.Names != nil {
		dns, ips = s.Names(ctx)
	}
	if peer != nil && s.PeerZones != nil {
		if zones := s.PeerZones(ctx, peer.Instance); len(zones) > 0 {
			dns = slices.DeleteFunc(slices.Clone(dns), func(n string) bool {
				return !slices.ContainsFunc(zones, func(z string) bool { return n == z || strings.HasSuffix(n, "."+z) })
			})
		}
	}
	sort.Strings(dns)
	sort.Strings(ips)
	return dns, ips
}

func (p plugin) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	s := p.s
	if req.Port != PortTLS || req.Role != sdk.RoleConsumer {
		return sdk.Plan{}, fmt.Errorf("порт %s не поддерживается", req.Port)
	}
	if req.Action == sdk.ActionRemove {
		return sdk.Plan{Actions: []sdk.Action{{
			Title:  "Hestia вернётся на HTTP: перенаправление http → https выключится, порт HTTPS закроется",
			Detail: "Файлы сертификата переносятся в " + DirName + ".removed-<время> (для разбора). Desktop-приложение вернётся на HTTP само.",
			Risk:   sdk.RiskDanger,
		}}, Warnings: []string{}}, nil
	}
	if s.Addr == "" {
		return sdk.Plan{}, errors.New(msgDisabledFlag)
	}
	dns, ips := s.names(ctx, req.Peer)
	if len(dns)+len(ips) == 0 {
		return sdk.Plan{}, errors.New("у Hestia нет ни проверенного имени, ни IP-адреса для сертификата")
	}
	preview, _ := json.Marshal(types.TLSRequest{DNS: dns, IPs: ips})
	names := strings.Join(append(slices.Clone(dns), ips...), ", ")
	port := s.configuredPort()
	pl := sdk.Plan{Request: preview, Warnings: []string{}}
	pl.Actions = append(pl.Actions, sdk.Action{
		Title:  "Hestia: создать ключ на контроллере и запросить сертификат на " + names,
		Detail: "Закрытый ключ создаётся в " + filepath.Join(s.DataDir, DirName) + " и не покидает контроллер (выпуск по CSR)",
		Risk:   sdk.RiskInfo,
	})
	if req.Reason == sdk.ReasonReissue || req.Action == sdk.ActionUpdate {
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Hestia: заменить сертификат HTTPS без перезапуска", Risk: sdk.RiskChange})
		if s.Info().Mode != ModeOn {
			pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Hestia: снова открыть порт %d, перенаправлять http → https", port), Risk: sdk.RiskChange})
		}
	} else {
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Hestia: открыть порт %d, перенаправлять http → https", port),
			Detail: "GET /api/v1/health и /ca.crt остаются доступны по HTTP; HSTS не включается", Risk: sdk.RiskChange})
	}
	addr := "https://" + firstName(dns, ips)
	if port != 443 && port != 0 {
		addr = fmt.Sprintf("%s:%d", addr, port)
	}
	pl.Warnings = append(pl.Warnings,
		"После включения адрес станет "+addr+". В браузере войдите заново.",
		"Desktop-приложения версии ниже "+DesktopMin+" перестанут открывать Hestia.")
	return pl, nil
}

func firstName(dns, ips []string) string {
	if len(dns) > 0 {
		return dns[0]
	}
	if len(ips) > 0 {
		if strings.Contains(ips[0], ":") {
			return "[" + ips[0] + "]"
		}
		return ips[0]
	}
	return ""
}

// LinkPrepare generates a new key (kept in key.pending.pem until a
// certificate for it is applied) and returns the CSR with the names.
func (p plugin) LinkPrepare(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	s := p.s
	s.op.Lock()
	defer s.op.Unlock()
	if s.Addr == "" {
		return nil, errors.New(msgDisabledFlag)
	}
	dns, ips := s.names(ctx, req.Peer)
	if len(dns)+len(ips) == 0 {
		return nil, errors.New("у Hestia нет ни проверенного имени, ни IP-адреса для сертификата")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	if err := writeAtomic(s.path(filePending), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: strings.Trim(firstName(dns, ips), "[]")}, DNSNames: dns}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(types.TLSRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), DNS: dns, IPs: ips})
}

func (p plugin) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	if req.Role != sdk.RoleConsumer || req.Port != PortTLS {
		return nil, fmt.Errorf("порт %s не поддерживается", req.Port)
	}
	var b types.TLSCert
	if err := json.Unmarshal(req.Binding, &b); err != nil {
		return nil, fmt.Errorf("данные связи: %w", err)
	}
	if err := job.Step("Установка сертификата HTTPS"); err != nil {
		return nil, err
	}
	if err := p.s.install(ctx, req.Link, b, job); err != nil {
		return nil, err
	}
	return nil, nil
}

func (p plugin) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	return p.s.remove(ctx, req.Link, job)
}

func (p plugin) LinkRefresh(context.Context, sdk.LinkRequest) (json.RawMessage, error) {
	return nil, errors.New("Hestia — потребитель связи")
}

func (p plugin) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	s := p.s
	in := s.Info()
	switch {
	case in.Reset:
		return sdk.LinkStatus{State: sdk.StateDegraded, Detail: msgReset}, nil
	case in.Mode != ModeOn || in.Link != req.Link:
		return sdk.LinkStatus{State: sdk.StateDown, Detail: msgNotLoaded}, nil
	case in.Listener != "up" || in.NotAfter == nil:
		msg := msgNotLoaded
		if in.Error != "" {
			msg += ": " + in.Error
		}
		return sdk.LinkStatus{State: sdk.StateDown, Detail: msg}, nil
	case in.Expired:
		return sdk.LinkStatus{State: sdk.StateDown, Detail: "Сертификат истёк " + dateText(*in.NotAfter)}, nil
	}
	if err := s.filesMatch(); err != nil {
		return sdk.LinkStatus{State: sdk.StateDown, Detail: "Файлы сертификата: " + err.Error()}, nil
	}
	dns, ips := s.names(ctx, req.Peer)
	s.mu.Lock()
	same := types.TLSRequest{DNS: s.state.DNS, IPs: s.state.IPs}.SameNames(types.TLSRequest{DNS: dns, IPs: ips})
	s.mu.Unlock()
	if !same {
		return sdk.LinkStatus{State: sdk.StateDegraded, Detail: msgNamesChanged}, nil
	}
	return sdk.LinkStatus{State: sdk.StateOK, Detail: "HTTPS до " + dateText(*in.NotAfter)}, nil
}

// filesMatch checks that the files on disk are those in use.
func (s *Service) filesMatch() error {
	certPEM, err := os.ReadFile(s.path(fileCert))
	if err != nil {
		return err
	}
	leaf, err := types.ParseCert(string(certPEM))
	if err != nil {
		return err
	}
	cur := s.cert.Load()
	if cur == nil || len(cur.Certificate) == 0 || !bytes.Equal(cur.Certificate[0], leaf.Raw) {
		return errors.New("сертификат на диске не тот, что в работе")
	}
	s.mu.Lock()
	serial := s.state.Serial
	s.mu.Unlock()
	if !strings.EqualFold(strings.TrimLeft(serial, "0"), strings.TrimLeft(leaf.SerialNumber.Text(16), "0")) {
		return errors.New("state.json не совпадает с сертификатом")
	}
	return nil
}

// snapshot is the previous content of the files (nil: missing).
type snapshot map[string][]byte

func (s *Service) snapshot() snapshot {
	out := snapshot{}
	for _, n := range []string{fileKey, fileCert, fileCA, fileState} {
		if b, err := os.ReadFile(s.path(n)); err == nil {
			out[n] = b
		} else {
			out[n] = nil
		}
	}
	return out
}

func (s *Service) restore(sn snapshot) {
	for n, b := range sn {
		if b == nil {
			_ = os.Remove(s.path(n))
		} else {
			_ = writeAtomic(s.path(n), b)
		}
	}
}

// install puts a new certificate in place: the pending key must match it;
// the files are replaced atomically, the certificate is swapped in without
// a restart; the first time the listener opens and Hestia checks itself
// over HTTPS before the mode is "on". Any failure restores the previous
// files, certificate, listener and mode.
func (s *Service) install(ctx context.Context, link int64, b types.TLSCert, job *sdk.Job) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.Addr == "" {
		return errors.New(msgDisabledFlag)
	}
	keyPEM, err := os.ReadFile(s.path(filePending))
	if err != nil {
		return errors.New("нет ключа из link.prepare (key.pending.pem)")
	}
	pair, err := tls.X509KeyPair([]byte(b.CertPEM+"\n"+b.ChainPEM), keyPEM)
	if err != nil {
		return fmt.Errorf("сертификат не подходит к ключу: %w", err)
	}
	ca, err := types.ParseCert(b.CAPEM)
	if err != nil {
		return fmt.Errorf("ca_pem: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	st := State{Mode: ModeOn, Link: link, Serial: b.Serial, NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(),
		CASHA256: types.CertSHA256(ca.Raw), DNS: slices.Clone(leaf.DNSNames)}
	for _, ip := range leaf.IPAddresses {
		st.IPs = append(st.IPs, ip.String())
	}
	stJSON, _ := json.MarshalIndent(st, "", "  ")

	old := s.snapshot()
	s.mu.Lock()
	oldState, oldCA, oldMode := s.state, s.caPEM, s.mode
	s.mu.Unlock()
	oldCert := s.cert.Load()
	opened := false
	rollback := func(cause error) error {
		if opened {
			s.closeListener()
		}
		s.restore(old)
		s.cert.Store(oldCert)
		s.mu.Lock()
		s.state, s.caPEM, s.mode = oldState, oldCA, oldMode
		s.mu.Unlock()
		_ = s.Store.SetSetting(context.WithoutCancel(ctx), SettingMode, oldMode)
		job.Log("warn", "Откат: прежние файлы сертификата восстановлены")
		return cause
	}
	if err := s.ensureDir(); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{fileCert, []byte(b.CertPEM + "\n" + b.ChainPEM)}, {fileCA, []byte(b.CAPEM)}, {fileKey, keyPEM}, {fileState, stJSON}} {
		if err := writeAtomic(s.path(f.name), f.data); err != nil {
			return rollback(fmt.Errorf("запись %s: %w", f.name, err))
		}
	}
	s.cert.Store(&pair)
	s.mu.Lock()
	s.state, s.caPEM = st, []byte(b.CAPEM)
	s.mu.Unlock()
	if s.Port() == 0 {
		if err := s.listen(); err != nil {
			return rollback(err)
		}
		opened = true
	}
	name := firstName(st.DNS, st.IPs)
	if err := s.selfCheck(ctx, ca, strings.Trim(name, "[]")); err != nil {
		return rollback(fmt.Errorf("самопроверка HTTPS: %w", err))
	}
	if err := s.setMode(ctx, ModeOn); err != nil {
		return rollback(err)
	}
	_ = os.Remove(s.path(filePending))
	s.setLoadErr("")
	job.Log("info", fmt.Sprintf("HTTPS на порту %d, сертификат %s до %s", s.Port(), st.Serial, dateText(st.NotAfter)))
	return nil
}

// selfCheck asks /api/v1/health over HTTPS on loopback trusting only the
// root of the link: the same instance must answer.
func (s *Service) selfCheck(ctx context.Context, ca *x509.Certificate, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool(ca), ServerName: name, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/v1/health", s.Port()), nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var h struct {
		InstanceID string `json:"instance_id"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&h) != nil {
		return fmt.Errorf("ответ %d", resp.StatusCode)
	}
	if h.InstanceID != s.InstanceID {
		return errors.New("на порту HTTPS отвечает не эта Hestia")
	}
	return nil
}

// remove turns HTTPS off for the link: the redirect stops at once, the
// listener closes and tls/ moves to tls.removed-<ts> (the last two kept).
// For a link that is not the one in use (the rollback of a failed create)
// only the pending key goes.
func (s *Service) remove(ctx context.Context, link int64, job *sdk.Job) error {
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	cur := s.state.Link
	s.mu.Unlock()
	if cur != link {
		_ = os.Remove(s.path(filePending))
		job.Log("info", "Ключ запроса удалён")
		return nil
	}
	if err := s.setMode(ctx, ModeOff); err != nil {
		return err
	}
	s.closeListener()
	s.cert.Store(nil)
	s.mu.Lock()
	s.state, s.caPEM = State{}, nil
	s.mu.Unlock()
	if _, err := os.Stat(s.dir()); err == nil {
		dst := filepath.Join(s.DataDir, fmt.Sprintf("%s.removed-%d", DirName, s.Now().Unix()))
		if err := os.Rename(s.dir(), dst); err != nil {
			return err
		}
		pruneRemoved(s.DataDir)
	}
	job.Log("info", "HTTPS выключен, Hestia работает по HTTP")
	return nil
}

// pruneRemoved keeps the last keepRemoved directories tls.removed-*.
func pruneRemoved(dataDir string) {
	list, _ := filepath.Glob(filepath.Join(dataDir, DirName+".removed-*"))
	sort.Strings(list)
	for len(list) > keepRemoved {
		_ = os.RemoveAll(list[0])
		list = list[1:]
	}
}
