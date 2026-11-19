package tlsself

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/sdktest"
	"github.com/uxerror/hestia/sdk/types"
)

type tenv struct {
	t     *testing.T
	s     *Service
	h     *sdktest.Host
	st    *store.Store
	root  *x509.Certificate
	rootK *ecdsa.PrivateKey
	ca    string
	http  *httptest.Server // the HTTP side (port 80) with the middleware
}

func newTEnv(t *testing.T, addr string) *tenv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Service{DataDir: dir, Store: st, Addr: addr, InstanceID: "inst-1", Version: "v0.4.0",
		Names: func(context.Context) ([]string, []string) { return []string{"hestia.home"}, []string{"10.10.10.30"} }}
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"instance_id": "inst-1", "tls": s.Health()})
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) { auth.SetCookie(w, r, "tok") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "spa") })
	h := s.Middleware(mux)
	s.SetHandler(h)
	t.Cleanup(s.Close)
	rootPEM, rootKey, err := pki.NewRoot("test", pki.Constraints{Zones: []string{"home"}, IPRanges: mustNets("10.0.0.0/8")}, 10, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root, _ := pki.ParseCertPEM(rootPEM)
	e := &tenv{t: t, s: s, st: st, root: root, rootK: rootKey, ca: string(rootPEM)}
	e.h = sdktest.New(t, Manifest("v0.4.0"), s.Plugin())
	e.http = httptest.NewServer(h)
	t.Cleanup(e.http.Close)
	return e
}

func mustNets(s ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range s {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}

func (e *tenv) req(link int64, action string) sdk.LinkRequest {
	return sdk.LinkRequest{Link: link, Kind: sdk.LinkService, Role: sdk.RoleConsumer, Action: action, Port: PortTLS, Type: types.TLSCertType,
		Instance: sdk.Instance{ID: 1, Name: "Hestia"}, Peer: &sdk.LinkPeer{Plugin: "hestia-ca", Instance: 2, Name: "CA", Port: "tls"}}
}

// issue prepares and signs a certificate valid for life (nb in the past).
func (e *tenv) issue(link int64, life time.Duration) (types.TLSCert, types.TLSRequest) {
	e.t.Helper()
	raw, err := e.h.LinkPrepare(context.Background(), e.req(link, sdk.ActionCreate))
	if err != nil {
		e.t.Fatal(err)
	}
	var r types.TLSRequest
	_ = json.Unmarshal(raw, &r)
	is, err := pki.Issue(e.root, e.rootK, []byte(r.CSRPEM), r.DNS, r.IPs, life, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return types.TLSCert{CertPEM: string(is.CertPEM), CAPEM: e.ca, CASHA256: types.CertSHA256(e.root.Raw), DNS: r.DNS, IPs: r.IPs,
		Serial: is.Serial, NotBefore: is.NotBefore, NotAfter: is.NotAfter}, r
}

func (e *tenv) apply(link int64, action string, b types.TLSCert) error {
	req := e.req(link, action)
	req.Binding, _ = json.Marshal(b)
	_, err := e.h.LinkApply(context.Background(), req)
	return err
}

// serial asks the HTTPS port for its certificate.
func (e *tenv) serial() string {
	e.t.Helper()
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.s.Port()), &tls.Config{RootCAs: poolOf(e.root), ServerName: "hestia.home"})
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
}

func poolOf(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get(t *testing.T, c *http.Client, method, url string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestEnableRenewRemove(t *testing.T) {
	e := newTEnv(t, "127.0.0.1:0")
	ctx := context.Background()
	// Before: HTTP serves all, /ca.crt is 404, no listener.
	if resp, _ := get(t, noRedirect(), "GET", e.http.URL+"/ca.crt"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ca.crt %d", resp.StatusCode)
	}
	if resp, body := get(t, noRedirect(), "GET", e.http.URL+"/x"); resp.StatusCode != 200 || body != "spa" {
		t.Fatalf("http %d %s", resp.StatusCode, body)
	}
	pl, err := e.h.LinkPlan(ctx, e.req(9, sdk.ActionCreate))
	if err != nil || !strings.Contains(string(pl.Request), "hestia.home") || strings.Contains(string(pl.Request), "csr") {
		t.Fatalf("plan %+v %v", pl, err)
	}
	// The key is born in tls/ and never leaves it: the request has the CSR only.
	b, r := e.issue(9, 90*24*time.Hour)
	if strings.Contains(r.CSRPEM, "PRIVATE") {
		t.Fatal("key in the request")
	}
	if st, err := os.Stat(filepath.Join(e.s.DataDir, DirName, filePending)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending key %v %v", err, st)
	}
	if err := e.apply(9, sdk.ActionCreate, b); err != nil {
		t.Fatal(err)
	}
	if mode, _ := e.st.GetSetting(ctx, SettingMode); mode != ModeOn {
		t.Fatalf("mode %q", mode)
	}
	if st, _ := os.Stat(filepath.Join(e.s.DataDir, DirName)); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v", st.Mode())
	}
	for _, f := range []string{fileKey, fileCert, fileCA, fileState} {
		if st, err := os.Stat(filepath.Join(e.s.DataDir, DirName, f)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s %v %v", f, err, st)
		}
	}
	if _, err := os.Stat(filepath.Join(e.s.DataDir, DirName, filePending)); err == nil {
		t.Fatal("pending key left")
	}
	if e.serial() != b.Serial {
		t.Fatal("wrong certificate served")
	}
	// HTTP: 308 to https with the port, except the health and /ca.crt.
	resp, _ := get(t, noRedirect(), "GET", e.http.URL+"/plugins?x=1")
	want := fmt.Sprintf("https://127.0.0.1:%d/plugins?x=1", e.s.Port())
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want || resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatalf("redirect %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := get(t, noRedirect(), "POST", e.http.URL+"/api/v1/health"); resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("POST health %d", resp.StatusCode)
	}
	resp, body := get(t, noRedirect(), "GET", e.http.URL+"/api/v1/health")
	if resp.StatusCode != 200 || !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, types.CertSHA256(e.root.Raw)) {
		t.Fatalf("health %d %s", resp.StatusCode, body)
	}
	resp, body = get(t, noRedirect(), "GET", e.http.URL+"/ca.crt")
	if resp.StatusCode != 200 || body != e.ca || resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" {
		t.Fatalf("ca.crt %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	// HTTPS: the same handler; the session cookie is Secure there.
	tc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: poolOf(e.root), ServerName: "10.10.10.30"}}}
	resp, _ = get(t, tc, "POST", fmt.Sprintf("https://127.0.0.1:%d/login", e.s.Port()))
	if c := resp.Cookies(); len(c) == 0 || !c[0].Secure {
		t.Fatalf("cookie %+v", resp.Cookies())
	}
	if ls, _ := e.h.LinkStatus(ctx, e.req(9, "")); ls.State != sdk.StateOK {
		t.Fatalf("status %+v", ls)
	}

	// Renewal: the new certificate is served without a restart.
	b2, _ := e.issue(9, 90*24*time.Hour)
	if err := e.apply(9, sdk.ActionUpdate, b2); err != nil {
		t.Fatal(err)
	}
	if e.serial() != b2.Serial || b2.Serial == b.Serial {
		t.Fatal("hot swap did not happen")
	}
	// A certificate for another key is refused and the old one stays.
	b3, _ := e.issue(9, 90*24*time.Hour)
	b3.CertPEM = b2.CertPEM // pending key is new, the certificate is the old one
	if err := e.apply(9, sdk.ActionUpdate, b3); err == nil {
		t.Fatal("mismatching key accepted")
	}
	if e.serial() != b2.Serial {
		t.Fatal("old certificate lost")
	}

	// Removal: HTTP again at once, the port closes, the files are kept aside.
	port := e.s.Port()
	if err := e.h.LinkRemove(ctx, e.req(9, sdk.ActionRemove)); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(t, noRedirect(), "GET", e.http.URL+"/x"); resp.StatusCode != 200 {
		t.Fatalf("after remove %d", resp.StatusCode)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		t.Fatal("HTTPS still listening")
	}
	if list, _ := filepath.Glob(filepath.Join(e.s.DataDir, DirName+".removed-*")); len(list) != 1 {
		t.Fatalf("removed dirs %v", list)
	}
	if mode, _ := e.st.GetSetting(ctx, SettingMode); mode != ModeOff {
		t.Fatalf("mode %q", mode)
	}
}

func TestEnableRollbackBusyPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	e := newTEnv(t, busy.Addr().String())
	b, _ := e.issue(3, 90*24*time.Hour)
	if err := e.apply(3, sdk.ActionCreate, b); err == nil || !strings.Contains(err.Error(), "порт HTTPS") {
		t.Fatalf("busy port: %v", err)
	}
	for _, f := range []string{fileKey, fileCert, fileCA, fileState} {
		if _, err := os.Stat(filepath.Join(e.s.DataDir, DirName, f)); err == nil {
			t.Fatalf("%s left after rollback", f)
		}
	}
	if e.s.Active() || e.s.Info().Mode != ModeOff {
		t.Fatal("HTTPS on after rollback")
	}
	// The rollback of the link removes the pending key.
	if err := e.h.LinkRemove(context.Background(), e.req(3, sdk.ActionRemove)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.s.DataDir, DirName, filePending)); err == nil {
		t.Fatal("pending key left")
	}
}

func TestSelfCheckOtherInstance(t *testing.T) {
	e := newTEnv(t, "127.0.0.1:0")
	e.s.InstanceID = "someone-else"
	b, _ := e.issue(4, 90*24*time.Hour)
	if err := e.apply(4, sdk.ActionCreate, b); err == nil || !strings.Contains(err.Error(), "самопроверка") {
		t.Fatalf("self-check: %v", err)
	}
	if e.s.Port() != 0 {
		t.Fatal("listener left open")
	}
}

func TestExpiredAndMissing(t *testing.T) {
	e := newTEnv(t, "127.0.0.1:0")
	ctx := context.Background()
	b, _ := e.issue(5, 30*time.Minute)
	if err := e.apply(5, sdk.ActionCreate, b); err != nil {
		t.Fatal(err)
	}
	// Expired: no redirect, the status says so; health still "enabled".
	e.s.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if resp, _ := get(t, noRedirect(), "GET", e.http.URL+"/x"); resp.StatusCode != 200 {
		t.Fatalf("expired: %d", resp.StatusCode)
	}
	if ls, _ := e.h.LinkStatus(ctx, e.req(5, "")); ls.State != sdk.StateDown || !strings.Contains(ls.Detail, "истёк") {
		t.Fatalf("status %+v", ls)
	}
	if h := e.s.Health(); h["expired"] != true {
		t.Fatalf("health %v", h)
	}
	e.s.Close()

	// A restart with the files gone: HTTP only, the mode stays "on".
	if err := os.RemoveAll(filepath.Join(e.s.DataDir, DirName)); err != nil {
		t.Fatal(err)
	}
	s2 := &Service{DataDir: e.s.DataDir, Store: e.st, Addr: "127.0.0.1:0", InstanceID: "inst-1"}
	if err := s2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	s2.Start()
	defer s2.Close()
	if s2.Port() != 0 || s2.Active() || s2.Info().Mode != ModeOn || s2.Info().Error == "" {
		t.Fatalf("restart without files: %+v", s2.Info())
	}
}

func TestStartWithFiles(t *testing.T) {
	e := newTEnv(t, "127.0.0.1:0")
	b, _ := e.issue(6, 90*24*time.Hour)
	if err := e.apply(6, sdk.ActionCreate, b); err != nil {
		t.Fatal(err)
	}
	e.s.Close()
	s2 := &Service{DataDir: e.s.DataDir, Store: e.st, Addr: "127.0.0.1:0", InstanceID: "inst-1"}
	if err := s2.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	s2.SetHandler(http.NotFoundHandler())
	s2.Start()
	defer s2.Close()
	if s2.Port() == 0 || !s2.Active() {
		t.Fatalf("not started: %+v", s2.Info())
	}
}

func TestResetAndStatus(t *testing.T) {
	e := newTEnv(t, "127.0.0.1:0")
	ctx := context.Background()
	b, _ := e.issue(8, 90*24*time.Hour)
	if err := e.apply(8, sdk.ActionCreate, b); err != nil {
		t.Fatal(err)
	}
	e.s.Close()
	var out bytes.Buffer
	if err := StatusReport(&out, e.s.DataDir, time.Now()); err != nil || !strings.Contains(out.String(), "hestia.home") ||
		!strings.Contains(out.String(), colon(types.CertSHA256(e.root.Raw))) {
		t.Fatalf("status %v\n%s", err, out.String())
	}
	// Not root and not hestia: refused.
	orig := currentUser
	defer func() { currentUser = orig }()
	currentUser = func() (int, string) { return 1000, "someone" }
	if err := Reset(&out, e.s.DataDir, time.Now()); err == nil {
		t.Fatal("reset by another user")
	}
	currentUser = func() (int, string) { return 990, ServiceUser }
	out.Reset()
	if err := Reset(&out, e.s.DataDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "systemctl restart hestia") {
		t.Fatal(out.String())
	}
	if list, _ := filepath.Glob(filepath.Join(e.s.DataDir, DirName+".off-*")); len(list) != 1 {
		t.Fatalf("off dirs %v", list)
	}
	// The next start: mode off, marker gone, the link degraded.
	s2 := &Service{DataDir: e.s.DataDir, Store: e.st, Addr: "127.0.0.1:0", InstanceID: "inst-1"}
	if err := s2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	s2.Start()
	defer s2.Close()
	if s2.Info().Mode != ModeOff || !s2.Info().Reset || s2.Port() != 0 {
		t.Fatalf("after reset %+v", s2.Info())
	}
	if _, err := os.Stat(filepath.Join(e.s.DataDir, ResetMarker)); err == nil {
		t.Fatal("marker left")
	}
	h2 := sdktest.New(t, Manifest("v0.4.0"), s2.Plugin())
	if ls, _ := h2.LinkStatus(ctx, e.req(8, "")); ls.State != sdk.StateDegraded || ls.Detail != msgReset {
		t.Fatalf("status %+v", ls)
	}
	out.Reset()
	if err := StatusReport(&out, e.s.DataDir, time.Now()); err != nil || !strings.Contains(out.String(), "выключен") {
		t.Fatalf("status after reset %v %s", err, out.String())
	}
}

func TestDisabledByFlag(t *testing.T) {
	e := newTEnv(t, "")
	if _, err := e.h.LinkPlan(context.Background(), e.req(1, sdk.ActionCreate)); err == nil || !strings.Contains(err.Error(), "флагом") {
		t.Fatalf("plan with HTTPS disabled: %v", err)
	}
	if e.s.Info().Listener != "disabled" {
		t.Fatal(e.s.Info().Listener)
	}
}
