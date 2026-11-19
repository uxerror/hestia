package caserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// StartTest runs a CA API on 127.0.0.1:0 and returns it with its address
// and the pin of its key (used by the plugin tests too).
func startTest(t *testing.T) (*Server, string, string, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	s := &Server{Dir: filepath.Join(t.TempDir(), "data"), TokenSHA: HashToken(testToken), LeafMax: 90 * 24 * time.Hour, Version: "v0.1.0",
		FailDelay: 50 * time.Millisecond, BackupIter: 100000, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	// Serve creates the API key first; wait for it.
	var pin string
	for i := 0; i < 100; i++ {
		if pin, err = APIPin(s.Dir); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pin == "" {
		t.Fatal("no api cert")
	}
	return s, ln.Addr().String(), pin, &logs
}

func csr(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := pki.NewCSR(k, "x")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestServerAPI(t *testing.T) {
	s, addr, pin, logs := startTest(t)
	cl := Client(addr, pin, testToken, 5*time.Second)
	anon := Client(addr, pin, "", 5*time.Second)
	wrong := Client(addr, pin, strings.Repeat("f", 64), 5*time.Second)

	var h map[string]any
	if err := anon.Do("GET", "/v1/health", nil, &h); err != nil || h["state"] != StateUninitialized {
		t.Fatalf("health %v %v", h, err)
	}
	// Without or with a wrong token: 401 after the delay.
	for _, c := range []*APIClient{anon, wrong} {
		start := time.Now()
		err := c.Do("GET", "/v1/root", nil, nil)
		var ae *APIError
		if !asAPI(err, &ae) || ae.Code != http.StatusUnauthorized || time.Since(start) < 50*time.Millisecond {
			t.Fatalf("no token: %v in %s", err, time.Since(start))
		}
	}
	// A wrong pin is refused by the client.
	if err := Client(addr, strings.Repeat("0", 64), testToken, 5*time.Second).Do("GET", "/v1/health", nil, nil); err != ErrPin {
		t.Fatalf("pin: %v", err)
	}
	// Issue before init: 409.
	if err := cl.Do("POST", "/v1/issue", IssueRequest{CSRPEM: csr(t), DNS: []string{"a.home"}}, nil); code(err) != http.StatusConflict {
		t.Fatalf("issue before init: %v", err)
	}
	var root struct {
		RootPEM    string `json:"root_pem"`
		RootSHA256 string `json:"root_sha256"`
	}
	if err := cl.Do("POST", "/v1/init", InitRequest{Mode: "generate", OU: "CA", Zones: "home", IPRanges: "10.0.0.0/8"}, &root); err != nil {
		t.Fatal(err)
	}
	if fp, _ := RootSHA256(s.Dir); fp != root.RootSHA256 {
		t.Fatal("root-sha256 differs")
	}
	if err := cl.Do("POST", "/v1/init", InitRequest{Mode: "generate", Zones: "home"}, nil); code(err) != http.StatusConflict {
		t.Fatalf("init twice: %v", err)
	}
	// Files: the directory 0700, every file 0600.
	if st, _ := os.Stat(s.Dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v", st.Mode())
	}
	for _, f := range []string{FileAPIKey, FileAPICert, FileCAKey, FileCACert} {
		if st, err := os.Stat(filepath.Join(s.Dir, f)); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, err, st)
		}
	}
	// The pin is the SPKI of the API certificate actually served.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if SPKIPin(conn.ConnectionState().PeerCertificates[0]) != pin {
		t.Fatal("api-pin is not the served key")
	}
	conn.Close()

	// Names outside the zones: 422 with a reason per name.
	err = cl.Do("POST", "/v1/issue", IssueRequest{CSRPEM: csr(t), DNS: []string{"a.home", "x.example.com"}, IPs: []string{"8.8.8.8"}}, nil)
	var ae *APIError
	if !asAPI(err, &ae) || ae.Code != http.StatusUnprocessableEntity || len(ae.Names) != 2 {
		t.Fatalf("names: %v %+v", err, ae)
	}
	// Longer than allowed.
	if err := cl.Do("POST", "/v1/issue", IssueRequest{CSRPEM: csr(t), DNS: []string{"a.home"}, LifetimeS: int64(100 * 24 * 3600)}, nil); code(err) != http.StatusUnprocessableEntity {
		t.Fatalf("lifetime: %v", err)
	}
	var is IssueResult
	if err := cl.Do("POST", "/v1/issue", IssueRequest{CSRPEM: csr(t), DNS: []string{"a.home"}, IPs: []string{"10.10.10.30"}, Ref: "link:1"}, &is); err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.ParseCertPEM([]byte(is.CertPEM))
	if err != nil || leaf.DNSNames[0] != "a.home" || is.RootPEM != root.RootPEM {
		t.Fatalf("leaf %v %v", leaf, err)
	}
	rc, _ := pki.ParseCertPEM([]byte(root.RootPEM))
	pool := x509.NewCertPool()
	pool.AddCert(rc)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
	var other IssueResult
	_ = cl.Do("POST", "/v1/issue", IssueRequest{CSRPEM: csr(t), DNS: []string{"b.home"}, Ref: "link:2"}, &other)

	// Journal and revocation.
	var list []Record
	if err := cl.Do("GET", "/v1/issued?active=1&ref=link:1", nil, &list); err != nil || len(list) != 1 || list[0].Serial != is.Serial {
		t.Fatalf("issued %v %v", list, err)
	}
	if err := cl.Do("POST", "/v1/revoke", map[string]string{"serial": is.Serial, "reason": "test"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.Do("POST", "/v1/revoke", map[string]string{"serial": "abcdef"}, nil); code(err) != http.StatusNotFound {
		t.Fatalf("unknown serial: %v", err)
	}
	_ = cl.Do("GET", "/v1/issued?active=1", nil, &list)
	if len(list) != 1 || list[0].Serial != other.Serial {
		t.Fatalf("active after revoke %v", list)
	}
	_ = cl.Do("GET", "/v1/issued", nil, &list)
	if len(list) != 2 || list[0].RevokedAt == nil {
		t.Fatalf("all %v", list)
	}

	// Backup: encrypted with the passphrase; a short one is refused.
	pass := "correct horse battery staple"
	if err := cl.Do("POST", "/v1/export", map[string]string{"passphrase": "short"}, nil); code(err) != http.StatusUnprocessableEntity {
		t.Fatalf("short pass: %v", err)
	}
	var bk struct {
		Backup string `json:"backup"`
	}
	if err := cl.Do("POST", "/v1/export", map[string]string{"passphrase": pass}, &bk); err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(s.Dir, FileCAKey))
	if strings.Contains(bk.Backup, "PRIVATE KEY") || strings.Contains(bk.Backup, pass) {
		t.Fatal("backup is not encrypted")
	}

	// Restore on a fresh CA: same root; a wrong passphrase is refused.
	s2, addr2, pin2, logs2 := startTest(t)
	cl2 := Client(addr2, pin2, testToken, 5*time.Second)
	if err := cl2.Do("POST", "/v1/init", InitRequest{Mode: "import", Backup: bk.Backup, Passphrase: pass + "x"}, nil); code(err) != http.StatusUnprocessableEntity {
		t.Fatalf("wrong pass: %v", err)
	}
	var r2 struct {
		RootSHA256 string `json:"root_sha256"`
	}
	if err := cl2.Do("POST", "/v1/init", InitRequest{Mode: "import", Backup: bk.Backup, Passphrase: pass}, &r2); err != nil {
		t.Fatal(err)
	}
	if r2.RootSHA256 != root.RootSHA256 {
		t.Fatal("other root after restore")
	}
	k2, _ := os.ReadFile(filepath.Join(s2.Dir, FileCAKey))
	if !bytes.Equal(k2, keyPEM) {
		t.Fatal("other key after restore")
	}
	// Nothing secret in the logs of the service.
	for _, l := range []string{logs.String(), logs2.String()} {
		for _, secret := range []string{testToken, pass, "PRIVATE KEY", strings.Repeat("f", 64)} {
			if strings.Contains(l, secret) {
				t.Fatalf("log contains a secret %q:\n%s", secret[:8], l)
			}
		}
	}
}

func asAPI(err error, out **APIError) bool {
	ae, ok := err.(*APIError)
	if ok {
		*out = ae
	}
	return ok
}

func code(err error) int {
	if ae, ok := err.(*APIError); ok {
		return ae.Code
	}
	return 0
}
