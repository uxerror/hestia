package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

type testCA struct {
	pem  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, zones, ranges string) testCA {
	t.Helper()
	z, _, err := ParseZones(zones)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseIPRanges(ranges)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, key, err := NewRoot("test", Constraints{Zones: z, IPRanges: r}, 10, testNow)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{certPEM, cert, key}
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func csrFor(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	b, err := NewCSR(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseZones(t *testing.T) {
	z, w, err := ParseZones(" home, lan ,home,home.arpa,corp.example ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(z, ",") != "home,lan,home.arpa,corp.example" {
		t.Fatalf("zones = %v", z)
	}
	if len(w) != 1 || !strings.Contains(w[0], "corp.example") {
		t.Fatalf("warnings = %v", w)
	}
	if _, w, _ := ParseZones("x.arpa"); len(w) != 1 {
		t.Fatalf("arpa outside home.arpa must warn: %v", w)
	}
	for _, bad := range []string{"", " , ", "local", "a.local", "*.home", "Home", "home.", "-a.home", "a..b", strings.Repeat("a", 64)} {
		if _, _, err := ParseZones(bad); err == nil {
			t.Errorf("ParseZones(%q) succeeded", bad)
		}
	}
	if _, _, err := ParseZones("local"); err == nil || !strings.Contains(err.Error(), "зарезервирована mDNS") {
		t.Errorf("local: %v", err)
	}
}

func TestParseIPRanges(t *testing.T) {
	r, err := ParseIPRanges(DefaultIPRanges)
	if err != nil || len(r) != 4 {
		t.Fatalf("default: %v %v", r, err)
	}
	r, err = ParseIPRanges("192.168.1.0/24, 10.1.0.0/16,192.168.1.0/24")
	if err != nil || len(r) != 2 {
		t.Fatalf("%v %v", r, err)
	}
	if r, err := ParseIPRanges(""); err != nil || len(r) != 0 {
		t.Fatalf("empty: %v %v", r, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.0/7", "8.8.8.0/24", "172.0.0.0/8", "fc00::/6", "2001:db8::/32", "192.168.1.1", "junk"} {
		if _, err := ParseIPRanges(bad); err == nil {
			t.Errorf("ParseIPRanges(%q) succeeded", bad)
		}
	}
}

func TestNewRoot(t *testing.T) {
	ca := newTestCA(t, "home,lan", "192.168.0.0/16")
	c := ca.cert
	if c.Subject.CommonName != "Hestia Root CA" || c.Subject.Organization[0] != "Hestia" || c.Subject.OrganizationalUnit[0] != "test" {
		t.Errorf("subject %v", c.Subject)
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Error("basic constraints")
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage %v", c.KeyUsage)
	}
	if !c.PermittedDNSDomainsCritical || strings.Join(c.PermittedDNSDomains, ",") != "home,lan" {
		t.Errorf("dns constraints %v", c.PermittedDNSDomains)
	}
	if len(c.PermittedIPRanges) != 1 || c.PermittedIPRanges[0].String() != "192.168.0.0/16" {
		t.Errorf("ip constraints %v", c.PermittedIPRanges)
	}
	if len(c.PermittedEmailAddresses) != 1 || c.PermittedEmailAddresses[0] != "invalid" ||
		len(c.PermittedURIDomains) != 1 || c.PermittedURIDomains[0] != "invalid" {
		t.Error("email/URI constraints")
	}
	var critNC, critBC bool
	for _, e := range c.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}) {
			critNC = e.Critical
		}
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
			critBC = e.Critical
		}
	}
	if !critNC || !critBC {
		t.Error("name constraints / basic constraints must be critical")
	}
	ski, _ := subjectKeyID(&ca.key.PublicKey)
	if !bytes.Equal(c.SubjectKeyId, ski) || len(ski) != 20 {
		t.Error("SKI")
	}
	if c.SerialNumber.BitLen() < 64 {
		t.Error("serial too short")
	}
	if !c.NotBefore.Equal(testNow.Add(-5*time.Minute)) || !c.NotAfter.Equal(testNow.AddDate(10, 0, 0)) {
		t.Errorf("validity %v %v", c.NotBefore, c.NotAfter)
	}
	if got := ConstraintsOf(c); len(got.Zones) != 2 || len(got.IPRanges) != 1 {
		t.Errorf("ConstraintsOf %v", got)
	}
	if _, _, err := NewRoot("x", Constraints{}, 10, testNow); err == nil {
		t.Error("root without zones")
	}
}

func TestRootWithoutIPRangesExcludesAll(t *testing.T) {
	ca := newTestCA(t, "home", "")
	if len(ca.cert.ExcludedIPRanges) != 2 {
		t.Fatalf("excluded %v", ca.cert.ExcludedIPRanges)
	}
	if _, err := Issue(ca.cert, ca.key, csrFor(t, ecKey(t)), nil, []string{"192.168.1.1"}, time.Hour, testNow); err == nil {
		t.Fatal("IP issued without ranges")
	}
	// Even a directly signed leaf does not verify.
	leaf := signDirect(t, ca, nil, []string{"192.168.1.1"})
	if err := verify(ca, leaf); err == nil {
		t.Fatal("IP leaf verified under a root without IP ranges")
	}
}

func issueNames(t *testing.T, ca testCA, dns, ips []string) error {
	t.Helper()
	_, err := Issue(ca.cert, ca.key, csrFor(t, ecKey(t)), dns, ips, 24*time.Hour, testNow)
	return err
}

func TestIssueNames(t *testing.T) {
	ca := newTestCA(t, "home", "192.168.0.0/16,fd00::/8")
	ok := []struct{ dns, ips []string }{
		{[]string{"nas.home"}, nil},
		{[]string{"home"}, nil},
		{[]string{"a.b.c.home"}, nil},
		{nil, []string{"192.168.1.10"}},
		{nil, []string{"fd00::1"}},
		{[]string{"nas.home"}, []string{"192.168.1.10"}},
	}
	for _, c := range ok {
		if err := issueNames(t, ca, c.dns, c.ips); err != nil {
			t.Errorf("%v %v: %v", c.dns, c.ips, err)
		}
	}
	bad := []struct{ dns, ips []string }{
		{nil, nil},
		{[]string{"nas.lan"}, nil},
		{[]string{"nothome"}, nil},
		{[]string{"xhome"}, nil},
		{[]string{"*.home"}, nil},
		{[]string{"NAS.home"}, nil},
		{[]string{"nas.home."}, nil},
		{[]string{"192.168.1.1"}, nil},
		{nil, []string{"10.0.0.1"}},
		{nil, []string{"127.0.0.1"}},
		{nil, []string{"0.0.0.0"}},
		{nil, []string{"::"}},
		{nil, []string{"224.0.0.1"}},
		{nil, []string{"fe80::1"}},
		{nil, []string{"nas"}},
		{[]string{"a.home", "a.home"}, nil},
	}
	for _, c := range bad {
		err := issueNames(t, ca, c.dns, c.ips)
		var ne *NamesErr
		if !errors.As(err, &ne) || len(ne.Names) == 0 {
			t.Errorf("%v %v: want *NamesErr, got %v", c.dns, c.ips, err)
		}
	}
	err := issueNames(t, ca, []string{"ok.home", "hestia.lan"}, []string{"8.8.8.8"})
	var ne *NamesErr
	if !errors.As(err, &ne) || len(ne.Names) != 2 || ne.Names[0].Name != "hestia.lan" || ne.Names[1].Name != "8.8.8.8" {
		t.Fatalf("per-name errors: %#v", err)
	}
	if ne.Names[0].Error() != "hestia.lan: вне зон CA (home)" {
		t.Errorf("message %q", ne.Names[0].Error())
	}
	var many []string
	for i := range 33 {
		many = append(many, "h"+big.NewInt(int64(i)).String()+".home")
	}
	if err := issueNames(t, ca, many, nil); err == nil {
		t.Error("33 names issued")
	}
	if err := issueNames(t, ca, many[:32], nil); err != nil {
		t.Errorf("32 names: %v", err)
	}
}

func TestIssueLeaf(t *testing.T) {
	ca := newTestCA(t, "home", "192.168.0.0/16")
	key := ecKey(t)
	csr, err := NewCSR(key, "evil.example.com")
	if err != nil {
		t.Fatal(err)
	}
	iss, err := Issue(ca.cert, ca.key, csr, []string{"nas.home"}, []string{"192.168.1.5"}, 48*time.Hour, testNow)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCertPEM(iss.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "nas.home" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "nas.home" ||
		len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.168.1.5" {
		t.Errorf("names %v %v %v", leaf.Subject, leaf.DNSNames, leaf.IPAddresses)
	}
	if !KeyMatches(leaf, key) {
		t.Error("leaf key differs from CSR key")
	}
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("usages")
	}
	if !bytes.Equal(leaf.AuthorityKeyId, ca.cert.SubjectKeyId) {
		t.Error("AKI")
	}
	if iss.Serial != SerialHex(leaf.SerialNumber) || iss.Serial != strings.ToLower(iss.Serial) {
		t.Error("serial")
	}
	if !leaf.NotBefore.Equal(testNow.Add(-5*time.Minute)) || !leaf.NotAfter.Equal(testNow.Add(48*time.Hour)) || !iss.NotAfter.Equal(leaf.NotAfter) {
		t.Errorf("validity %v %v", leaf.NotBefore, leaf.NotAfter)
	}
	if err := verify(ca, leaf); err != nil {
		t.Errorf("verify: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool(ca), DNSName: "nas.home", CurrentTime: testNow}); err != nil {
		t.Errorf("verify name: %v", err)
	}

	// NotAfter is clamped to the root.
	iss, err = Issue(ca.cert, ca.key, csr, []string{"nas.home"}, nil, 20*365*24*time.Hour, testNow)
	if err != nil || !iss.NotAfter.Equal(ca.cert.NotAfter) {
		t.Errorf("clamp: %v %v", iss.NotAfter, err)
	}
	if _, err := Issue(ca.cert, ca.key, csr, []string{"nas.home"}, nil, 0, testNow); err == nil {
		t.Error("zero lifetime")
	}
	if _, err := Issue(ca.cert, ca.key, csr, []string{"nas.home"}, nil, time.Hour, ca.cert.NotAfter.Add(time.Second)); err == nil {
		t.Error("expired root")
	}
}

func TestIssueKeys(t *testing.T) {
	ca := newTestCA(t, "home", "")
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := Issue(ca.cert, ca.key, csrFor(t, rsa2048), []string{"a.home"}, nil, time.Hour, testNow)
	if err != nil {
		t.Fatalf("rsa 2048: %v", err)
	}
	leaf, _ := ParseCertPEM(iss.CertPEM)
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Error("RSA leaf needs KeyEncipherment")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := Issue(ca.cert, ca.key, csrFor(t, p384), []string{"a.home"}, nil, time.Hour, testNow); err != nil {
		t.Errorf("p384: %v", err)
	}

	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	for name, k := range map[string]crypto.Signer{"rsa1024": rsa1024, "ed25519": edKey, "p521": p521} {
		_, err := Issue(ca.cert, ca.key, csrFor(t, k), []string{"a.home"}, nil, time.Hour, testNow)
		if err == nil || !strings.Contains(err.Error(), "не поддерживается: браузеры") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseCSRBad(t *testing.T) {
	good := csrFor(t, ecKey(t))
	block, _ := pem.Decode(good)
	der := bytes.Clone(block.Bytes)
	der[len(der)-3] ^= 0xff // inside the signature
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ParseCSR(bad); err == nil {
		t.Error("bad signature accepted")
	}
	if _, err := ParseCSR([]byte("junk")); err == nil {
		t.Error("junk accepted")
	}
	if _, err := ParseCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})); err == nil {
		t.Error("wrong PEM type accepted")
	}
	if _, err := ParseCSR(good); err != nil {
		t.Error(err)
	}
}

// signDirect signs a leaf bypassing Issue's checks.
func signDirect(t *testing.T, ca testCA, dns, ips []string) *x509.Certificate {
	t.Helper()
	key := ecKey(t)
	var ipAddrs []net.IP
	for _, s := range ips {
		ipAddrs = append(ipAddrs, net.ParseIP(s))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "x"},
		DNSNames:     dns, IPAddresses: ipAddrs,
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func pool(ca testCA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

func verify(ca testCA, leaf *x509.Certificate) error {
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool(ca), CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func TestNameConstraintsEnforcedByVerifier(t *testing.T) {
	ca := newTestCA(t, "home", "192.168.0.0/16")
	if err := verify(ca, signDirect(t, ca, []string{"nas.home"}, []string{"192.168.1.1"})); err != nil {
		t.Fatalf("control leaf: %v", err)
	}
	for _, c := range []struct{ dns, ips []string }{
		{[]string{"example.com"}, nil},
		{nil, []string{"8.8.8.8"}},
		{[]string{"nas.home"}, []string{"8.8.8.8"}},
	} {
		err := verify(ca, signDirect(t, ca, c.dns, c.ips))
		var cie x509.CertificateInvalidError
		if !errors.As(err, &cie) || cie.Reason != x509.CANotAuthorizedForThisName {
			t.Errorf("%v %v: want CANotAuthorizedForThisName, got %v", c.dns, c.ips, err)
		}
	}
}

func TestFingerprint(t *testing.T) {
	ca := newTestCA(t, "home", "")
	fp := Fingerprint(ca.cert.Raw)
	if len(fp) != 64 || fp != strings.ToLower(fp) {
		t.Fatal(fp)
	}
	col := FingerprintColon(fp)
	if len(col) != 95 || col != strings.ToUpper(col) || col[2] != ':' || strings.ReplaceAll(strings.ToLower(col), ":", "") != fp {
		t.Fatal(col)
	}
}

func TestKeyPEMRoundTrip(t *testing.T) {
	k := ecKey(t)
	p, err := EncodeKeyPEM(k)
	if err != nil || !bytes.HasPrefix(p, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatal(err)
	}
	back, err := ParseKeyPEM(p)
	if err != nil || !back.(*ecdsa.PrivateKey).Equal(k) {
		t.Fatal(err)
	}
	if _, err := ParseKeyPEM([]byte("junk")); err == nil {
		t.Fatal("junk key")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	st, _ := os.Stat(path)
	if string(b) != "two" || st.Mode().Perm() != 0o640 {
		t.Fatalf("%q %v", b, st.Mode())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
}
