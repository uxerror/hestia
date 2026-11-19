package types

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// TLSRequest is the request of tls.cert (consumer → provider). The preview
// in link.plan has no CSR.
type TLSRequest struct {
	CSRPEM string   `json:"csr_pem,omitempty"`
	DNS    []string `json:"dns,omitempty"`
	IPs    []string `json:"ips,omitempty"`
}

// Names returns every name of the request (DNS first, then IPs).
func (r TLSRequest) Names() []string {
	return append(slices.Clone(r.DNS), r.IPs...)
}

// SameNames reports whether two requests ask for the same names (order
// does not matter).
func (r TLSRequest) SameNames(o TLSRequest) bool {
	return sameSet(r.DNS, o.DNS) && sameSet(r.IPs, o.IPs)
}

// TLSCert is the binding of tls.cert (provider → consumer; no secrets).
type TLSCert struct {
	CertPEM   string    `json:"cert_pem"`
	ChainPEM  string    `json:"chain_pem,omitempty"`
	CAPEM     string    `json:"ca_pem"`
	CASHA256  string    `json:"ca_sha256"`
	DNS       []string  `json:"dns"`
	IPs       []string  `json:"ips"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// ShortLifetime is the lifetime below which a certificate counts as issued
// in a test mode: CheckTLSCert then only wants it not expired (otherwise it
// must be valid for at least another hour).
const ShortLifetime = 24 * time.Hour

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// CertSHA256 is the fingerprint of a certificate (lowercase hex of the
// sha256 of its DER).
func CertSHA256(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// ParseCert reads the first certificate of a PEM text.
func ParseCert(s string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("ожидается сертификат PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ParseCSR reads a certificate request PEM and checks its signature.
func ParseCSR(s string) (*x509.CertificateRequest, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("ожидается запрос сертификата (CERTIFICATE REQUEST) PEM")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("запрос сертификата: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("подпись запроса сертификата неверна")
	}
	return csr, nil
}

// CheckTLSCert checks a tls.cert binding against the request it answers:
// the leaf parses and chains to ca_pem (serverAuth, at now), ca_sha256 is
// the fingerprint of ca_pem, the leaf's public key is the CSR's, its SANs
// are exactly the requested names, the fields of the binding describe the
// leaf, and the leaf is valid long enough (see ShortLifetime). wantCA, if
// set, is the root the provider is pinned to (its ca.issuer).
func CheckTLSCert(b TLSCert, req TLSRequest, wantCA string, now time.Time) error {
	leaf, err := ParseCert(b.CertPEM)
	if err != nil {
		return fmt.Errorf("cert_pem: %v", err)
	}
	ca, err := ParseCert(b.CAPEM)
	if err != nil {
		return fmt.Errorf("ca_pem: %v", err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid {
		return errors.New("ca_pem не является сертификатом CA")
	}
	fp := CertSHA256(ca.Raw)
	if NormalizeSHA256(b.CASHA256) != fp {
		return errors.New("ca_sha256 не совпадает с отпечатком ca_pem")
	}
	if wantCA != "" && NormalizeSHA256(wantCA) != fp {
		return errors.New("корень поставщика изменился: сертификат выпущен другим CA (смена корня — только новой связью)")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	inter := x509.NewCertPool()
	for rest := []byte(b.ChainPEM); ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("chain_pem: %v", err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("сертификат не проверяется цепочкой до корня: %v", err)
	}
	csr, err := ParseCSR(req.CSRPEM)
	if err != nil {
		return err
	}
	lk, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return err
	}
	ck, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(lk, ck) {
		return errors.New("открытый ключ сертификата не совпадает с ключом запроса (CSR)")
	}
	var leafIPs []string
	for _, ip := range leaf.IPAddresses {
		leafIPs = append(leafIPs, ip.String())
	}
	reqIPs := make([]string, 0, len(req.IPs))
	for _, s := range req.IPs {
		if ip := net.ParseIP(s); ip != nil {
			reqIPs = append(reqIPs, ip.String())
		} else {
			reqIPs = append(reqIPs, s)
		}
	}
	if !sameSet(leaf.DNSNames, req.DNS) || !sameSet(leafIPs, reqIPs) || len(leaf.EmailAddresses)+len(leaf.URIs) > 0 {
		return fmt.Errorf("имена сертификата (%s) не совпадают с запрошенными (%s)",
			strings.Join(append(slices.Clone(leaf.DNSNames), leafIPs...), ", "), strings.Join(req.Names(), ", "))
	}
	if !sameSet(b.DNS, leaf.DNSNames) || !sameSet(b.IPs, leafIPs) {
		return errors.New("поля dns/ips не совпадают с сертификатом")
	}
	if !strings.EqualFold(strings.TrimLeft(b.Serial, "0"), strings.TrimLeft(leaf.SerialNumber.Text(16), "0")) {
		return errors.New("serial не совпадает с сертификатом")
	}
	if !b.NotBefore.Equal(leaf.NotBefore) || !b.NotAfter.Equal(leaf.NotAfter) {
		return errors.New("not_before/not_after не совпадают с сертификатом")
	}
	min := time.Hour
	if leaf.NotAfter.Sub(leaf.NotBefore) < ShortLifetime {
		min = 0
	}
	if !leaf.NotAfter.After(now.Add(min)) {
		return fmt.Errorf("сертификат истекает слишком скоро (%s)", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// RenewAfter is when a certificate valid from nb to na is renewed: at 2/3
// of its lifetime.
func RenewAfter(nb, na time.Time) time.Time {
	return nb.Add(na.Sub(nb) * 2 / 3)
}
