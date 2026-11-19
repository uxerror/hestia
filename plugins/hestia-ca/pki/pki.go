// Package pki implements the HestiaCA certificate authority primitives shared
// by the hestia-ca plugin and ca-server: the name-constrained root, leaf
// issuance from a CSR, name checks, the encrypted key backup format and
// atomic file writes. It uses the standard library only.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// DefaultIPRanges is the default list of IP ranges a new root may sign.
const DefaultIPRanges = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8"

// MaxNames is the maximum number of names (DNS + IP) in one certificate.
const MaxNames = 32

// clockSkew is subtracted from NotBefore of every certificate.
const clockSkew = 5 * time.Minute

// Constraints are the name constraints baked into a root certificate.
type Constraints struct {
	Zones    []string
	IPRanges []*net.IPNet
}

// privateTLDs are last labels that never resolve on the public Internet.
var privateTLDs = []string{"home", "lan", "internal", "intranet", "corp", "private"}

// privateNets are the only networks IP ranges of a root may lie in.
var privateNets = mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")

func mustCIDRs(list ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// splitList splits a comma separated list, trimming spaces and dropping
// empty items.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// ParseZones parses a comma separated list of DNS zones for a new root.
// Warnings are returned for zones that look like public domains.
func ParseZones(s string) (zones []string, warnings []string, err error) {
	for _, z := range splitList(s) {
		if strings.Contains(z, "*") {
			return nil, nil, fmt.Errorf("зона %q: без «*» — зона %s уже включает все свои поддомены", z, strings.TrimLeft(z, "*."))
		}
		if z == "local" || strings.HasSuffix(z, ".local") {
			return nil, nil, fmt.Errorf("зона %s: зона local зарезервирована mDNS", z)
		}
		if err := ValidateDNSName(z); err != nil {
			return nil, nil, fmt.Errorf("зона %q: %w", z, err)
		}
		if slices.Contains(zones, z) {
			continue
		}
		zones = append(zones, z)
		if !privateZone(z) {
			warnings = append(warnings, fmt.Sprintf("Зона %s похожа на публичный домен", z))
		}
	}
	if len(zones) == 0 {
		return nil, nil, errors.New("нужна хотя бы одна DNS-зона")
	}
	return zones, warnings, nil
}

func privateZone(z string) bool {
	if z == "home.arpa" || strings.HasSuffix(z, ".home.arpa") {
		return true
	}
	last := z[strings.LastIndexByte(z, '.')+1:]
	return slices.Contains(privateTLDs, last)
}

// ParseIPRanges parses a comma separated list of CIDRs. Each range must lie
// inside RFC 1918 or fc00::/7. An empty string yields no ranges: such a root
// refuses IP names entirely.
func ParseIPRanges(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	seen := map[string]bool{}
	for _, item := range splitList(s) {
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("диапазон %q: ожидается подсеть вида 192.168.0.0/16", item)
		}
		if !insidePrivate(n) {
			return nil, fmt.Errorf("диапазон %s: разрешены только подсети внутри 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 и fc00::/7", n)
		}
		if seen[n.String()] {
			continue
		}
		seen[n.String()] = true
		out = append(out, n)
	}
	return out, nil
}

func insidePrivate(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	for _, p := range privateNets {
		pOnes, pBits := p.Mask.Size()
		if pBits == bits && pOnes <= ones && p.Contains(n.IP) {
			return true
		}
	}
	return false
}

// NewRoot creates a self-signed, name-constrained root certificate and its
// ECDSA P-256 key. The root may only sign leaves (MaxPathLen 0).
func NewRoot(ou string, c Constraints, years int, now time.Time) (certPEM []byte, key *ecdsa.PrivateKey, err error) {
	if years < 1 || years > 30 {
		return nil, nil, fmt.Errorf("срок корневого сертификата — от 1 до 30 лет, а не %d", years)
	}
	if len(ou) > 64 || strings.ContainsFunc(ou, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, nil, errors.New("имя экземпляра для сертификата — до 64 символов без управляющих")
	}
	if len(c.Zones) == 0 {
		return nil, nil, errors.New("нужна хотя бы одна DNS-зона")
	}
	for _, z := range c.Zones {
		if err := ValidateDNSName(z); err != nil {
			return nil, nil, fmt.Errorf("зона %q: %w", z, err)
		}
	}
	for _, n := range c.IPRanges {
		if !insidePrivate(n) {
			return nil, nil, fmt.Errorf("диапазон %s вне частных сетей", n)
		}
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("создание ключа CA: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	ski, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	subject := pkix.Name{CommonName: "Hestia Root CA", Organization: []string{"Hestia"}}
	if ou != "" {
		subject.OrganizationalUnit = []string{ou}
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     subject,
		NotBefore:                   now.Add(-clockSkew),
		NotAfter:                    now.AddDate(years, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		SubjectKeyId:                ski,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         slices.Clone(c.Zones),
		PermittedIPRanges:           slices.Clone(c.IPRanges),
		// "invalid" (RFC 6761) never resolves: without a permitted entry
		// these name types would not be constrained at all.
		PermittedEmailAddresses: []string{"invalid"},
		PermittedURIDomains:     []string{"invalid"},
	}
	if len(c.IPRanges) == 0 {
		// No permitted IP subtree means "IPs unconstrained"; exclude all.
		tmpl.ExcludedIPRanges = mustCIDRs("0.0.0.0/0", "::/0")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("создание корневого сертификата: %w", err)
	}
	return encodeCert(der), key, nil
}

// subjectKeyID is the SHA-1 of the subjectPublicKey bits (RFC 5280 4.2.1.2
// method 1), the way Go has historically derived it.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, err
	}
	sum := sha1.Sum(info.PublicKey.Bytes)
	return sum[:], nil
}

// ConstraintsOf returns the permitted zones and IP ranges of a root.
func ConstraintsOf(root *x509.Certificate) Constraints {
	return Constraints{
		Zones:    slices.Clone(root.PermittedDNSDomains),
		IPRanges: slices.Clone(root.PermittedIPRanges),
	}
}

// ValidateDNSName checks that name is a lowercase LDH host name without a
// trailing dot or wildcard.
func ValidateDNSName(name string) error {
	if name == "" {
		return errors.New("пустое имя")
	}
	if len(name) > 253 {
		return errors.New("имя длиннее 253 символов")
	}
	if strings.Contains(name, "*") {
		return errors.New("wildcard-имена не поддерживаются")
	}
	if strings.HasSuffix(name, ".") {
		return errors.New("имя с точкой на конце")
	}
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			return errors.New("пустая метка в имени")
		}
		if len(l) > 63 {
			return errors.New("метка длиннее 63 символов")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("метка начинается или кончается дефисом")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("допустимы только строчные латинские буквы, цифры, дефис и точка")
			}
		}
	}
	return nil
}

// NameError is a refusal of one requested name.
type NameError struct {
	Name string `json:"name"`
	Msg  string `json:"msg"`
}

func (e NameError) Error() string {
	if e.Name == "" {
		return e.Msg
	}
	return e.Name + ": " + e.Msg
}

// NamesErr carries all refused names of a request.
type NamesErr struct {
	Names []NameError
}

func (e *NamesErr) Error() string {
	parts := make([]string, len(e.Names))
	for i, n := range e.Names {
		parts[i] = n.Error()
	}
	return strings.Join(parts, "; ")
}

// NamesError wraps name errors into a *NamesErr; nil if errs is empty.
func NamesError(errs []NameError) error {
	if len(errs) == 0 {
		return nil
	}
	return &NamesErr{Names: errs}
}

// CheckNames checks requested DNS names and IPs against the constraints.
func CheckNames(c Constraints, dns, ips []string) []NameError {
	var errs []NameError
	total := len(dns) + len(ips)
	if total == 0 {
		return []NameError{{Msg: "нужно хотя бы одно имя"}}
	}
	if total > MaxNames {
		errs = append(errs, NameError{Msg: fmt.Sprintf("не больше %d имён в сертификате, запрошено %d", MaxNames, total)})
	}
	seen := map[string]bool{}
	dup := func(n string) bool {
		if seen[n] {
			errs = append(errs, NameError{n, "имя повторяется"})
			return true
		}
		seen[n] = true
		return false
	}
	for _, n := range dns {
		if dup(n) {
			continue
		}
		if net.ParseIP(n) != nil {
			errs = append(errs, NameError{n, "IP-адрес в списке DNS-имён"})
			continue
		}
		if err := ValidateDNSName(n); err != nil {
			errs = append(errs, NameError{n, err.Error()})
			continue
		}
		if !inZones(n, c.Zones) {
			errs = append(errs, NameError{n, "вне зон CA (" + zoneList(c.Zones) + ")"})
		}
	}
	for _, s := range ips {
		if dup(s) {
			continue
		}
		ip := net.ParseIP(s)
		switch {
		case ip == nil:
			errs = append(errs, NameError{s, "не IP-адрес"})
		case ip.String() != s:
			errs = append(errs, NameError{s, "запишите адрес как " + ip.String()})
		case ip.IsUnspecified():
			errs = append(errs, NameError{s, "неуказанный адрес не допускается"})
		case ip.IsLoopback():
			errs = append(errs, NameError{s, "loopback-адрес не допускается"})
		case ip.IsMulticast():
			errs = append(errs, NameError{s, "multicast-адрес не допускается"})
		case ip.IsLinkLocalUnicast():
			errs = append(errs, NameError{s, "link-local адрес не допускается"})
		case !inRanges(ip, c.IPRanges):
			errs = append(errs, NameError{s, "вне диапазонов IP CA (" + rangeList(c.IPRanges) + ")"})
		}
	}
	return errs
}

func inZones(name string, zones []string) bool {
	for _, z := range zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return true
		}
	}
	return false
}

func inRanges(ip net.IP, ranges []*net.IPNet) bool {
	for _, r := range ranges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func zoneList(zones []string) string {
	if len(zones) == 0 {
		return "нет"
	}
	return strings.Join(zones, ", ")
}

func rangeList(ranges []*net.IPNet) string {
	if len(ranges) == 0 {
		return "нет"
	}
	parts := make([]string, len(ranges))
	for i, r := range ranges {
		parts[i] = r.String()
	}
	return strings.Join(parts, ", ")
}

// ParseCSR decodes a PEM CSR, verifies its signature and the key algorithm.
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("CSR: нет PEM-блока CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR не разбирается: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("CSR: неверная подпись")
	}
	if err := checkLeafKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}

const keyHint = "браузеры принимают ECDSA P-256/P-384 и RSA 2048…4096"

func checkLeafKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return fmt.Errorf("ключ ECDSA %s не поддерживается: %s", k.Curve.Params().Name, keyHint)
		}
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < 2048 || bits > 4096 {
			return fmt.Errorf("ключ RSA %d бит не поддерживается: %s", bits, keyHint)
		}
	default:
		return fmt.Errorf("ключ %T не поддерживается: %s", pub, keyHint)
	}
	return nil
}

// Issued is a signed leaf certificate.
type Issued struct {
	CertPEM   []byte
	Serial    string // lowercase hex
	NotBefore time.Time
	NotAfter  time.Time
}

// Issue signs a server certificate for the CSR's key with exactly the
// requested names. Name problems are returned as *NamesErr.
func Issue(root *x509.Certificate, rootKey crypto.Signer, csrPEM []byte, dns, ips []string, lifetime time.Duration, now time.Time) (Issued, error) {
	if errs := CheckNames(ConstraintsOf(root), dns, ips); len(errs) > 0 {
		return Issued{}, NamesError(errs)
	}
	if lifetime <= 0 {
		return Issued{}, errors.New("срок сертификата должен быть больше нуля")
	}
	if !now.Before(root.NotAfter) {
		return Issued{}, errors.New("срок корневого сертификата истёк")
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return Issued{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return Issued{}, err
	}
	var ipAddrs []net.IP
	for _, s := range ips {
		ipAddrs = append(ipAddrs, net.ParseIP(s))
	}
	cn := ""
	if len(dns) > 0 {
		cn = dns[0]
	} else {
		cn = ips[0]
	}
	usage := x509.KeyUsageDigitalSignature
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment
	}
	notAfter := now.Add(lifetime)
	if notAfter.After(root.NotAfter) {
		notAfter = root.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              slices.Clone(dns),
		IPAddresses:           ipAddrs,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        root.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootKey)
	if err != nil {
		return Issued{}, fmt.Errorf("подпись сертификата: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Issued{}, err
	}
	return Issued{
		CertPEM:   encodeCert(der),
		Serial:    SerialHex(cert.SerialNumber),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

// SerialHex formats a serial number as lowercase hex.
func SerialHex(n *big.Int) string {
	return strings.ToLower(n.Text(16))
}

// NewCSR creates a PEM CSR for key with the given common name. The CA uses
// only the key from a CSR, so names are not included.
func NewCSR(key crypto.Signer, cn string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Fingerprint is the lowercase hex SHA-256 of der.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// FingerprintColon formats a hex fingerprint as uppercase colon-separated
// pairs ("3F:A1:…").
func FingerprintColon(h string) string {
	h = strings.ToUpper(h)
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i:min(i+2, len(h))])
	}
	return b.String()
}

// ParseCertPEM decodes the first CERTIFICATE block of data.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("нет PEM-сертификата")
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("сертификат не разбирается: %w", err)
			}
			return cert, nil
		}
	}
}

// EncodeKeyPEM encodes a private key as PKCS#8 "PRIVATE KEY" PEM.
func EncodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("ключ не кодируется в PKCS#8")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM decodes a PKCS#8 "PRIVATE KEY" PEM. Errors never include key
// material.
func ParseKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("нет PEM-блока PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("ключ PKCS#8 не разбирается")
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("неподдерживаемый тип ключа")
	}
	return signer, nil
}

// KeyMatches reports whether key is the private half of cert's public key.
func KeyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}

// WriteFileAtomic writes data to path via a temporary file in the same
// directory: chmod, write, fsync, rename, then fsync of the directory.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func newSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n.SetInt64(1) // serials must be positive
	}
	return n, nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
