package netscan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Extra is the answer to one of the follow-up requests.
type Extra struct {
	Status   int
	Location string
	Body     string
}

// Facts is everything collected about one open port; rules match on it.
type Facts struct {
	IP        netip.Addr
	Port      int
	Hint      PortInfo
	Proto     string // http | https | ssh | banner | tcp
	Banner    string
	Status    int
	Server    string
	Location  string
	Title     string
	Type      string // Content-Type
	Cookies   []string
	Headers   http.Header
	Body      string
	Cert      *CertInfo
	Extra     map[string]Extra
	OpenPorts []int // all open ports of the host
	// Err is why an HTTP probe failed (kept for the detail line).
	Err string
}

// Header-less reading limits of follow-up requests.
const extraBodyMax = 16 << 10

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func parseTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := html.UnescapeString(strings.Join(strings.Fields(m[1]), " "))
	if r := []rune(t); len(r) > 200 {
		t = string(r[:200])
	}
	return t
}

// probePort collects the facts of one open port within the probe timeout.
func (s *Scanner) probePort(ctx context.Context, ip netip.Addr, pi PortInfo) *Facts {
	ctx, cancel := context.WithTimeout(ctx, s.probeTimeout())
	defer cancel()
	f := &Facts{IP: ip, Port: pi.Port, Hint: pi, Proto: "tcp", Extra: map[string]Extra{}}
	switch pi.Proto {
	case ProtoNone:
		return f
	case ProtoSSH, ProtoBanner:
		s.banner(ctx, f)
		return f
	case ProtoHTTPS:
		s.web(ctx, f, "https", "http")
	case ProtoHTTP:
		s.web(ctx, f, "http", "https")
	default: // auto: TLS first; a plain HTTP reply to it identifies plain HTTP at once
		err := s.get(ctx, f, "https", "/")
		if err == nil {
			return f
		}
		f.Err = err.Error()
		if ctx.Err() != nil {
			return f
		}
		if httpReplyToTLS(err) {
			if s.get(ctx, f, "http", "/") == nil {
				f.Err = ""
			}
			return f
		}
		s.banner(ctx, f)
		if f.Banner != "" {
			f.Err = ""
			return f
		}
		if ctx.Err() == nil && s.get(ctx, f, "http", "/") == nil {
			f.Err = ""
		}
	}
	return f
}

// httpReplyToTLS: the port answered our TLS hello with plain HTTP.
func httpReplyToTLS(err error) bool {
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return strings.HasPrefix(string(rh.RecordHeader[:]), "HTTP/")
	}
	return strings.Contains(err.Error(), "server gave HTTP response to HTTPS client")
}

// web tries the first scheme and, if the port speaks the other one, the
// fallback. It reports whether a real HTTP answer was obtained.
func (s *Scanner) web(ctx context.Context, f *Facts, first, fallback string) bool {
	err := s.get(ctx, f, first, "/")
	if err == nil {
		return true
	}
	f.Err = err.Error()
	// Retry only when the port answered with the wrong protocol; a silent or
	// refusing port would just burn the time budget.
	if fallback != "" && ctx.Err() == nil && wrongScheme(err) {
		if err2 := s.get(ctx, f, fallback, "/"); err2 == nil {
			f.Err = ""
			return true
		}
	}
	// An auto port that is neither http nor https (the caller reads a banner).
	return false
}

func wrongScheme(err error) bool {
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return true
	}
	m := err.Error()
	for _, p := range []string{"server gave HTTP response to HTTPS client", "malformed HTTP", "first record does not look like a TLS", "EOF", "connection reset", "tls:"} {
		if strings.Contains(m, p) {
			return true
		}
	}
	return false
}

func (s *Scanner) client(ip netip.Addr, port int) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return s.Dialer.DialContext(ctx, ip, port)
		},
		// The probe only reads what the device shows anyone: home devices
		// use self-signed certificates and nothing secret is sent, so the
		// chain is not verified; the certificate itself is recorded.
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   s.probeTimeout(),
		ResponseHeaderTimeout: s.probeTimeout(),
	}
	return &http.Client{
		Transport: tr,
		// Redirects are reported, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// get performs "GET path" and fills the facts (for "/") or the extra answer.
func (s *Scanner) get(ctx context.Context, f *Facts, scheme, path string) error {
	cl := s.client(f.IP, f.Port)
	defer cl.CloseIdleConnections()
	u := scheme + "://" + net.JoinHostPort(f.IP.String(), strconv.Itoa(f.Port)) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", s.userAgent())
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.5")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	max := int64(BodyMax)
	if path != "/" {
		max = extraBodyMax
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, max))
	if path != "/" {
		f.Extra[path] = Extra{Status: resp.StatusCode, Location: resp.Header.Get("Location"), Body: string(body)}
		return nil
	}
	f.Proto, f.Status = scheme, resp.StatusCode
	f.Server = resp.Header.Get("Server")
	f.Location = resp.Header.Get("Location")
	f.Type = resp.Header.Get("Content-Type")
	f.Headers = resp.Header
	f.Body = string(body)
	f.Title = parseTitle(f.Body)
	f.Cookies = f.Cookies[:0]
	for _, c := range resp.Cookies() {
		f.Cookies = append(f.Cookies, c.Name)
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		f.Cert = certInfo(resp.TLS.PeerCertificates[0])
	}
	return nil
}

func (s *Scanner) userAgent() string {
	if s.UserAgent != "" {
		return s.UserAgent
	}
	return "Hestia (network inventory)"
}

func certInfo(c *x509.Certificate) *CertInfo {
	ci := &CertInfo{CN: c.Subject.CommonName, NotAfter: c.NotAfter.UTC(), SAN: []string{}}
	ci.SAN = append(ci.SAN, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		ci.SAN = append(ci.SAN, ip.String())
	}
	ci.Issuer = c.Issuer.CommonName
	if ci.Issuer == "" && len(c.Issuer.Organization) > 0 {
		ci.Issuer = c.Issuer.Organization[0]
	}
	ci.SelfSigned = bytes.Equal(c.RawSubject, c.RawIssuer)
	return ci
}

// banner reads what the server says first (up to 256 bytes, nothing is sent).
func (s *Scanner) banner(ctx context.Context, f *Facts) {
	conn, err := s.Dialer.DialContext(ctx, f.IP, f.Port)
	if err != nil {
		return
	}
	defer conn.Close()
	deadline := time.Now().Add(s.bannerTimeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, BannerMax)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	if n <= 0 {
		return
	}
	f.Banner = cleanBanner(buf[:n])
	if strings.HasPrefix(f.Banner, "SSH-") {
		f.Proto = ProtoSSH
	} else {
		f.Proto = ProtoBanner
	}
}

// cleanBanner keeps the first line and drops control and non-ASCII bytes.
func cleanBanner(b []byte) string {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 && i > 0 {
		b = b[:i]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
}

// followups requests the extra paths a preliminary match asks for (at most 2).
func (s *Scanner) followups(ctx context.Context, f *Facts) {
	if f.Proto != "http" && f.Proto != "https" {
		return
	}
	for _, p := range extraPaths(f) {
		if ctx.Err() != nil {
			return
		}
		_ = s.get(ctx, f, f.Proto, p)
	}
}
