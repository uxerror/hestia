package netscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeNet is a Dialer that never leaves the machine: (ip, port) pairs are
// mapped to local listeners; the rest is refused (alive hosts) or silent.
type fakeNet struct {
	mu     sync.Mutex
	routes map[string]string // "10.10.10.5:22" → "127.0.0.1:41234"
	alive  map[netip.Addr]bool
	dials  int
}

func newFakeNet() *fakeNet {
	return &fakeNet{routes: map[string]string{}, alive: map[netip.Addr]bool{}}
}

func key(ip netip.Addr, port int) string { return ip.String() + ":" + strconv.Itoa(port) }

func (f *fakeNet) route(ip string, port int, local string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[ip+":"+strconv.Itoa(port)] = local
	f.alive[netip.MustParseAddr(ip)] = true
}

func (f *fakeNet) unroute(ip string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, ip+":"+strconv.Itoa(port))
}

func (f *fakeNet) DialContext(ctx context.Context, ip netip.Addr, port int) (net.Conn, error) {
	f.mu.Lock()
	f.dials++
	local, ok := f.routes[key(ip, port)]
	alive := f.alive[ip]
	f.mu.Unlock()
	if ok {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", local)
	}
	if alive { // a live host with a closed port answers with RST
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	<-ctx.Done() // a dead address: no answer
	return nil, ctx.Err()
}

// fakeARP is a neighbour table with fixed content.
type fakeARP struct {
	table map[netip.Addr]string
	local bool
	err   error
}

func (a fakeARP) Table() (map[netip.Addr]string, error) { return a.table, a.err }
func (a fakeARP) Local(netip.Prefix) bool               { return a.local }

type fakeResolver map[string][]string

func (r fakeResolver) LookupAddr(_ context.Context, ip netip.Addr) ([]string, error) {
	if n, ok := r[ip.String()]; ok {
		return n, nil
	}
	return nil, errors.New("no such host")
}

// ---- fixtures ----

type fxHTTP struct {
	IP       string     `json:"ip"`
	Port     int        `json:"port"`
	Scheme   string     `json:"scheme"`
	Path     string     `json:"path"`
	Status   int        `json:"status"`
	Headers  [][]string `json:"headers"`
	Body     string     `json:"body"`
	CertText string     `json:"cert_text"`
	Error    string     `json:"error"`
}

type fxSSH struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

type fixtures struct {
	HTTP []fxHTTP `json:"http"`
	SSH  []fxSSH  `json:"ssh"`
}

func loadFixtures(t testing.TB) fixtures {
	t.Helper()
	b, err := os.ReadFile("testdata/banners.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx fixtures
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	return fx
}

var (
	reCertCN  = regexp.MustCompile(`CN=([^,\n]+)`)
	reCertDNS = regexp.MustCompile(`DNS:([^,\s]+)`)
)

// makeCert builds the certificate described by openssl's output in the
// fixture: the subject CN, the SAN names and the issuer (self-signed if the
// issuer line equals the subject line).
func makeCert(t testing.TB, certText string) tls.Certificate {
	t.Helper()
	var subj, iss string
	for _, ln := range strings.Split(certText, "\n") {
		switch {
		case strings.HasPrefix(ln, "subject="):
			subj = strings.TrimPrefix(ln, "subject=")
		case strings.HasPrefix(ln, "issuer="):
			iss = strings.TrimPrefix(ln, "issuer=")
		}
	}
	cn := ""
	if m := reCertCN.FindStringSubmatch(subj); m != nil {
		cn = m[1]
	}
	var dns []string
	for _, m := range reCertDNS.FindAllStringSubmatch(certText, -1) {
		dns = append(dns, m[1])
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Date(2037, 7, 26, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := tpl, key
	if iss != subj {
		icn := ""
		if m := reCertCN.FindStringSubmatch(iss); m != nil {
			icn = m[1]
		}
		ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: icn}, NotBefore: tpl.NotBefore, NotAfter: tpl.NotAfter,
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		parent, signer = ca, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startFixtureServers serves the recorded answers on local ports and maps
// the original (ip, port) pairs to them in the returned Dialer.
func startFixtureServers(t testing.TB, fx fixtures) *fakeNet {
	t.Helper()
	fn := newFakeNet()
	type ep struct {
		ip   string
		port int
	}
	groups := map[ep][]fxHTTP{}
	for _, h := range fx.HTTP {
		groups[ep{h.IP, h.Port}] = append(groups[ep{h.IP, h.Port}], h)
	}
	for k, list := range groups {
		first := list[0]
		if first.Error != "" { // recorded as a timeout: accepts and never answers
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			t.Cleanup(func() { close(done); ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() { <-done; c.Close() }()
				}
			}()
			fn.route(k.ip, k.port, ln.Addr().String())
			continue
		}
		list := list
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, e := range list {
				if e.Path != r.URL.Path || e.Error != "" {
					continue
				}
				for _, kv := range e.Headers {
					switch strings.ToLower(kv[0]) {
					case "content-length", "transfer-encoding", "connection", "keep-alive", "date":
						continue
					}
					w.Header().Add(kv[0], kv[1])
				}
				w.WriteHeader(e.Status)
				_, _ = w.Write([]byte(e.Body))
				return
			}
			http.NotFound(w, r)
		})
		srv := httptest.NewUnstartedServer(handler)
		srv.EnableHTTP2 = false
		if first.Scheme == "https" {
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{makeCert(t, first.CertText)}}
			srv.StartTLS()
		} else {
			srv.Start()
		}
		t.Cleanup(srv.Close)
		fn.route(k.ip, k.port, srv.Listener.Addr().String())
	}
	for _, s := range fx.SSH {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		banner := s.Banner
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte(banner))
				go func() { time.Sleep(2 * time.Second); c.Close() }()
			}
		}()
		fn.route(s.IP, s.Port, ln.Addr().String())
	}
	return fn
}

// listenBanner starts a listener that greets with banner (or stays silent).
func listenBanner(t testing.TB, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				_, _ = c.Write([]byte(banner))
			}
			go func() { time.Sleep(time.Second); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

type (
	netipAddr = netip.Addr
	netConn   = net.Conn
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
