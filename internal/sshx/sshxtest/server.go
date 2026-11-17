// Package sshxtest is an in-process SSH server for tests. It listens on
// 127.0.0.1 only and runs commands through a caller-supplied handler.
package sshxtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Handler runs one command. stdin is everything the client sent.
type Handler func(user, cmd string, stdin []byte) (stdout, stderr string, exit int)

// Server is a fake SSH server.
type Server struct {
	Addr string // 127.0.0.1:port
	Host string
	Port int

	// PasswordAuth and KeyAuth decide logins; nil means "deny".
	PasswordAuth func(user, password string) bool
	KeyAuth      func(user string, key ssh.PublicKey) bool
	Handler      Handler

	mu      sync.Mutex
	signers []ssh.Signer // the first one is the preferred (default) host key
	ln      net.Listener
	conns   []net.Conn
}

// New starts a server with a fresh host key; it is stopped on test cleanup.
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{}
	s.SetHostKey(NewSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	s.Addr = ln.Addr().String()
	s.Host = "127.0.0.1"
	s.Port = ln.Addr().(*net.TCPAddr).Port
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// NewSigner generates an ed25519 signer.
func NewSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

// NewRSASigner generates a (small, test-only) RSA signer.
func NewRSASigner(t testing.TB) ssh.Signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

// SetHostKey replaces all host keys for new connections with sg.
func (s *Server) SetHostKey(sg ssh.Signer) {
	s.mu.Lock()
	s.signers = []ssh.Signer{sg}
	s.mu.Unlock()
}

// AddHostKey makes the server offer one more host key (after the existing
// ones), like a real sshd with several key types. A client picks by its
// HostKeyAlgorithms preference.
func (s *Server) AddHostKey(sg ssh.Signer) {
	s.mu.Lock()
	s.signers = append(s.signers, sg)
	s.mu.Unlock()
}

// HostKeyFP returns the fingerprint of the preferred (first) host key.
func (s *Server) HostKeyFP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ssh.FingerprintSHA256(s.signers[0].PublicKey())
}

// HasHostKeyFP reports whether fp is the fingerprint of one of the host keys.
// (With several keys the one a client sees depends on its algorithm order.)
func (s *Server) HasHostKeyFP(fp string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sg := range s.signers {
		if ssh.FingerprintSHA256(sg.PublicKey()) == fp {
			return true
		}
	}
	return false
}

// HostKeyOf returns the host key of the given type (e.g. "ssh-rsa"), or nil.
func (s *Server) HostKeyOf(keyType string) ssh.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sg := range s.signers {
		if sg.PublicKey().Type() == keyType {
			return sg.PublicKey()
		}
	}
	return nil
}

// Close stops the server and drops connections.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.handle(c)
	}
}

func (s *Server) handle(nc net.Conn) {
	defer nc.Close()
	s.mu.Lock()
	signers := append([]ssh.Signer(nil), s.signers...)
	s.mu.Unlock()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if s.PasswordAuth != nil && s.PasswordAuth(c.User(), string(pw)) {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if s.KeyAuth != nil && s.KeyAuth(c.User(), k) {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
	}
	for _, sg := range signers {
		cfg.AddHostKey(sg)
	}
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		go s.session(conn.User(), ch)
	}
}

func (s *Server) session(user string, nch ssh.NewChannel) {
	ch, reqs, err := nch.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var p struct{ Cmd string }
		if ssh.Unmarshal(req.Payload, &p) != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		stdin, _ := io.ReadAll(ch) // clients without stdin send EOF immediately
		var out, errOut string
		code := 0
		if s.Handler != nil {
			out, errOut, code = s.Handler(user, p.Cmd, bytes.Clone(stdin))
		} else {
			errOut, code = "no handler", 127
		}
		_, _ = io.WriteString(ch, out)
		_, _ = io.WriteString(ch.Stderr(), errOut)
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(code)}))
		return
	}
}

// Port string helper for tests.
func (s *Server) PortString() string { return strconv.Itoa(s.Port) }
