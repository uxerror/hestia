package sshx_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/sshx/sshxtest"
)

func newServer(t *testing.T) *sshxtest.Server {
	s := sshxtest.New(t)
	s.PasswordAuth = func(u, p string) bool { return u == "root" && p == "pw" }
	s.Handler = func(user, cmd string, stdin []byte) (string, string, int) {
		switch {
		case cmd == "whoami":
			return user + "\n", "", 0
		case cmd == "fail":
			return "", "boom\n", 3
		case cmd == "cat":
			return string(stdin), "", 0
		case cmd == "sleep":
			time.Sleep(5 * time.Second)
		}
		return "", "unknown", 127
	}
	return s
}

func cfg(s *sshxtest.Server) sshx.Config {
	return sshx.Config{Host: s.Host, Port: s.Port, User: "root", Password: "pw"}
}

func TestPasswordExecAndTOFU(t *testing.T) {
	s := newServer(t)
	cl, err := sshx.Dial(context.Background(), cfg(s))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cl.HostKeyFP() != s.HostKeyFP() {
		t.Fatalf("fp %q != %q", cl.HostKeyFP(), s.HostKeyFP())
	}
	r, err := cl.Exec(context.Background(), "whoami", nil)
	if err != nil || r.Stdout != "root\n" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = cl.Exec(context.Background(), "cat", []byte("hello"))
	if err != nil || r.Stdout != "hello" {
		t.Fatalf("stdin: %+v %v", r, err)
	}
	r, err = cl.Exec(context.Background(), "fail", nil)
	var ee *sshx.ExitError
	if !errors.As(err, &ee) || r.ExitCode != 3 || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestWrongPasswordIsAuthError(t *testing.T) {
	s := newServer(t)
	c := cfg(s)
	c.Password = "nope"
	if _, err := sshx.Dial(context.Background(), c); !errors.Is(err, sshx.ErrAuth) {
		t.Fatalf("got %v", err)
	}
}

func TestKeyAuth(t *testing.T) {
	s := newServer(t)
	signer := sshxtest.NewSigner(t)
	s.KeyAuth = func(u string, k ssh.PublicKey) bool {
		return string(k.Marshal()) == string(signer.PublicKey().Marshal())
	}
	cl, err := sshx.Dial(context.Background(), sshx.Config{Host: s.Host, Port: s.Port, User: "root", Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	cl.Close()
	other := sshxtest.NewSigner(t)
	if _, err := sshx.Dial(context.Background(), sshx.Config{Host: s.Host, Port: s.Port, User: "root", Signer: other}); !errors.Is(err, sshx.ErrAuth) {
		t.Fatalf("got %v", err)
	}
}

func TestPinnedHostKey(t *testing.T) {
	s := newServer(t)
	c := cfg(s)
	c.ExpectedFP = s.HostKeyFP()
	cl, err := sshx.Dial(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	cl.Close()

	old := s.HostKeyFP()
	s.SetHostKey(sshxtest.NewSigner(t))
	_, err = sshx.Dial(context.Background(), c)
	var hk *sshx.HostKeyChangedError
	if !errors.As(err, &hk) || hk.Expected != old || hk.Got != s.HostKeyFP() {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "изменился") {
		t.Fatal(err)
	}
}

func TestConnectionRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	_, err := sshx.Dial(context.Background(), sshx.Config{Host: "127.0.0.1", Port: port, User: "root", Password: "x"})
	if !errors.Is(err, sshx.ErrConnect) || !strings.Contains(err.Error(), "порт закрыт") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveError(t *testing.T) {
	_, err := sshx.Dial(context.Background(), sshx.Config{Host: "no-such-host.invalid", Port: 22, User: "root", Password: "x"})
	if !errors.Is(err, sshx.ErrResolve) {
		t.Fatalf("got %v", err)
	}
}

func TestExecTimeoutAndCancel(t *testing.T) {
	s := newServer(t)
	cl, err := sshx.Dial(context.Background(), cfg(s))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = cl.Exec(ctx, "sleep", nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 3*time.Second {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
}

func TestHandshakeTimeoutOnSilentServer(t *testing.T) {
	// A listener that accepts but never speaks SSH: the dial must give up by ctx.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := sshx.Dial(ctx, sshx.Config{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "root", Password: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseKey(t *testing.T) {
	if _, err := sshx.ParseKey([]byte("garbage"), ""); err == nil || !strings.Contains(err.Error(), "приватный ключ") {
		t.Fatalf("got %v", err)
	}
}

func TestRSAHostKeyPinWithRestrictedAlgorithms(t *testing.T) {
	s := newServer(t)
	rsaKey := sshxtest.NewRSASigner(t)
	s.AddHostKey(rsaKey) // ed25519 stays the first key
	fp := ssh.FingerprintSHA256(rsaKey.PublicKey())

	c := cfg(s)
	c.ExpectedFP = fp
	c.HostKeyAlgorithms = sshx.AlgorithmsForKeyType("ssh-rsa")
	if got := strings.Join(c.HostKeyAlgorithms, ","); got != "rsa-sha2-512,rsa-sha2-256" {
		t.Fatalf("algorithms %q", got)
	}
	cl, err := sshx.Dial(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if cl.HostKeyFP() != fp {
		t.Fatalf("fp %q", cl.HostKeyFP())
	}
	cl.Close()

	// A different RSA key is a changed key.
	s.SetHostKey(sshxtest.NewRSASigner(t))
	var hk *sshx.HostKeyChangedError
	if _, err := sshx.Dial(context.Background(), c); !errors.As(err, &hk) {
		t.Fatalf("got %v", err)
	}

	// A server with no RSA key cannot be reached with RSA-only algorithms,
	// whatever other keys (even a "right-looking" ed25519 one) it offers.
	s.SetHostKey(sshxtest.NewSigner(t))
	_, err = sshx.Dial(context.Background(), c)
	if !errors.Is(err, sshx.ErrConnect) || !strings.Contains(err.Error(), "rsa-sha2-512") {
		t.Fatalf("got %v", err)
	}
}

func TestAlgorithmsForKeyType(t *testing.T) {
	if sshx.AlgorithmsForKeyType("") != nil {
		t.Fatal("empty type must not restrict")
	}
	if got := sshx.AlgorithmsForKeyType("ssh-ed25519"); len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Fatalf("%v", got)
	}
}
