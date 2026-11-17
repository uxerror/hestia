// Package sshx is a small SSH client: password or key login, host key
// pinning (TOFU), and command execution with timeouts and output limits.
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DialTimeout bounds connect + handshake.
const DialTimeout = 10 * time.Second

// DefaultExecTimeout applies to Exec when the context has no deadline.
const DefaultExecTimeout = 30 * time.Second

// MaxOutput caps captured stdout and stderr (each).
const MaxOutput = 1 << 20

// Error kinds; messages are shown to the user as is.
var (
	ErrAuth    = errors.New("доступ запрещён: неверный пароль или ключ")
	ErrTimeout = errors.New("превышено время ожидания (10 с)")
	ErrResolve = errors.New("адрес не найден (не резолвится)")
	ErrConnect = errors.New("не удалось подключиться")
)

// HostKeyChangedError is returned when the server key differs from the pinned one.
type HostKeyChangedError struct{ Host, Expected, Got string }

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("отпечаток SSH-ключа сервера %s изменился (был %s, стал %s): подключение отклонено", e.Host, e.Expected, e.Got)
}

// Config describes a connection. Exactly one of Password and Signer is used
// (Signer wins if both are set).
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Signer   ssh.Signer
	// ExpectedFP pins the server host key (SHA256:…). Empty = trust on first
	// use: the key is accepted and reported by Client.HostKeyFP.
	ExpectedFP string
	// HostKeyAlgorithms restricts the host key types the client accepts
	// (empty = library default). Used with a pin of a key whose type is known,
	// so the server cannot present a different key type.
	HostKeyAlgorithms []string
}

// AlgorithmsForKeyType returns the SSH host key algorithms that verify a key
// of the given type (as in known_hosts, e.g. "ssh-rsa").
func AlgorithmsForKeyType(keyType string) []string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	case "":
		return nil
	}
	return []string{keyType}
}

// Addr returns host:port.
func (c Config) Addr() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }

// ParseKey parses a PEM private key, with an optional passphrase.
func ParseKey(pem []byte, passphrase string) (ssh.Signer, error) {
	var s ssh.Signer
	var err error
	if passphrase != "" {
		s, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	} else {
		s, err = ssh.ParsePrivateKey(pem)
	}
	if err == nil {
		return s, nil
	}
	var pm *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &pm):
		return nil, errors.New("ключ защищён парольной фразой — введите её")
	case strings.Contains(err.Error(), "decryption password incorrect"), strings.Contains(err.Error(), "bcrypt"):
		return nil, errors.New("неверная парольная фраза ключа")
	}
	return nil, errors.New("не удалось разобрать приватный ключ (нужен OpenSSH/PEM)")
}

// Client is an established SSH connection.
type Client struct {
	c      *ssh.Client
	fp     string
	cfg    Config
	done   chan struct{}
	closed sync.Once
}

// Dial connects and authenticates. Errors wrap one of the Err* values or are
// a *HostKeyChangedError.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	var gotFP string
	var mismatch *HostKeyChangedError
	var auth []ssh.AuthMethod
	if cfg.Signer != nil {
		auth = append(auth, ssh.PublicKeys(cfg.Signer))
	} else {
		pw := cfg.Password
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range ans {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	sc := &ssh.ClientConfig{
		User: cfg.User,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			gotFP = ssh.FingerprintSHA256(key)
			if cfg.ExpectedFP != "" && cfg.ExpectedFP != gotFP {
				mismatch = &HostKeyChangedError{Host: cfg.Host, Expected: cfg.ExpectedFP, Got: gotFP}
				return mismatch
			}
			return nil
		},
		HostKeyAlgorithms: cfg.HostKeyAlgorithms,
		Timeout:           DialTimeout,
	}

	dctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", cfg.Addr())
	if err != nil {
		return nil, classifyNet(ctx, err)
	}
	// The handshake gets the same overall deadline; ctx cancellation closes the conn.
	_ = conn.SetDeadline(time.Now().Add(DialTimeout))
	stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
	cc, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr(), sc)
	stopped := stop()
	if err != nil {
		_ = conn.Close()
		if mismatch != nil {
			return nil, mismatch
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !stopped || isTimeout(err) {
			return nil, ErrTimeout
		}
		if len(cfg.HostKeyAlgorithms) > 0 && strings.Contains(err.Error(), "no common algorithm for host key") {
			return nil, fmt.Errorf("%w: сервер не предложил ключ нужного типа (%s)", ErrConnect, strings.Join(cfg.HostKeyAlgorithms, ", "))
		}
		if strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "no supported methods remain") {
			return nil, ErrAuth
		}
		return nil, fmt.Errorf("%w: %v", ErrConnect, err)
	}
	_ = conn.SetDeadline(time.Time{})
	cl := &Client{c: ssh.NewClient(cc, chans, reqs), fp: gotFP, cfg: cfg, done: make(chan struct{})}
	go func() { _ = cc.Wait(); close(cl.done) }()
	return cl, nil
}

func classifyNet(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return ErrResolve
	}
	if isTimeout(err) {
		return ErrTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	switch {
	case strings.Contains(err.Error(), "connection refused"):
		return fmt.Errorf("%w: соединение отклонено (порт закрыт?)", ErrConnect)
	case strings.Contains(err.Error(), "no route to host"), strings.Contains(err.Error(), "network is unreachable"):
		return fmt.Errorf("%w: нет маршрута до хоста", ErrConnect)
	}
	return fmt.Errorf("%w: %v", ErrConnect, err)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// HostKeyFP is the SHA256 fingerprint of the key the server presented.
func (c *Client) HostKeyFP() string { return c.fp }

// Config returns the connection parameters.
func (c *Client) Config() Config { return c.cfg }

// Alive reports whether the connection is still open.
func (c *Client) Alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// Close closes the connection.
func (c *Client) Close() error {
	var err error
	c.closed.Do(func() { err = c.c.Close() })
	return err
}

// Result is the outcome of a command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// ExitError is returned by Exec for a non-zero exit status.
type ExitError struct {
	Cmd    string
	Result Result
}

func (e *ExitError) Error() string {
	msg := strings.TrimSpace(e.Result.Stderr)
	if msg == "" {
		msg = strings.TrimSpace(e.Result.Stdout)
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return fmt.Sprintf("команда завершилась с кодом %d: %s", e.Result.ExitCode, msg)
}

// Exec runs cmd (via the remote login shell) with optional stdin. A non-zero
// exit status yields *ExitError alongside the Result. Without a context
// deadline DefaultExecTimeout applies.
func (c *Client) Exec(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultExecTimeout)
		defer cancel()
	}
	sess, err := c.c.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("SSH-сессия: %w", err)
	}
	defer sess.Close()
	var out, errb limitedBuffer
	sess.Stdout, sess.Stderr = &out, &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	if err := sess.Start(cmd); err != nil {
		return Result{}, fmt.Errorf("запуск команды: %w", err)
	}
	waitc := make(chan error, 1)
	go func() { waitc <- sess.Wait() }()
	select {
	case err = <-waitc:
	case <-ctx.Done():
		_ = sess.Close()
		return Result{Stdout: out.String(), Stderr: errb.String()}, fmt.Errorf("команда прервана: %w", ctx.Err())
	}
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if err == nil {
		return res, nil
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitStatus()
		return res, &ExitError{Cmd: cmd, Result: res}
	}
	return res, err
}

// limitedBuffer keeps at most MaxOutput bytes and silently drops the rest.
type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := MaxOutput - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var _ io.Writer = (*limitedBuffer)(nil)
