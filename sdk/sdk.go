package sdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/uxerror/hestia/sdk/rpc"
)

// Plugin is what a plugin implements. Every method gets the Host through
// HostFrom(ctx).
type Plugin interface {
	// Validate checks a configuration; nil or empty means it is fine.
	Validate(ctx context.Context, cfg Config) []FieldError
	// Plan describes what create/update/remove would do without changing
	// anything.
	Plan(ctx context.Context, req PlanRequest) (Plan, error)
	// Apply carries out a plan the user confirmed; steps and log go through
	// job. It has no overall timeout; ctx ends when Hestia cancels the job.
	Apply(ctx context.Context, req ApplyRequest, job *Job) error
	// Status reports the health of an instance.
	Status(ctx context.Context, inst Instance) (Status, error)
}

// Environment of a plugin process.
const (
	// EnvSocket is the unix socket of Hestia (production, systemd unit).
	EnvSocket = "HESTIA_SOCKET"
	// EnvToken carries the token in dev mode (stdin/stdout transport).
	EnvToken = "HESTIA_PLUGIN_TOKEN"
	// EnvCredentials is set by systemd (LoadCredential=token:...).
	EnvCredentials = "CREDENTIALS_DIRECTORY"
)

// HelloTimeout bounds the handshake.
const HelloTimeout = 20 * time.Second

type hostKey struct{}

// HostFrom returns the Hestia API client of the current call.
func HostFrom(ctx context.Context) *Host {
	h, _ := ctx.Value(hostKey{}).(*Host)
	return h
}

// Serve runs the plugin until Hestia disconnects; it never returns. The
// transport comes from the environment: HESTIA_SOCKET plus the systemd
// credential "token" in production, stdin/stdout plus HESTIA_PLUGIN_TOKEN in
// dev mode (hestia serve --plugin-dev).
func Serve(manifest []byte, p Plugin) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rwc, token, dev, err := connect(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hestia plugin:", err)
		os.Exit(2)
	}
	err = Run(ctx, manifest, p, rwc, token)
	switch {
	case ctx.Err() != nil:
		os.Exit(0)
	case err == nil || (dev && errors.Is(err, io.EOF)):
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "hestia plugin:", err)
	os.Exit(1)
}

func connect(ctx context.Context) (io.ReadWriteCloser, string, bool, error) {
	if sock := os.Getenv(EnvSocket); sock != "" {
		dir := os.Getenv(EnvCredentials)
		if dir == "" {
			return nil, "", false, errors.New("нет $CREDENTIALS_DIRECTORY с токеном")
		}
		tok, err := os.ReadFile(filepath.Join(dir, "token"))
		if err != nil {
			return nil, "", false, fmt.Errorf("токен: %w", err)
		}
		// The socket may appear a little later than the plugin starts.
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var d net.Dialer
		for {
			c, err := d.DialContext(dctx, "unix", sock)
			if err == nil {
				return c, strings.TrimSpace(string(tok)), false, nil
			}
			select {
			case <-dctx.Done():
				return nil, "", false, fmt.Errorf("сокет Hestia %s: %w", sock, err)
			case <-time.After(time.Second):
			}
		}
	}
	if tok := os.Getenv(EnvToken); tok != "" {
		return stdio{}, tok, true, nil
	}
	return nil, "", false, errors.New("это плагин Hestia: его запускает Hestia (нет HESTIA_SOCKET или HESTIA_PLUGIN_TOKEN)")
}

type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error {
	_ = os.Stdin.Close()
	return os.Stdout.Close()
}

// Run serves the plugin over rwc: handshake, then requests until the
// connection ends (the error says why; io.EOF for a clean disconnect) or ctx
// is cancelled. Serve uses it; tests may call it directly.
func Run(ctx context.Context, manifest []byte, p Plugin, rwc io.ReadWriteCloser, token string) error {
	m, err := ParseManifest(manifest)
	if err != nil {
		return err
	}
	srv := &server{manifest: json.RawMessage(manifest), p: p}
	conn := rpc.New(rwc, srv.handle, rpc.Options{})
	defer conn.Close()
	srv.host = &Host{conn: conn}
	conn.Start()

	hctx, cancel := context.WithTimeout(ctx, HelloTimeout)
	var w Welcome
	err = conn.Call(hctx, MethodHello, Hello{Protocol: Protocol, ID: m.ID, Version: m.Version, Token: token}, &w)
	cancel()
	if err != nil {
		return fmt.Errorf("рукопожатие: %w", err)
	}
	srv.host.setWelcome(w)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.Done():
		if err := conn.Err(); err != nil {
			return err
		}
		return io.EOF
	}
}

type server struct {
	manifest json.RawMessage
	p        Plugin
	host     *Host
}

func (s *server) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	ctx = context.WithValue(ctx, hostKey{}, s.host)
	switch method {
	case MethodManifest:
		return s.manifest, nil
	case MethodValidate:
		var req struct {
			Config Config `json:"config"`
		}
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		errs := s.p.Validate(ctx, req.Config)
		if errs == nil {
			errs = []FieldError{}
		}
		return errs, nil
	case MethodPlan:
		var req PlanRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		pl, err := s.p.Plan(ctx, req)
		if err != nil {
			return nil, err
		}
		if pl.Actions == nil {
			pl.Actions = []Action{}
		}
		if pl.Warnings == nil {
			pl.Warnings = []string{}
		}
		return pl, nil
	case MethodApply:
		var req ApplyRequest
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		job := &Job{ID: req.JobID, host: s.host, ctx: ctx}
		if err := s.p.Apply(ctx, req, job); err != nil {
			job.closeOpen(err)
			return nil, err
		}
		job.closeOpen(nil)
		return struct{}{}, nil
	case MethodStatus:
		var req struct {
			Instance Instance `json:"instance"`
		}
		if err := decode(params, &req); err != nil {
			return nil, err
		}
		st, err := s.p.Status(ctx, req.Instance)
		if err != nil {
			return nil, err
		}
		if st.Endpoints == nil {
			st.Endpoints = []Endpoint{}
		}
		return st, nil
	}
	return nil, rpc.Errorf(rpc.CodeMethodNotFound, "метод %s не поддерживается", method)
}

func decode(params json.RawMessage, v any) error {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, v); err != nil {
		return rpc.Errorf(rpc.CodeInvalidParams, "неверные параметры: %v", err)
	}
	return nil
}

// Host is the client of the Hestia API.
type Host struct {
	conn *rpc.Conn

	mu      sync.Mutex
	welcome Welcome
}

// NewHost wraps a connection (used by sdktest).
func NewHost(c *rpc.Conn) *Host { return &Host{conn: c} }

func (h *Host) setWelcome(w Welcome) {
	h.mu.Lock()
	h.welcome = w
	h.mu.Unlock()
}

// Welcome returns Hestia's answer to hello (version, instances at connect).
func (h *Host) Welcome() Welcome {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.welcome
}

// Call invokes any Hestia method (for methods without a typed wrapper).
func (h *Host) Call(ctx context.Context, method string, params, result any) error {
	return h.conn.Call(ctx, method, params, result)
}

// Targets lists the targets granted to an instance (needs targets.read).
func (h *Host) Targets(ctx context.Context, instance int64) ([]TargetInfo, error) {
	var out []TargetInfo
	err := h.conn.Call(ctx, MethodTargetList, InstanceRef{Instance: instance}, &out)
	return out, err
}

// Exec runs a command as root on a granted target (needs targets.exec). A
// non-zero exit code is not an error: check ExecResult.Code.
func (h *Host) Exec(ctx context.Context, req ExecRequest) (ExecResult, error) {
	var out ExecResult
	call := h.conn.Call
	if req.TimeoutS > int(rpc.DefaultTimeout/time.Second)-5 {
		call = h.conn.CallNoTimeout // Hestia enforces timeout_s itself
	}
	err := call(ctx, MethodTargetExec, req, &out)
	return out, err
}

// PutFile writes a file on a granted target (needs targets.exec).
func (h *Host) PutFile(ctx context.Context, instance int64, target, path string, data []byte, mode fs.FileMode) error {
	return h.conn.Call(ctx, MethodTargetPut, PutFileRequest{
		Instance: instance, Target: target, Path: path,
		DataB64: base64.StdEncoding.EncodeToString(data), Mode: fmt.Sprintf("%04o", mode.Perm()),
	}, nil)
}

// SecretPut stores a secret of the instance (encrypted by Hestia).
func (h *Host) SecretPut(ctx context.Context, instance int64, name, value string) error {
	return h.conn.Call(ctx, MethodSecretPut, SecretRequest{Instance: instance, Name: name, Value: value}, nil)
}

// SecretGet reads a secret of the instance; ok is false if it does not exist.
func (h *Host) SecretGet(ctx context.Context, instance int64, name string) (string, bool, error) {
	var v SecretValue
	err := h.conn.Call(ctx, MethodSecretGet, SecretRequest{Instance: instance, Name: name}, &v)
	return v.Value, v.Exists, err
}

// SecretDelete removes a secret of the instance (missing is fine).
func (h *Host) SecretDelete(ctx context.Context, instance int64, name string) error {
	return h.conn.Call(ctx, MethodSecretDelete, SecretRequest{Instance: instance, Name: name}, nil)
}

// Inventory returns hosts, services and guests (needs inventory.read).
func (h *Host) Inventory(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	err := h.conn.Call(ctx, MethodInventoryGet, struct{}{}, &out)
	return out, err
}

// DeployPlan asks what deploying a compose project on a granted target
// would do (needs deploy.docker). It changes nothing.
func (h *Host) DeployPlan(ctx context.Context, req DeployRequest) (DeployPlan, error) {
	var out DeployPlan
	err := h.conn.Call(ctx, MethodDeployPlan, req, &out)
	return out, err
}

// DeployUp deploys the project within the apply job req.JobID: Docker,
// container features, files, `docker compose up`, wait until running; on a
// failure Hestia rolls the project back. Hestia adds its own job steps, so
// do not wrap the call in Job.Step/Run. It has no overall timeout.
func (h *Host) DeployUp(ctx context.Context, req DeployRequest) (DeployStatus, error) {
	var out DeployStatus
	err := h.conn.CallNoTimeout(ctx, MethodDeployUp, req, &out)
	return out, err
}

// DeployDown stops and removes the project and its directory (steps go to
// the job, like DeployUp).
func (h *Host) DeployDown(ctx context.Context, req DeployDownRequest) error {
	return h.conn.CallNoTimeout(ctx, MethodDeployDown, req, nil)
}

// DeployStatus returns the containers of the project.
func (h *Host) DeployStatus(ctx context.Context, req DeployStatusRequest) (DeployStatus, error) {
	var out DeployStatus
	err := h.conn.Call(ctx, MethodDeployStatus, req, &out)
	return out, err
}

// Log writes a line to the plugin's system log in Hestia (level: info,
// warn, error). Errors are ignored.
func (h *Host) Log(ctx context.Context, level, line string) {
	_ = h.conn.Call(ctx, MethodLog, LogLine{Level: level, Line: line}, nil)
}

// Job reports progress of an apply job: steps (one at a time) and log lines.
type Job struct {
	ID   string
	host *Host
	ctx  context.Context

	mu   sync.Mutex
	open bool
}

// Host returns the Hestia API client.
func (j *Job) Host() *Host { return j.host }

// Step starts a step (closing the previous one as done).
func (j *Job) Step(title string) error {
	j.closeOpen(nil)
	if err := j.host.conn.Call(j.ctx, MethodJobStep, JobStep{JobID: j.ID, Title: title}, nil); err != nil {
		return err
	}
	j.mu.Lock()
	j.open = true
	j.mu.Unlock()
	return nil
}

// Done closes the current step: as failed when err is not nil.
func (j *Job) Done(err error) error {
	j.mu.Lock()
	open := j.open
	j.open = false
	j.mu.Unlock()
	if !open {
		return nil
	}
	p := JobStepDone{JobID: j.ID}
	if err != nil {
		p.Error = err.Error()
	}
	return j.host.conn.Call(context.WithoutCancel(j.ctx), MethodJobStepDone, p, nil)
}

func (j *Job) closeOpen(err error) { _ = j.Done(err) }

// Log adds a line to the job log (Hestia masks the instance's secrets).
func (j *Job) Log(level, line string) {
	_ = j.host.conn.Call(j.ctx, MethodJobLog, JobLog{JobID: j.ID, Level: level, Line: line}, nil)
}

// Logf is Log at level info with formatting.
func (j *Job) Logf(format string, args ...any) { j.Log("info", fmt.Sprintf(format, args...)) }

// Run is a step helper: Step(title), fn, Done(err). It returns fn's error.
func (j *Job) Run(title string, fn func(ctx context.Context) error) error {
	if err := j.Step(title); err != nil {
		return err
	}
	err := fn(j.ctx)
	if derr := j.Done(err); err == nil {
		err = derr
	}
	return err
}
