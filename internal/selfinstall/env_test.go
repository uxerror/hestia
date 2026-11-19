package selfinstall_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/sshx/sshxtest"
	"github.com/uxerror/hestia/internal/store"
)

func ctxBG() context.Context { return context.Background() }

const testVersion = "v-test"

var fakeBinary = bytes.Repeat([]byte("FAKE-HESTIA-BINARY\n"), 50)

type env struct {
	t      *testing.T
	dir    string
	st     *store.Store
	sec    *secrets.Service
	runner *jobs.Runner
	gate   *selfinstall.Gate
	svc    *selfinstall.Service
	pve    *fakePVE
	ssh    *sshxtest.Server
	node   *nodeHandler
	tgt    store.Target
	userID int64

	healthURL    string
	forceID      string
	noController bool
	duringXfer   []bool // gate.Transferring() observed when the controller started
	ctrl         *fakeController
}

// newEnv builds a local controller (store, secrets, runner), a fake Proxmox
// API and a fake SSH node, and connects them as a Proxmox target.
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), gate: &selfinstall.Gate{}}
	var err error
	if e.st, err = store.Open(e.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.st.Close() })
	if e.sec, err = secrets.Open(e.st, e.dir); err != nil {
		t.Fatal(err)
	}
	id, err := e.sec.EnsureIdentity(ctxBG(), "pc")
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.st.CreateFirstUser(ctxBG(), "admin", "hash")
	if err != nil {
		t.Fatal(err)
	}
	e.userID = u.ID
	if _, err := e.st.EnsureInstanceID(ctxBG()); err != nil {
		t.Fatal(err)
	}
	e.runner, err = jobs.NewRunner(context.Background(), e.st)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.runner.Shutdown)

	e.pve = newFakePVE(t)
	e.node = newNodeHandler(t)
	e.node.newCT = func(vmid int) *fakeMachine { return e.newCT() }
	e.pve.onCreate = e.node.addCT
	e.ssh = sshxtest.New(t)
	want := ssh.FingerprintSHA256(id.Signer.PublicKey())
	e.ssh.KeyAuth = func(user string, k ssh.PublicKey) bool { return user == "root" && ssh.FingerprintSHA256(k) == want }
	e.ssh.Handler = e.node.handle

	ref, err := e.sec.Put(ctxBG(), secrets.PurposeAPIToken, []byte(apiSecret))
	if err != nil {
		t.Fatal(err)
	}
	e.tgt = store.Target{Kind: store.KindProxmox, Name: "home", Host: "127.0.0.1", Port: e.ssh.Port, SSHUser: "root",
		HostKeyFP: e.ssh.HostKeyFP(), APICertFP: e.pve.fp, Cluster: "home", TokenID: proxmox.TokenID, TokenSecretRef: ref,
		Nodes: []store.Node{{Name: "pve1", IP: "127.0.0.1", Online: true, HostKeyFP: e.ssh.HostKeyFP(), HostKeyType: "ssh-ed25519"}}}
	if err := e.st.CreateTarget(ctxBG(), &e.tgt); err != nil {
		t.Fatal(err)
	}

	e.svc = (&selfinstall.Service{
		Store: e.st, Secrets: e.sec, Runner: e.runner, Identity: id, Gate: e.gate, DataDir: e.dir, Version: testVersion,
		APIPort: e.pve.port, Binary: func() ([]byte, error) { return fakeBinary, nil },
		HealthBase: func(string, int) string {
			if e.healthURL == "" {
				return "http://127.0.0.1:1"
			}
			return e.healthURL
		},
		PollInterval: 5 * time.Millisecond, IPTimeout: time.Second, HealthTimeout: 600 * time.Millisecond,
		HTTP: &http.Client{Timeout: time.Second},
	}).Init()
	return e
}

// newCT is a fresh container made of the Debian template: empty machine-id,
// no SSH host keys.
func (e *env) newCT() *fakeMachine {
	m := newMachine(e.t, testVersion)
	m.files["/etc/machine-id"] = []byte("")
	m.startHook = e.startController(m)
	return m
}

func (e *env) startController(m *fakeMachine) func(*fakeMachine) {
	return func(*fakeMachine) {
		e.duringXfer = append(e.duringXfer, e.gate.Transferring())
		if e.noController {
			return
		}
		if c := m.bootController(e.forceID); c != nil {
			e.ctrl = c
			e.healthURL = c.srv.URL
		}
	}
}

func (e *env) probe(req selfinstall.ProbeRequest) (*selfinstall.ProbeResult, error) {
	req.TargetID = e.tgt.ID
	return e.svc.Probe(ctxBG(), req)
}

func (e *env) mustProbe(req selfinstall.ProbeRequest) *selfinstall.ProbeResult {
	e.t.Helper()
	res, err := e.probe(req)
	if err != nil {
		e.t.Fatalf("probe: %v", err)
	}
	return res
}

type outcome struct {
	status string
	err    string
	result any
	logs   []string
	steps  map[string]string // title → last status
}

// finish starts the job for a probe and collects its events until the end.
func (e *env) install(res *selfinstall.ProbeResult) outcome {
	e.t.Helper()
	job, err := e.svc.Start(ctxBG(), res.ProbeID, e.userID)
	if err != nil {
		e.t.Fatalf("start: %v", err)
	}
	return e.collect(job)
}

func (e *env) collect(job store.Job) outcome {
	ch, cancel := e.runner.Hub().Subscribe(job.ID)
	defer cancel()
	out := outcome{steps: map[string]string{}}
	timeout := time.After(30 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				e.t.Fatal("event stream dropped")
			}
			switch d := ev.Data.(type) {
			case store.LogLine:
				out.logs = append(out.logs, d.Line)
			case jobs.StepEvent:
				out.steps[d.Title] = d.Status
			case jobs.StatusEvent:
				if store.IsFinal(d.Status) {
					out.status, out.err, out.result = d.Status, d.Error, d.Result
					e.runner.Wait()
					return out
				}
			}
		case <-timeout:
			e.t.Fatal("job did not finish")
		}
	}
}

func (o outcome) result_() selfinstall.Result {
	r, _ := o.result.(selfinstall.Result)
	return r
}

// noSecrets fails if a log line carries a secret.
func (e *env) noSecrets(logs []string, extra ...string) {
	e.t.Helper()
	key, _ := os.ReadFile(filepath.Join(e.dir, secrets.KeyFile))
	if len(key) == 0 {
		// after the switch the key is in the archive
		m, _ := filepath.Glob(filepath.Join(e.dir, "archive", "*", secrets.KeyFile))
		if len(m) == 1 {
			key, _ = os.ReadFile(m[0])
		}
	}
	bad := []string{apiSecret, hex.EncodeToString(key)}
	bad = append(bad, extra...)
	for _, l := range logs {
		for _, b := range bad {
			if b != "" && bytes.Contains([]byte(l), []byte(b)) {
				e.t.Fatalf("secret leaked into the job log: %q", l)
			}
		}
	}
}

var errNope = errors.New("nope")
