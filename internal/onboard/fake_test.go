package onboard_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"hestia/internal/jobs"
	"hestia/internal/onboard"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/sshx"
	"hestia/internal/sshx/sshxtest"
	"hestia/internal/store"
)

const (
	rootPassword = "hunter2-root-pw"
	tokenValue   = "11111111-2222-3333-4444-555555555555"
)

// fakeHost is the shared state of a fake Proxmox cluster or server: every
// node's SSH server runs commands against it, like a real shared /etc/pve.
type fakeHost struct {
	mu sync.Mutex

	isProxmox    bool
	cluster      string // empty = single node
	nodes        []proxmox.Node
	local        string
	roles        map[string]string // roleid → privs
	users        map[string]bool
	tokens       map[string]string // token name → secret
	acl          map[string]bool   // "path|user|role"
	authKeys     string            // shared authorized_keys
	failTokenAdd bool
	// nodeKeys is node → known_hosts line served as
	// /etc/pve/nodes/<node>/ssh_known_hosts (real PVE: ssh-rsa only).
	nodeKeys map[string]string
	cmds     []string

	// standalone server facts
	uid      string
	hasSudo  bool
	hasFiles bool
}

func newFakeProxmox(cluster string, nodeNames ...string) *fakeHost {
	f := &fakeHost{isProxmox: true, cluster: cluster, roles: map[string]string{}, users: map[string]bool{},
		tokens: map[string]string{}, acl: map[string]bool{}, uid: "0", hasSudo: true, nodeKeys: map[string]string{}}
	for i, n := range nodeNames {
		f.nodes = append(f.nodes, proxmox.Node{Name: n, IP: fmt.Sprintf("198.51.100.%d", i+1), Online: true})
	}
	f.local = nodeNames[0]
	return f
}

func (f *fakeHost) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

var (
	reCat   = regexp.MustCompile(`^cat '([^']*)'$`)
	rePut   = regexp.MustCompile(`^cat > '([^']*)' && `)
	rePrivs = regexp.MustCompile(`--privs '([^']*)'`)

	reNodeKeys = regexp.MustCompile(`^/etc/pve/nodes/([^/]+)/ssh_known_hosts$`)
)

const keysPath = "/root/.ssh/authorized_keys"

func (f *fakeHost) handle(user, cmd string, stdin []byte) (string, string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	ok := func(s string) (string, string, int) { return s, "", 0 }
	fail := func(s string) (string, string, int) { return "", s + "\n", 255 }

	switch {
	case cmd == "true":
		return ok("")
	case cmd == "hostname":
		return ok(f.local + "\n")
	case cmd == `printf '%s\n' "$HOME"`:
		return ok("/root\n")
	case strings.HasPrefix(cmd, "mkdir -p "):
		return ok("")
	case reCat.MatchString(cmd):
		p := reCat.FindStringSubmatch(cmd)[1]
		switch p {
		case keysPath:
			if f.authKeys == "" {
				return "", "cat: " + p + ": No such file or directory\n", 1
			}
			return ok(f.authKeys)
		case "/etc/pve/.members":
			if !f.isProxmox || f.cluster == "" {
				return "", "cat: " + p + ": No such file or directory\n", 1
			}
			return ok(f.membersJSON())
		case "/etc/os-release":
			return ok("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\n")
		}
		if m := reNodeKeys.FindStringSubmatch(p); m != nil && f.isProxmox {
			if line, has := f.nodeKeys[m[1]]; has {
				return ok(line + "\n")
			}
		}
		return "", "cat: " + p + ": No such file or directory\n", 1
	case rePut.MatchString(cmd):
		if rePut.FindStringSubmatch(cmd)[1] != keysPath {
			return fail("unexpected write")
		}
		f.authKeys = string(stdin)
		return ok("")
	}

	if strings.HasPrefix(cmd, "pveum ") || cmd == "pveversion" {
		if !f.isProxmox {
			return "", "bash: " + strings.Fields(cmd)[0] + ": command not found\n", 127
		}
		return f.pve(cmd)
	}
	// standalone facts
	switch cmd {
	case "uname -srm":
		return ok("Linux 6.1.0-18-amd64 x86_64\n")
	case "cat /etc/os-release":
		return ok("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\n")
	case "nproc":
		return ok("4\n")
	case "free -b":
		return ok("              total        used        free      shared  buff/cache   available\nMem:     8000000000  1000000000  5000000000   100000000  2000000000  6500000000\nSwap:             0           0           0\n")
	case "df -B1 -x tmpfs -x devtmpfs":
		return ok("Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 100000000000 40000000000 60000000000 40% /\n")
	case "command -v docker":
		return "", "", 1
	case "id -u":
		return ok(f.uid + "\n")
	case "sudo -n true":
		if f.hasSudo {
			return ok("")
		}
		return "", "sudo: a password is required\n", 1
	}
	return "", "unknown command: " + cmd + "\n", 127
}

func (f *fakeHost) membersJSON() string {
	nl := map[string]any{}
	for i, n := range f.nodes {
		on := 0
		if n.Online {
			on = 1
		}
		nl[n.Name] = map[string]any{"id": i + 1, "online": on, "ip": n.IP}
	}
	b, _ := json.Marshal(map[string]any{"nodename": f.local, "version": 3,
		"cluster":  map[string]any{"name": f.cluster, "version": 2, "nodes": len(f.nodes), "quorate": 1},
		"nodelist": nl})
	return string(b)
}

func (f *fakeHost) pve(cmd string) (string, string, int) {
	out := func(v any) (string, string, int) {
		b, _ := json.Marshal(v)
		return string(b) + "\n", "", 0
	}
	fail := func(s string) (string, string, int) { return "", s + "\n", 2 }
	switch {
	case cmd == "pveversion":
		return "pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.8-2-pve)\n", "", 0
	case cmd == "pveum role list --output-format json":
		l := []map[string]any{{"roleid": "Administrator", "privs": "Sys.Audit", "special": 1}}
		for id, p := range f.roles {
			l = append(l, map[string]any{"roleid": id, "privs": p})
		}
		return out(l)
	case cmd == "pveum user list --output-format json":
		l := []map[string]any{{"userid": "root@pam"}}
		for u := range f.users {
			l = append(l, map[string]any{"userid": u})
		}
		return out(l)
	case cmd == "pveum user token list "+proxmox.UserID+" --output-format json":
		l := []map[string]any{}
		for n := range f.tokens {
			l = append(l, map[string]any{"tokenid": n, "privsep": 0})
		}
		return out(l)
	case cmd == "pveum acl list --output-format json":
		l := []map[string]any{}
		for k := range f.acl {
			p := strings.Split(k, "|")
			l = append(l, map[string]any{"path": p[0], "ugid": p[1], "roleid": p[2], "type": "user", "propagate": 1})
		}
		return out(l)
	case strings.HasPrefix(cmd, "pveum role add "+proxmox.RoleName+" "):
		f.roles[proxmox.RoleName] = sortedPrivs(rePrivs.FindStringSubmatch(cmd)[1])
		return "", "", 0
	case strings.HasPrefix(cmd, "pveum role modify "+proxmox.RoleName+" "):
		if _, ok := f.roles[proxmox.RoleName]; !ok {
			return fail("role does not exist")
		}
		f.roles[proxmox.RoleName] = sortedPrivs(rePrivs.FindStringSubmatch(cmd)[1])
		return "", "", 0
	case cmd == proxmox.CmdRoleDel:
		if _, ok := f.roles[proxmox.RoleName]; !ok {
			return fail("role does not exist")
		}
		delete(f.roles, proxmox.RoleName)
		return "", "", 0
	case strings.HasPrefix(cmd, "pveum user add "+proxmox.UserID):
		f.users[proxmox.UserID] = true
		return "", "", 0
	case cmd == proxmox.CmdUserDel:
		if !f.users[proxmox.UserID] {
			return fail("user does not exist")
		}
		delete(f.users, proxmox.UserID)
		f.tokens = map[string]string{}
		return "", "", 0
	case cmd == proxmox.CmdACLAdd:
		f.acl["/|"+proxmox.UserID+"|"+proxmox.RoleName] = true
		return "", "", 0
	case cmd == proxmox.CmdACLDel:
		delete(f.acl, "/|"+proxmox.UserID+"|"+proxmox.RoleName)
		return "", "", 0
	case cmd == proxmox.CmdTokenAdd:
		if f.failTokenAdd {
			return fail("create token failed: permission denied")
		}
		if !f.users[proxmox.UserID] {
			return fail("user does not exist")
		}
		if _, dup := f.tokens[proxmox.TokenName]; dup {
			return fail("token already exists")
		}
		f.tokens[proxmox.TokenName] = tokenValue
		return out(map[string]any{"full-tokenid": proxmox.TokenID, "info": map[string]any{"privsep": "0"}, "value": tokenValue})
	case cmd == proxmox.CmdTokenDel:
		if _, ok := f.tokens[proxmox.TokenName]; !ok {
			return fail("token does not exist")
		}
		delete(f.tokens, proxmox.TokenName)
		return "", "", 0
	}
	return fail("unsupported pveum command: " + cmd)
}

func sortedPrivs(s string) string {
	p := strings.Split(s, ",")
	sort.Strings(p)
	return strings.Join(p, ",")
}

func (f *fakeHost) hasKey(pub ssh.PublicKey) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range strings.Split(f.authKeys, "\n") {
		if l == "" {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil && string(k.Marshal()) == string(pub.Marshal()) {
			return true
		}
	}
	return false
}

func (f *fakeHost) keyLines() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range strings.Split(f.authKeys, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// env wires a store, secrets, runner, fake SSH servers and a fake API.
type env struct {
	t     *testing.T
	svc   *onboard.Service
	st    *store.Store
	sec   *secrets.Service
	run   *jobs.Runner
	host  *fakeHost
	main  *sshxtest.Server
	nodes map[string]*sshxtest.Server // fake node IP → server
	api   *apiFake
	dir   string
	id    secrets.Identity
	now   time.Time
}

// apiFake is the Proxmox API :8006 replacement.
type apiFake struct {
	srv  *httptest.Server
	port int
	mu   sync.Mutex
	auth []string // Authorization headers seen
	host *fakeHost
}

func newAPIFake(t *testing.T, host *fakeHost) *apiFake {
	a := &apiFake{host: host}
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.auth = append(a.auth, r.Header.Get("Authorization"))
		a.mu.Unlock()
		host.mu.Lock()
		secret, has := host.tokens[proxmox.TokenName]
		host.mu.Unlock()
		if !has || r.Header.Get("Authorization") != "PVEAPIToken="+proxmox.TokenID+"="+secret {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"8.2.4"}}`))
		case "/api2/json/nodes":
			host.mu.Lock()
			var l []map[string]string
			for _, n := range host.nodes {
				st := "online"
				if !n.Online {
					st = "offline"
				}
				l = append(l, map[string]string{"node": n.Name, "status": st})
			}
			host.mu.Unlock()
			b, _ := json.Marshal(map[string]any{"data": l})
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)
	_, p, _ := net.SplitHostPort(a.srv.Listener.Addr().String())
	a.port, _ = strconv.Atoi(p)
	return a
}

func (a *apiFake) headers() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auth...)
}

func newEnv(t *testing.T, host *fakeHost) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.Open(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sec.EnsureIdentity(context.Background(), "ctl")
	if err != nil {
		t.Fatal(err)
	}
	run, err := jobs.NewRunner(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, sec: sec, run: run, host: host, dir: dir, id: id, nodes: map[string]*sshxtest.Server{}, now: time.Now()}
	t.Cleanup(func() { run.Shutdown(); _ = st.Close() })

	newSrv := func() *sshxtest.Server {
		s := sshxtest.New(t)
		s.PasswordAuth = func(u, p string) bool { return u == "root" && p == rootPassword }
		s.KeyAuth = func(u string, k ssh.PublicKey) bool { return u == "root" && host.hasKey(k) }
		s.Handler = host.handle
		return s
	}
	e.main = newSrv()
	for _, n := range host.nodes[min(1, len(host.nodes)):] {
		e.nodes[n.IP] = newSrv()
	}
	// Like a real PVE 8/9 cluster: every node offers ed25519 (preferred) and
	// RSA, but the cluster files list the RSA key only.
	if host.isProxmox && len(host.nodes) > 1 {
		for i, n := range host.nodes {
			srv := e.main
			if i > 0 {
				srv = e.nodes[n.IP]
			}
			rsaKey := sshxtest.NewRSASigner(t)
			srv.AddHostKey(rsaKey)
			host.nodeKeys[n.Name] = n.Name + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rsaKey.PublicKey())))
		}
	}
	e.api = newAPIFake(t, host)

	e.svc = (&onboard.Service{
		Store: st, Secrets: sec, Runner: run, Identity: id,
		APIPort: e.api.port,
		Now:     func() time.Time { return e.now },
		// Fake node addresses (TEST-NET) are rewritten to local servers; any
		// other non-loopback target is a test bug and must never be dialed.
		Dial: func(ctx context.Context, cfg sshx.Config) (*sshx.Client, error) {
			if s, ok := e.nodes[cfg.Host]; ok {
				cfg.Host, cfg.Port = s.Host, s.Port
			}
			if cfg.Host != "127.0.0.1" {
				t.Errorf("test tried to dial non-loopback host %q", cfg.Host)
				return nil, errors.New("blocked: non-loopback dial in test")
			}
			return sshx.Dial(ctx, cfg)
		},
	}).Init()
	return e
}

func (e *env) probeReq(kind string) onboard.ProbeRequest {
	return onboard.ProbeRequest{Kind: kind, Host: "127.0.0.1", Port: e.main.Port, Username: "root", Auth: "password", Password: rootPassword}
}

func (e *env) confirm(res *onboard.ProbeResult) onboard.CreateRequest {
	var c onboard.CreateRequest
	c.ProbeID = res.ProbeID
	c.Accept.HostKeyFP = res.HostKeyFP
	c.Accept.APICertFP = res.APICertFP
	return c
}

// waitJob waits for the job to finish and returns it.
func (e *env) waitJob(j store.Job) store.Job {
	e.t.Helper()
	e.run.Wait()
	got, err := e.st.GetJob(context.Background(), j.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) jobText(j store.Job) string {
	var b strings.Builder
	for _, l := range j.Log {
		b.WriteString(l.Line + "\n")
	}
	return b.String()
}
