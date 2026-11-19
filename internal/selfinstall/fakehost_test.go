package selfinstall_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/uxerror/hestia/internal/store"
)

// wordSplit splits a command line like a POSIX shell (single quotes, and
// backslash escapes outside quotes — enough for target.Quote output).
func wordSplit(s string) []string {
	var words []string
	var cur strings.Builder
	started, inQuote := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == '\'' {
				inQuote = false
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			inQuote, started = true, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			started = true
		case c == ' ' || c == '\t' || c == '\n':
			if started {
				words = append(words, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		words = append(words, cur.String())
	}
	return words
}

// splitChain splits a script on && and ; that are outside single quotes.
func splitChain(s string) (cmds []string, ops []string) {
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inQuote = !inQuote
			cur.WriteByte(c)
		case !inQuote && c == '&' && i+1 < len(s) && s[i+1] == '&':
			cmds, ops = append(cmds, cur.String()), append(ops, "&&")
			cur.Reset()
			i++
		case !inQuote && c == ';':
			cmds, ops = append(cmds, cur.String()), append(ops, ";")
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(cmds, cur.String()), ops
}

// fakeMachine is an in-memory Linux box (a container or a server) that
// understands the small set of commands the installer uses.
type fakeMachine struct {
	t       *testing.T
	mu      sync.Mutex
	files   map[string][]byte
	modes   map[string]string
	owners  map[string]string
	dirs    map[string]bool
	users   map[string]bool
	enabled bool
	started bool
	version string
	port80  bool // something already listens on port 80
	busy    map[int]bool
	cmds    []string

	hostKeys   bool
	failCmd    string // a command containing this fails
	startHook  func(m *fakeMachine)
	stopCtrl   func()
	genCounter int
}

func newMachine(t *testing.T, version string) *fakeMachine {
	return &fakeMachine{t: t, files: map[string][]byte{}, modes: map[string]string{}, owners: map[string]string{},
		dirs: map[string]bool{}, users: map[string]bool{}, version: version, busy: map[int]bool{}}
}

func (m *fakeMachine) file(p string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[p]
	return b, ok
}

func (m *fakeMachine) executed(sub string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// run executes a script (chain of simple commands).
func (m *fakeMachine) run(script string, stdin []byte) (string, string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cmds, ops := splitChain(script)
	var out, errOut strings.Builder
	code := 0
	for i, c := range cmds {
		if i > 0 && ops[i-1] == "&&" && code != 0 {
			continue
		}
		o, e, cd := m.simple(strings.TrimSpace(c), stdin)
		out.WriteString(o)
		errOut.WriteString(e)
		code = cd
	}
	return out.String(), errOut.String(), code
}

func (m *fakeMachine) simple(c string, stdin []byte) (string, string, int) {
	if c == "" {
		return "", "", 0
	}
	if !strings.HasPrefix(c, "cat >") {
		m.cmds = append(m.cmds, c)
	} else {
		m.cmds = append(m.cmds, "cat > "+wordSplit(c)[2])
	}
	if m.failCmd != "" && strings.Contains(c, m.failCmd) {
		return "", "simulated failure\n", 1
	}
	w := wordSplit(c)
	nf := func(p string) (string, string, int) { return "", "cat: " + p + ": No such file or directory\n", 1 }
	switch w[0] {
	case "true":
		return "", "", 0
	case "echo":
		return strings.Join(w[1:], " ") + "\n", "", 0
	case "cat":
		if len(w) == 3 && w[1] == ">" {
			m.files[w[2]] = append([]byte(nil), stdin...)
			return "", "", 0
		}
		b, ok := m.files[w[1]]
		if !ok {
			return nf(w[1])
		}
		return string(b), "", 0
	case "chmod":
		m.modes[w[2]] = w[1]
		return "", "", 0
	case "chown":
		m.owners[w[2]] = w[1]
		return "", "", 0
	case "sha256sum":
		b, ok := m.files[w[1]]
		if !ok {
			return "", "sha256sum: " + w[1] + ": No such file or directory\n", 1
		}
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:]) + "  " + w[1] + "\n", "", 0
	case "rm":
		for _, p := range w[1:] {
			if strings.HasPrefix(p, "-") {
				continue
			}
			delete(m.files, p)
			delete(m.modes, p)
			delete(m.owners, p)
			delete(m.dirs, p)
			for k := range m.files {
				if strings.HasPrefix(k, p+"/") {
					delete(m.files, k)
				}
			}
		}
		return "", "", 0
	case "systemd-machine-id-setup":
		m.files["/etc/machine-id"] = []byte(randHex(16) + "\n")
		return "", "", 0
	case "test":
		return m.test(w[1:])
	case "ssh-keygen":
		if w[1] == "-A" {
			m.files["/etc/ssh/ssh_host_ed25519_key.pub"] = []byte("ssh-ed25519 AAAAfake root@ct\n")
			return "", "", 0
		}
		if _, ok := m.files[w[2]]; !ok {
			return nf(w[2])
		}
		return "256 SHA256:fakeFingerprintOfTheContainerKey root@ct (ED25519)\n", "", 0
	case "id":
		if m.users[w[2]] {
			return "999\n", "", 0
		}
		return "", "id: ‘" + w[2] + "’: no such user\n", 1
	case "useradd":
		m.users[w[len(w)-1]] = true
		return "", "", 0
	case "userdel":
		delete(m.users, w[1])
		return "", "", 0
	case "install":
		m.dirs[w[len(w)-1]] = true
		return "", "", 0
	case binPathT:
		b, ok := m.files[binPathT]
		if !ok || string(b) == "" {
			return "", "not found\n", 127
		}
		return "hestia " + m.version + "\n", "", 0
	case "systemctl":
		return m.systemctl(w[1:])
	case "systemd-tmpfiles":
		m.dirs["/run/hestia"] = true
		return "", "", 0
	case "ss":
		port := 0
		for _, a := range w {
			if strings.HasPrefix(a, "sport = :") {
				port, _ = strconv.Atoi(strings.TrimPrefix(a, "sport = :"))
			}
		}
		if port == 80 && m.port80 || m.busy[port] {
			return fmt.Sprintf("LISTEN 0 128 0.0.0.0:%d 0.0.0.0:*\n", port), "", 0
		}
		return "", "", 0
	}
	return "", "unknown command: " + c + "\n", 127
}

const binPathT = "/usr/local/bin/hestia"

func (m *fakeMachine) test(a []string) (string, string, int) {
	// test -s FILE | test -e FILE [-o -e FILE …]
	if len(a) >= 2 && a[0] == "-s" {
		if b, ok := m.files[a[1]]; ok && len(b) > 0 {
			return "", "", 0
		}
		return "", "", 1
	}
	for i := 0; i+1 < len(a); i += 3 {
		p := a[i+1]
		if _, ok := m.files[p]; ok || m.dirs[p] {
			return "", "", 0
		}
	}
	return "", "", 1
}

func (m *fakeMachine) systemctl(a []string) (string, string, int) {
	switch {
	case len(a) >= 1 && a[0] == "--version":
		return "systemd 257\n", "", 0
	case a[0] == "is-system-running":
		return "running\n", "", 0
	case a[0] == "daemon-reload":
		return "", "", 0
	case a[0] == "enable":
		m.enabled = true
		return "", "", 0
	case a[0] == "disable":
		m.enabled, m.started = false, false
		if m.stopCtrl != nil {
			m.stopCtrl()
		}
		return "", "", 0
	case a[0] == "start":
		m.started = true
		if m.startHook != nil {
			m.mu.Unlock()
			m.startHook(m)
			m.mu.Lock()
		}
		return "", "", 0
	}
	return "", "unknown systemctl\n", 1
}

// controller starts a fake "new controller" for the machine: it opens the
// uploaded database (so a broken copy fails here) and answers health with the
// instance id found in it (or forced).
type fakeController struct {
	srv *httptest.Server
	id  string
}

func (m *fakeMachine) bootController(forceID string) *fakeController {
	db, ok := m.file("/var/lib/hestia/hestia.db")
	if !ok {
		m.t.Error("no database uploaded to the machine")
		return nil
	}
	dir := m.t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hestia.db"), db, 0o600); err != nil {
		m.t.Fatal(err)
	}
	st, err := store.OpenCopy(dir)
	if err != nil {
		m.t.Errorf("the uploaded database does not open: %v", err)
		return nil
	}
	id, err := st.EnsureInstanceID(ctxBG())
	_ = st.Close()
	if err != nil {
		m.t.Errorf("instance id: %v", err)
		return nil
	}
	if forceID != "" {
		id = forceID
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":%q,"instance_id":%q}`, m.version, id)
	}))
	m.t.Cleanup(srv.Close)
	return &fakeController{srv: srv, id: id}
}

// ---- the SSH node ----

// nodeHandler is the command handler of an SSH server that plays a Proxmox
// node (with `pct exec` into fake containers) or a standalone server.
type nodeHandler struct {
	t        *testing.T
	mu       sync.Mutex
	arch     string
	nodeID   string
	pingBusy map[string]bool
	cts      map[int]*fakeMachine
	newCT    func(vmid int) *fakeMachine
	server   *fakeMachine // standalone server machine
	uid      int          // 0 = root
	hasSudo  bool
	execs    []string
}

func newNodeHandler(t *testing.T) *nodeHandler {
	return &nodeHandler{t: t, arch: "x86_64", nodeID: randHex(16), pingBusy: map[string]bool{}, cts: map[int]*fakeMachine{}, hasSudo: true}
}

func (n *nodeHandler) ct(vmid int) *fakeMachine {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cts[vmid]
}

func (n *nodeHandler) addCT(vmid int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	m := n.newCT(vmid)
	n.cts[vmid] = m
}

func (n *nodeHandler) commands() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.execs...)
}

func (n *nodeHandler) handle(user, cmd string, stdin []byte) (string, string, int) {
	n.mu.Lock()
	if !strings.HasPrefix(cmd, "pct exec") && !strings.Contains(cmd, "sh -c") {
		n.execs = append(n.execs, cmd)
	}
	n.mu.Unlock()
	w := wordSplit(cmd)
	switch {
	case cmd == "uname -m":
		return n.arch + "\n", "", 0
	case cmd == "cat /etc/machine-id":
		return n.nodeID + "\n", "", 0
	case strings.HasPrefix(cmd, "ping -c1 -W1 "):
		if n.pingBusy[strings.TrimPrefix(cmd, "ping -c1 -W1 ")] {
			return "1 received\n", "", 0
		}
		return "", "100% packet loss\n", 1
	case len(w) > 5 && w[0] == "pct" && w[1] == "exec" && w[3] == "--":
		id, _ := strconv.Atoi(w[2])
		m := n.ct(id)
		if m == nil {
			return "", "Configuration file 'nodes/pve1/lxc/" + w[2] + ".conf' does not exist\n", 2
		}
		return m.run(w[6], stdin)
	case len(w) == 3 && w[0] == "sh" && w[1] == "-c" && n.server != nil:
		if n.uid != 0 {
			return "", "Permission denied\n", 1
		}
		return n.server.run(w[2], stdin)
	case len(w) == 5 && w[0] == "sudo" && w[1] == "-n" && w[2] == "sh" && w[3] == "-c" && n.server != nil:
		if !n.hasSudo {
			return "", "sudo: a password is required\n", 1
		}
		return n.server.run(w[4], stdin)
	case cmd == "uname -srm":
		return "Linux 6.1.0-18-amd64 " + n.arch + "\n", "", 0
	case cmd == "hostname":
		return "srv\n", "", 0
	case cmd == "cat /etc/os-release":
		return "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", "", 0
	case cmd == "nproc":
		return "4\n", "", 0
	case cmd == "free -b":
		return "              total        used        free      shared  buff/cache   available\nMem:     8000000000  1000000000  5000000000   100000000  2000000000  6500000000\n", "", 0
	case cmd == "df -B1 -x tmpfs -x devtmpfs":
		return "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 100000000000 40000000000 60000000000 40% /\n", "", 0
	case cmd == "command -v docker":
		return "", "", 1
	case cmd == "id -u":
		return strconv.Itoa(n.uid) + "\n", "", 0
	case cmd == "sudo -n true":
		if n.hasSudo {
			return "", "", 0
		}
		return "", "sudo: a password is required\n", 1
	}
	return "", "unknown command: " + cmd + "\n", 127
}
