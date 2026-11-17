package proxmox_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hestia/internal/proxmox"
	"hestia/internal/sshx"
	"hestia/internal/target"
)

// Real outputs of a PVE 9.2 cluster ("home": pve, pve1, pve2), see testdata.
const fixtureDir = "testdata/real-pve9"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// splitNodeFiles splits nodes_ssh_known_hosts.txt: files are introduced by a
// "== <node>" marker and (as captured) may lack a trailing newline.
func splitNodeFiles(t *testing.T) map[string]string {
	t.Helper()
	re := regexp.MustCompile(`== (\S+)\n`)
	raw := string(fixture(t, "nodes_ssh_known_hosts.txt"))
	locs := re.FindAllStringSubmatchIndex(raw, -1)
	if len(locs) != 3 {
		t.Fatalf("expected 3 node files, found %d", len(locs))
	}
	out := map[string]string{}
	for i, l := range locs {
		end := len(raw)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out[raw[l[2]:l[3]]] = raw[l[1]:end]
	}
	return out
}

// keyscanFPs returns the RSA fingerprint per IP from keyscan_fps.txt.
func keyscanRSA(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, l := range strings.Split(string(fixture(t, "keyscan_fps.txt")), "\n") {
		f := strings.Fields(l)
		if len(f) == 4 && f[3] == "(RSA)" {
			out[f[2]] = f[1]
		}
	}
	if len(out) != 3 {
		t.Fatalf("keyscan RSA entries: %v", out)
	}
	return out
}

// fakePVE serves the fixtures like the cluster would.
type fakePVE struct {
	files    map[string][]byte
	noNodeKH bool // /etc/pve/nodes/*/ssh_known_hosts do not exist (old PVE)
	tokenCmd func() (string, string, int)
	execs    []string
}

func newFakePVE(t *testing.T) *fakePVE {
	f := &fakePVE{files: map[string][]byte{
		"/etc/pve/.members":         fixture(t, "members.json"),
		"/etc/pve/priv/known_hosts": fixture(t, "known_hosts"),
	}}
	for n, c := range splitNodeFiles(t) {
		f.files["/etc/pve/nodes/"+n+"/ssh_known_hosts"] = []byte(c)
	}
	return f
}

func (f *fakePVE) Exec(_ context.Context, cmd string) (target.Result, error) {
	f.execs = append(f.execs, cmd)
	var out, errOut string
	code := 0
	switch cmd {
	case "pveversion":
		out = string(fixture0(cmd))
	case "pveum role list --output-format json":
		out = string(fixture0("role_list.json"))
	case "pveum user list --output-format json":
		out = string(fixture0("user_list.json"))
	case "pveum acl list --output-format json":
		out = string(fixture0("acl_list.json"))
	case "pveum user token list hestia@pve --output-format json":
		if f.tokenCmd != nil {
			out, errOut, code = f.tokenCmd()
		} else {
			out = string(fixture0("token_list.json"))
		}
	default:
		errOut, code = "unexpected command: "+cmd+"\n", 127
	}
	r := target.Result{Stdout: out, Stderr: errOut, ExitCode: code}
	if code != 0 {
		return r, &sshx.ExitError{Cmd: cmd, Result: r}
	}
	return r, nil
}

func fixture0(name string) []byte {
	if name == "pveversion" {
		name = "pveversion.txt"
	}
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		panic(err)
	}
	return b
}

func (f *fakePVE) Get(_ context.Context, path string) ([]byte, error) {
	if f.noNodeKH && strings.HasSuffix(path, "/ssh_known_hosts") {
		return nil, fs.ErrNotExist
	}
	b, ok := f.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}

func (f *fakePVE) Put(context.Context, string, []byte, fs.FileMode) error {
	return errors.New("read-only")
}
func (f *fakePVE) Facts(context.Context) (target.Facts, error) { return target.Facts{}, nil }
func (f *fakePVE) Close() error                                { return nil }

func TestParseMembersReal(t *testing.T) {
	cluster, local, nodes, err := proxmox.ParseMembers(fixture(t, "members.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cluster != "home" || local != "pve" || len(nodes) != 3 {
		t.Fatalf("%q %q %+v", cluster, local, nodes)
	}
	want := []proxmox.Node{{Name: "pve", IP: "10.10.10.10", Online: true}, {Name: "pve1", IP: "10.10.10.50", Online: true}, {Name: "pve2", IP: "10.10.10.100", Online: true}}
	for i, n := range want {
		if nodes[i] != n {
			t.Errorf("node %d: %+v, want %+v", i, nodes[i], n)
		}
	}
}

func TestInspectRealOutputs(t *testing.T) {
	f := newFakePVE(t)
	st, err := proxmox.Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "9.2.10" || st.Cluster != "home" || st.LocalNode != "pve" || len(st.Nodes) != 3 {
		t.Fatalf("%+v", st)
	}
	// Hestia has not been set up on this cluster: other users, tokens, ACLs and
	// roles in the real outputs must not be mistaken for ours.
	if st.RoleExists || st.UserExists || st.TokenExist || st.ACLExists || len(st.RolePrivs) != 0 {
		t.Fatalf("false positives: %+v", st)
	}
	if got := st.MissingPrivs(); len(got) != len(proxmox.PrivilegesFor(st.Version)) {
		t.Fatalf("missing privs: %v", got)
	}
}

// The host keys of the nodes, read from /etc/pve/nodes/*/ssh_known_hosts,
// must be exactly the RSA keys ssh-keyscan sees on the nodes.
func TestInspectNodeKeysMatchKeyscan(t *testing.T) {
	st, err := proxmox.Inspect(context.Background(), newFakePVE(t))
	if err != nil {
		t.Fatal(err)
	}
	scan := keyscanRSA(t)
	for _, n := range st.Nodes {
		if n.HostKeyType != "ssh-rsa" || n.HostKeyFP == "" || n.HostKeyFP != scan[n.IP] {
			t.Errorf("%s (%s): %s %q, keyscan %q", n.Name, n.IP, n.HostKeyType, n.HostKeyFP, scan[n.IP])
		}
	}
}

// Old versions only have /etc/pve/priv/known_hosts, which in the capture lists
// the local node (by name and IP) only: the others stay without a key.
func TestInspectNodeKeysLegacyFallback(t *testing.T) {
	f := newFakePVE(t)
	f.noNodeKH = true
	st, err := proxmox.Inspect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	scan := keyscanRSA(t)
	if st.Nodes[0].Name != "pve" || st.Nodes[0].HostKeyFP != scan["10.10.10.10"] {
		t.Fatalf("pve: %+v", st.Nodes[0])
	}
	for _, n := range st.Nodes[1:] {
		if n.HostKeyFP != "" || n.HostKeyType != "" {
			t.Errorf("%s got a key from nowhere: %+v", n.Name, n)
		}
	}
}

func TestParseKnownHostsRealFiles(t *testing.T) {
	m := proxmox.ParseKnownHosts(fixture(t, "known_hosts"))
	scan := keyscanRSA(t)
	for _, h := range []string{"pve", "10.10.10.10"} {
		if len(m[h]) != 1 || m[h][0].FP != scan["10.10.10.10"] || m[h][0].Type != "ssh-rsa" {
			t.Errorf("%s: %+v", h, m[h])
		}
	}
	for node, content := range splitNodeFiles(t) {
		keys := proxmox.ParseKnownHosts([]byte(content))
		if len(keys) != 1 || len(keys[node]) != 1 {
			t.Errorf("%s: %+v", node, keys)
		}
	}
}

func TestParseKnownHostsSkipsNoise(t *testing.T) {
	good := strings.TrimSpace(strings.SplitN(string(fixture(t, "known_hosts")), "\n", 2)[0]) // "pve ssh-rsa …"
	key := strings.Fields(good)[2]
	in := strings.Join([]string{
		"# comment",
		"",
		"garbage line",
		"|1|c2FsdA==|aGFzaA== ssh-rsa " + key,
		"*.example.com ssh-rsa " + key,
		"@revoked revoked ssh-rsa " + key,
		"@cert-authority ca ssh-rsa " + key,
		"[pve9]:2222 ssh-rsa " + key,
		"a,b ssh-rsa NOTBASE64!",
		good,
	}, "\n")
	m := proxmox.ParseKnownHosts([]byte(in))
	if len(m) != 2 || len(m["pve"]) != 1 || len(m["pve9"]) != 1 {
		t.Fatalf("%+v", m)
	}
}

// `pveum user token list` for a missing user exits 255 with "no such user":
// that means "no tokens", not a failed check.
func TestTokenListForMissingUserMeansNoTokens(t *testing.T) {
	raw := string(fixture(t, "token_list_nouser.txt"))
	msg, rc, ok := strings.Cut(strings.TrimSpace(raw), "\nrc=")
	if !ok || rc != "255" || !strings.Contains(msg, "no such user") {
		t.Fatalf("fixture shape: %q", raw)
	}
	f := newFakePVE(t)
	f.tokenCmd = func() (string, string, int) { return "", msg + "\n", 255 }
	st, err := proxmox.Inspect(context.Background(), f)
	if err != nil {
		t.Fatalf("no such user must not fail the check: %v", err)
	}
	if st.TokenExist {
		t.Fatal("token reported for a missing user")
	}
}

func TestTokenListOtherFailuresStayErrors(t *testing.T) {
	for name, fn := range map[string]func() (string, string, int){
		"other message, rc 255": func() (string, string, int) { return "", "permission denied\n", 255 },
		"no such user, rc 1":    func() (string, string, int) { return "", "no such user ('x')\n", 1 },
	} {
		f := newFakePVE(t)
		f.tokenCmd = fn
		if _, err := proxmox.Inspect(context.Background(), f); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestTokenListRealOutputFindsHestiaToken(t *testing.T) {
	f := newFakePVE(t)
	f.tokenCmd = func() (string, string, int) { return `[{"expire":0,"privsep":0,"tokenid":"hestia"}]`, "", 0 }
	st, err := proxmox.Inspect(context.Background(), f)
	if err != nil || !st.TokenExist {
		t.Fatalf("%+v %v", st, err)
	}
}
