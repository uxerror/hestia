package api_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"hestia/internal/sshx/sshxtest"
)

func (e *env) login(t *testing.T) {
	t.Helper()
	if resp, b := e.do(t, e.client, "POST", "/api/v1/setup/admin", adminBody); resp.StatusCode != 201 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func TestTargetEndpointsRequireAuth(t *testing.T) {
	e := newEnv(t)
	for _, c := range [][2]string{
		{"GET", "/api/v1/identity"}, {"POST", "/api/v1/targets/probe"}, {"POST", "/api/v1/targets"},
		{"GET", "/api/v1/targets"}, {"GET", "/api/v1/targets/1"}, {"DELETE", "/api/v1/targets/1"},
	} {
		if resp, _ := e.do(t, e.client, c[0], c[1], `{}`); resp.StatusCode != 401 {
			t.Errorf("%s %s = %d", c[0], c[1], resp.StatusCode)
		}
	}
}

func TestIdentityAndEmptyTargets(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	_, b := e.do(t, e.client, "GET", "/api/v1/identity", "")
	var id struct{ SSHPublicKey, Fingerprint string }
	var raw map[string]string
	_ = json.Unmarshal(b, &raw)
	id.SSHPublicKey, id.Fingerprint = raw["ssh_public_key"], raw["fingerprint"]
	if !strings.HasPrefix(id.SSHPublicKey, "ssh-ed25519 ") || !strings.HasSuffix(id.SSHPublicKey, " hestia@testhost") || !strings.HasPrefix(id.Fingerprint, "SHA256:") {
		t.Fatalf("%s", b)
	}
	if strings.Contains(string(b), "PRIVATE") {
		t.Fatal("private key exposed")
	}
	_, b = e.do(t, e.client, "GET", "/api/v1/targets", "")
	if strings.TrimSpace(string(b)) != `{"targets":[]}` {
		t.Fatalf("%s", b)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/targets/42", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/targets/abc", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/targets/42?revert=true", ""); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, e.client, "DELETE", "/api/v1/targets/42?revert=maybe", ""); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
}

func TestProbeErrorsAreReadable(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	resp, b := e.do(t, e.client, "POST", "/api/v1/targets/probe", `{"kind":"ssh","host":"","auth":"password","password":"x"}`)
	if resp.StatusCode != 400 || !strings.Contains(string(b), "адрес") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if resp, _ := e.do(t, e.client, "POST", "/api/v1/targets/probe", `nonsense`); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	// A loopback port nothing listens on (the SSH server is closed right away).
	s := sshxtest.New(t)
	port := s.Port
	s.Close()
	body := `{"kind":"ssh","host":"127.0.0.1","port":` + itoa(port) + `,"auth":"password","password":"x"}`
	resp, b = e.do(t, e.client, "POST", "/api/v1/targets/probe", body)
	if resp.StatusCode != 422 || !strings.Contains(string(b), "не удалось подключиться") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), `"password"`) {
		t.Fatal("error echoes the request")
	}
	resp, b = e.do(t, e.client, "POST", "/api/v1/targets", `{"probe_id":"nope","accept":{"host_key_fp":"x"}}`)
	if resp.StatusCode != 410 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// miniServer is a tiny fake Linux host: just enough for the SSH-server flow.
type miniServer struct {
	mu   sync.Mutex
	keys string
}

func (m *miniServer) handle(user, cmd string, stdin []byte) (string, string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case cmd == `printf '%s\n' "$HOME"`:
		return "/home/u\n", "", 0
	case strings.HasPrefix(cmd, "cat '"):
		if m.keys == "" {
			return "", "cat: No such file or directory\n", 1
		}
		return m.keys, "", 0
	case strings.HasPrefix(cmd, "cat > "):
		m.keys = string(stdin)
		return "", "", 0
	case strings.HasPrefix(cmd, "mkdir -p "), cmd == "true":
		return "", "", 0
	case cmd == "uname -srm":
		return "Linux 6.1.0 x86_64\n", "", 0
	case cmd == "id -u":
		return "0\n", "", 0
	case cmd == "hostname":
		return "mini\n", "", 0
	}
	return "", "", 1 // other fact commands: unavailable
}

func TestSSHTargetLifecycleOverHTTP(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	m := &miniServer{}
	srv := sshxtest.New(t)
	srv.PasswordAuth = func(u, p string) bool { return u == "u" && p == "pw-123456" }
	srv.KeyAuth = func(u string, k ssh.PublicKey) bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return u == "u" && strings.Contains(m.keys, base64.StdEncoding.EncodeToString(k.Marshal()))
	}
	srv.Handler = m.handle

	resp, b := e.do(t, e.client, "POST", "/api/v1/targets/probe",
		`{"kind":"ssh","host":"127.0.0.1","port":`+itoa(srv.Port)+`,"username":"u","auth":"password","password":"pw-123456"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), "pw-123456") {
		t.Fatal("probe response contains the password")
	}
	var probe struct {
		ProbeID   string `json:"probe_id"`
		HostKeyFP string `json:"host_key_fp"`
		Nodes     []any  `json:"nodes"`
		Plan      []any  `json:"plan"`
	}
	_ = json.Unmarshal(b, &probe)
	if probe.HostKeyFP != srv.HostKeyFP() || probe.Nodes == nil || len(probe.Plan) != 2 {
		t.Fatalf("%s", b)
	}

	// Wrong fingerprint → 409.
	resp, _ = e.do(t, e.client, "POST", "/api/v1/targets", `{"probe_id":"`+probe.ProbeID+`","accept":{"host_key_fp":"SHA256:bad"}}`)
	if resp.StatusCode != 409 {
		t.Fatal(resp.StatusCode)
	}
	resp, b = e.do(t, e.client, "POST", "/api/v1/targets",
		`{"probe_id":"`+probe.ProbeID+`","name":"mini","accept":{"host_key_fp":"`+probe.HostKeyFP+`"}}`)
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var jr struct{ Job struct{ ID string } }
	_ = json.Unmarshal(b, &jr)
	waitJobDone(t, e, jr.Job.ID)

	_, b = e.do(t, e.client, "GET", "/api/v1/targets", "")
	var list struct {
		Targets []struct {
			ID        int64
			Name      string
			Kind      string
			HostKeyFP string `json:"host_key_fp"`
		}
	}
	_ = json.Unmarshal(b, &list)
	if len(list.Targets) != 1 || list.Targets[0].Name != "mini" || list.Targets[0].Kind != "ssh" {
		t.Fatalf("%s", b)
	}
	for _, bad := range []string{"pw-123456", "token_secret", "secret_ref"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("list leaks %q: %s", bad, b)
		}
	}
	id := list.Targets[0].ID
	if resp, _ := e.do(t, e.client, "GET", "/api/v1/targets/"+itoa(int(id)), ""); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}

	resp, b = e.do(t, e.client, "DELETE", "/api/v1/targets/"+itoa(int(id))+"?revert=true", "")
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	_ = json.Unmarshal(b, &jr)
	waitJobDone(t, e, jr.Job.ID)
	_, b = e.do(t, e.client, "GET", "/api/v1/targets", "")
	if strings.TrimSpace(string(b)) != `{"targets":[]}` {
		t.Fatalf("%s", b)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.Contains(m.keys, "hestia@testhost") {
		t.Fatalf("key not removed: %q", m.keys)
	}
}

func waitJobDone(t *testing.T, e *env, id string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, b := e.do(t, e.client, "GET", "/api/v1/jobs/"+id, "")
		var j struct {
			Job struct{ Status, Error string }
		}
		_ = json.Unmarshal(b, &j)
		switch j.Job.Status {
		case "done":
			return
		case "failed", "cancelled":
			t.Fatalf("job %s: %s", j.Job.Status, j.Job.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("job did not finish")
}
