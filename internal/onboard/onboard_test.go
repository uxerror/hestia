package onboard_test

import (
	"context"
	"errors"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hestia/internal/onboard"
	"hestia/internal/proxmox"
	"hestia/internal/sshx/sshxtest"
	"hestia/internal/store"
)

func probeOK(t *testing.T, e *env, kind string) *onboard.ProbeResult {
	t.Helper()
	res, err := e.svc.Probe(context.Background(), e.probeReq(kind))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return res
}

func asErr(t *testing.T, err error) *onboard.Error {
	t.Helper()
	var oe *onboard.Error
	if !errors.As(err, &oe) {
		t.Fatalf("not an onboard.Error: %v", err)
	}
	return oe
}

func planIDs(res *onboard.ProbeResult) string {
	var ids []string
	for _, p := range res.Plan {
		ids = append(ids, p.ID)
	}
	return strings.Join(ids, ",")
}

func TestProbeProxmoxCluster3Nodes(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2", "pve3")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	if res.Kind != "proxmox" || res.Version != "8.2.4" || res.Cluster != "lab" || len(res.Nodes) != 3 {
		t.Fatalf("%+v", res)
	}
	if !e.main.HasHostKeyFP(res.HostKeyFP) || !strings.HasPrefix(res.HostKeyFP, "SHA256:") {
		t.Fatalf("host key fp %q", res.HostKeyFP)
	}
	if strings.Count(res.APICertFP, ":") != 31 {
		t.Fatalf("api fp %q", res.APICertFP)
	}
	if planIDs(res) != "role,user,acl,token,ssh_key,verify" {
		t.Fatalf("plan: %s", planIDs(res))
	}
	if res.SuggestedName != "lab" || res.ProbeID == "" || res.Facts != nil {
		t.Fatalf("%+v", res)
	}
	// A probe changes nothing on the target.
	for _, c := range host.commands() {
		if strings.Contains(c, " add ") || strings.Contains(c, "modify") || strings.Contains(c, "delete") || strings.HasPrefix(c, "cat >") {
			t.Fatalf("probe ran a mutating command: %s", c)
		}
	}
	if len(host.roles)+len(host.users)+len(host.tokens) != 0 || host.authKeys != "" {
		t.Fatal("probe changed state")
	}
}

func TestProbeSingleNode(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "solo"))
	res := probeOK(t, e, "proxmox")
	if res.Cluster != "" || len(res.Nodes) != 1 || res.Nodes[0].Name != "solo" || res.SuggestedName != "solo" {
		t.Fatalf("%+v", res)
	}
}

func TestProbeNotProxmox(t *testing.T) {
	host := newFakeProxmox("", "x")
	host.isProxmox = false
	e := newEnv(t, host)
	_, err := e.svc.Probe(context.Background(), e.probeReq("proxmox"))
	oe := asErr(t, err)
	if oe.Status != 422 || !strings.Contains(oe.Msg, "это не Proxmox") || !strings.Contains(oe.Msg, "отдельный сервер") {
		t.Fatalf("%+v", oe)
	}
}

func TestProbeAccessDeniedAndValidation(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "x"))
	req := e.probeReq("proxmox")
	req.Password = "wrong"
	oe := asErr(t, func() error { _, err := e.svc.Probe(context.Background(), req); return err }())
	if oe.Status != 422 || !strings.Contains(oe.Msg, "доступ запрещён") {
		t.Fatalf("%+v", oe)
	}
	if e.svc.SessionCount() != 0 {
		t.Fatal("failed probe left a session")
	}

	cases := map[string]func(*onboard.ProbeRequest){
		"kind":     func(r *onboard.ProbeRequest) { r.Kind = "x" },
		"host":     func(r *onboard.ProbeRequest) { r.Host = " " },
		"hostchar": func(r *onboard.ProbeRequest) { r.Host = "a b;rm" },
		"port":     func(r *onboard.ProbeRequest) { r.Port = 70000 },
		"nopw":     func(r *onboard.ProbeRequest) { r.Password = "" },
		"auth":     func(r *onboard.ProbeRequest) { r.Auth = "magic" },
		"badkey":   func(r *onboard.ProbeRequest) { r.Auth = "key"; r.PrivateKey = "junk" },
		"nokey":    func(r *onboard.ProbeRequest) { r.Auth = "key"; r.PrivateKey = "" },
		"pveuser":  func(r *onboard.ProbeRequest) { r.Username = "bob" },
	}
	for name, mut := range cases {
		r := e.probeReq("proxmox")
		mut(&r)
		_, err := e.svc.Probe(context.Background(), r)
		if oe := asErr(t, err); oe.Status != 400 {
			t.Errorf("%s: status %d (%s)", name, oe.Status, oe.Msg)
		}
	}
}

func TestProbeUnreachablePort(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "x"))
	req := e.probeReq("proxmox")
	e.main.Close()
	_, err := e.svc.Probe(context.Background(), req)
	if oe := asErr(t, err); oe.Status != 422 || !strings.Contains(oe.Msg, "не удалось подключиться") {
		t.Fatalf("%+v", oe)
	}
}

func TestConnectProxmoxClusterEndToEnd(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2", "pve3")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")

	job, err := e.svc.Connect(context.Background(), e.confirm(res))
	if err != nil {
		t.Fatal(err)
	}
	j := e.waitJob(job)
	if j.Status != store.JobDone {
		t.Fatalf("job %s: %s\n%s", j.Status, j.Error, e.jobText(j))
	}
	// State on Proxmox.
	if got := host.roles[proxmox.RoleName]; got != sortedPrivs(strings.Join(proxmox.PrivilegesFor("8.2.4"), ",")) {
		t.Fatalf("role privs: %s", got)
	}
	if !host.users[proxmox.UserID] || !host.acl["/|hestia@pve|Hestia"] || host.tokens["hestia"] != tokenValue {
		t.Fatalf("state: %+v %+v %+v", host.users, host.acl, host.tokens)
	}
	// The key was added once even though three nodes were checked.
	if host.keyLines() != 1 || !strings.Contains(host.authKeys, "hestia@ctl") {
		t.Fatalf("authorized_keys: %q", host.authKeys)
	}
	// The API was called with the token header.
	want := "PVEAPIToken=hestia@pve!hestia=" + tokenValue
	found := 0
	for _, h := range e.api.headers() {
		if h == want {
			found++
		}
	}
	if found < 2 { // /version and /nodes
		t.Fatalf("API headers: %v", e.api.headers())
	}
	// Target record.
	tg, err := e.st.FindTargetByAddr(context.Background(), "127.0.0.1", e.main.Port)
	if err != nil {
		t.Fatal(err)
	}
	tg, _ = e.st.GetTarget(context.Background(), tg.ID)
	if tg.Kind != "proxmox" || tg.Name != "lab" || tg.Cluster != "lab" || len(tg.Nodes) != 3 ||
		tg.HostKeyFP != res.HostKeyFP || tg.APICertFP != res.APICertFP || tg.TokenID != proxmox.TokenID {
		t.Fatalf("%+v", tg)
	}
	sec, err := e.sec.Get(context.Background(), tg.TokenSecretRef)
	if err != nil || string(sec) != tokenValue {
		t.Fatalf("stored token: %q %v", sec, err)
	}
	// Credentials left memory.
	if e.svc.SessionCount() != 0 {
		t.Fatal("probe session survived a successful connect")
	}
	// Neither the password nor the token leaks into jobs, logs or DB files.
	assertNoSecrets(t, e, j, rootPassword, tokenValue)
}

func assertNoSecrets(t *testing.T, e *env, j store.Job, secretsList ...string) {
	t.Helper()
	text := e.jobText(j) + j.Error
	for _, s := range j.Steps {
		text += s.Title + s.Error
	}
	rows, err := e.st.DB().Query(`SELECT line FROM job_log UNION ALL SELECT error FROM jobs UNION ALL SELECT error FROM job_steps`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var l string
		_ = rows.Scan(&l)
		text += l
	}
	rows.Close()
	for _, s := range secretsList {
		if strings.Contains(text, s) {
			t.Errorf("secret %q found in job data", s)
		}
	}
	_, _ = e.st.DB().Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	ents, _ := os.ReadDir(e.dir)
	for _, ent := range ents {
		b, _ := os.ReadFile(filepath.Join(e.dir, ent.Name()))
		for _, s := range secretsList {
			if strings.Contains(string(b), s) {
				t.Errorf("secret %q found in file %s", s, ent.Name())
			}
		}
	}
}

func TestConnectTokenStepFailureRollsEverythingBack(t *testing.T) {
	host := newFakeProxmox("", "solo")
	host.failTokenAdd = true
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	job, err := e.svc.Connect(context.Background(), e.confirm(res))
	if err != nil {
		t.Fatal(err)
	}
	j := e.waitJob(job)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "permission denied") || !strings.Contains(j.Error, "откатан") {
		t.Fatalf("%s: %q", j.Status, j.Error)
	}
	if len(host.roles) != 0 || len(host.users) != 0 || len(host.acl) != 0 || len(host.tokens) != 0 || host.authKeys != "" {
		t.Fatalf("not rolled back: roles=%v users=%v acl=%v tokens=%v keys=%q", host.roles, host.users, host.acl, host.tokens, host.authKeys)
	}
	ts, _ := e.st.ListTargets(context.Background())
	if len(ts) != 0 {
		t.Fatal("target saved despite failure")
	}
	// The failed step is visible and the probe session is usable for a retry.
	failed := false
	for _, s := range j.Steps {
		if s.Status == store.StepFailed && strings.Contains(s.Title, "API-токен") {
			failed = true
		}
	}
	if !failed {
		t.Fatalf("steps: %+v", j.Steps)
	}
	if e.svc.SessionCount() != 1 {
		t.Fatal("session should survive a failed connect")
	}
	host.mu.Lock()
	host.failTokenAdd = false
	host.mu.Unlock()
	job, err = e.svc.Connect(context.Background(), e.confirm(res))
	if err != nil {
		t.Fatal(err)
	}
	if j := e.waitJob(job); j.Status != store.JobDone {
		t.Fatalf("retry: %s %s", j.Status, j.Error)
	}
}

func TestRollbackKeepsPreexistingObjects(t *testing.T) {
	host := newFakeProxmox("", "solo")
	host.users[proxmox.UserID] = true // user exists, role does not
	host.failTokenAdd = true
	host.authKeys = "ssh-rsa AAAAother admin@pc\n"
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	if j := e.waitJob(job); j.Status != store.JobFailed {
		t.Fatal(j.Status)
	}
	if !host.users[proxmox.UserID] {
		t.Fatal("pre-existing user was deleted by the rollback")
	}
	if len(host.roles) != 0 || len(host.acl) != 0 {
		t.Fatalf("created objects not removed: %v %v", host.roles, host.acl)
	}
	if host.authKeys != "ssh-rsa AAAAother admin@pc\n" {
		t.Fatalf("authorized_keys changed: %q", host.authKeys)
	}
}

func TestReconnectWithExistingRoleUserTokenAndKey(t *testing.T) {
	host := newFakeProxmox("", "solo")
	host.roles[proxmox.RoleName] = "Extra.Priv,Sys.Audit"
	host.users[proxmox.UserID] = true
	host.tokens[proxmox.TokenName] = "old-secret-value"
	host.acl["/|hestia@pve|Hestia"] = true
	e := newEnv(t, host)
	host.authKeys = "ssh-rsa AAAAother admin@pc\n" + e.id.AuthorizedKey + "\n"

	res := probeOK(t, e, "proxmox")
	if planIDs(res) != "role,user,acl,token,ssh_key,verify" {
		t.Fatalf("plan %s", planIDs(res))
	}
	byID := map[string]onboard.PlanItem{}
	for _, p := range res.Plan {
		byID[p.ID] = p
	}
	if !strings.Contains(byID["role"].Title, "Дополнить") || !strings.Contains(byID["user"].Title, "уже есть") ||
		!strings.Contains(byID["token"].Title, "Пересоздать") || !strings.Contains(byID["ssh_key"].Title, "уже в authorized_keys") {
		t.Fatalf("%+v", byID)
	}
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	j := e.waitJob(job)
	if j.Status != store.JobDone {
		t.Fatalf("%s %s\n%s", j.Status, j.Error, e.jobText(j))
	}
	// Existing extra privileges are kept; required ones are added.
	privs := host.roles[proxmox.RoleName]
	if !strings.Contains(privs, "Extra.Priv") || !strings.Contains(privs, "VM.Clone") || !strings.Contains(privs, "Pool.Audit") {
		t.Fatalf("privs: %s", privs)
	}
	if host.tokens[proxmox.TokenName] != tokenValue {
		t.Fatal("token not recreated")
	}
	if host.keyLines() != 2 {
		t.Fatalf("key duplicated: %q", host.authKeys)
	}
	for _, c := range host.commands() {
		if c == proxmox.CmdUserAdd || c == proxmox.CmdACLAdd {
			t.Fatalf("recreated existing object: %s", c)
		}
	}
}

func TestHostKeyChangeBetweenProbeAndConnect(t *testing.T) {
	host := newFakeProxmox("", "solo")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	e.main.SetHostKey(sshxtest.NewSigner(t))
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	j := e.waitJob(job)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "изменился") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if len(host.roles)+len(host.users)+len(host.tokens) != 0 {
		t.Fatal("changes made over an untrusted connection")
	}
	// A fresh probe shows the new fingerprint.
	res2 := probeOK(t, e, "proxmox")
	if res2.HostKeyFP == res.HostKeyFP {
		t.Fatal("fingerprint not refreshed")
	}
}

func TestAPICertChangeBetweenProbeAndConnect(t *testing.T) {
	host := newFakeProxmox("", "solo")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	e.svc.FetchCertFP = func(context.Context, string, int) (string, error) { return "AA:BB", nil }
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	j := e.waitJob(job)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "сертификата") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if len(host.roles)+len(host.users)+len(host.tokens) != 0 {
		t.Fatal("changes made despite cert change")
	}
}

func TestConnectConfirmationErrors(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "solo"))
	res := probeOK(t, e, "proxmox")

	check := func(name string, mut func(*onboard.CreateRequest), status int) {
		t.Helper()
		c := e.confirm(res)
		mut(&c)
		_, err := e.svc.Connect(context.Background(), c)
		if oe := asErr(t, err); oe.Status != status {
			t.Errorf("%s: %d %s", name, oe.Status, oe.Msg)
		}
	}
	check("wrong host fp", func(c *onboard.CreateRequest) { c.Accept.HostKeyFP = "SHA256:nope" }, 409)
	check("wrong api fp", func(c *onboard.CreateRequest) { c.Accept.APICertFP = "AA" }, 409)
	check("missing api fp", func(c *onboard.CreateRequest) { c.Accept.APICertFP = "" }, 400)
	check("long name", func(c *onboard.CreateRequest) { c.Name = strings.Repeat("я", 65) }, 400)
	check("unknown probe", func(c *onboard.CreateRequest) { c.ProbeID = "deadbeef" }, 410)
	if e.svc.SessionCount() != 1 {
		t.Fatal("rejected confirmations must not consume the session")
	}
}

func TestProbeSessionExpires(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "solo"))
	res := probeOK(t, e, "proxmox")
	e.now = e.now.Add(onboard.SessionTTL + time.Second)
	_, err := e.svc.Connect(context.Background(), e.confirm(res))
	if oe := asErr(t, err); oe.Status != 410 {
		t.Fatalf("%+v", oe)
	}
	if e.svc.SessionCount() != 0 {
		t.Fatal("expired session kept (credentials still in memory)")
	}
}

func TestDuplicateTargetRejected(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "solo"))
	res := probeOK(t, e, "proxmox")
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	if j := e.waitJob(job); j.Status != store.JobDone {
		t.Fatal(j.Error)
	}
	res2 := probeOK(t, e, "proxmox")
	_, err := e.svc.Connect(context.Background(), e.confirm(res2))
	if oe := asErr(t, err); oe.Status != 409 || !strings.Contains(oe.Msg, "уже подключена") {
		t.Fatalf("%+v", oe)
	}
}

func TestSSHServerProbeAndConnect(t *testing.T) {
	host := newFakeProxmox("", "web1")
	host.isProxmox = false
	e := newEnv(t, host)
	res := probeOK(t, e, "ssh")
	f := res.Facts
	if f == nil || f.OS != "Debian GNU/Linux 12 (bookworm)" || f.CPUs != 4 || f.MemTotal != 8000000000 || f.Arch != "x86_64" ||
		f.Docker || !f.IsRoot() || len(f.Disks) != 1 || f.Hostname != "web1" {
		t.Fatalf("%+v", f)
	}
	if res.APICertFP != "" || len(res.Warnings) != 0 || planIDs(res) != "ssh_key,verify" || res.SuggestedName != "web1" {
		t.Fatalf("%+v", res)
	}
	job, err := e.svc.Connect(context.Background(), onboard.CreateRequest{ProbeID: res.ProbeID, Name: "  Мой сервер ",
		Accept: struct {
			HostKeyFP string `json:"host_key_fp"`
			APICertFP string `json:"api_cert_fp"`
		}{HostKeyFP: res.HostKeyFP}})
	if err != nil {
		t.Fatal(err)
	}
	j := e.waitJob(job)
	if j.Status != store.JobDone {
		t.Fatalf("%s %s\n%s", j.Status, j.Error, e.jobText(j))
	}
	if host.keyLines() != 1 {
		t.Fatalf("keys: %q", host.authKeys)
	}
	ts, _ := e.st.ListTargets(context.Background())
	if len(ts) != 1 || ts[0].Kind != "ssh" || ts[0].Name != "Мой сервер" || ts[0].TokenSecretRef != 0 || ts[0].APICertFP != "" {
		t.Fatalf("%+v", ts)
	}
	assertNoSecrets(t, e, j, rootPassword)
}

func TestSSHServerNonRootWithoutSudoWarns(t *testing.T) {
	host := newFakeProxmox("", "web1")
	host.isProxmox = false
	host.uid = "1000"
	host.hasSudo = false
	e := newEnv(t, host)
	res := probeOK(t, e, "ssh")
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "sudo") || res.Facts.IsRoot() || res.Facts.Sudo {
		t.Fatalf("%+v", res)
	}
}

func TestSSHConnectKeyLoginFailureRollsBackKey(t *testing.T) {
	host := newFakeProxmox("", "web1")
	host.isProxmox = false
	e := newEnv(t, host)
	e.main.KeyAuth = func(string, ssh.PublicKey) bool { return false } // server never accepts keys
	res := probeOK(t, e, "ssh")
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	j := e.waitJob(job)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "вход ключом") || !strings.Contains(j.Error, "откатан") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if host.authKeys != "" && strings.TrimSpace(host.authKeys) != "" {
		t.Fatalf("key left behind: %q", host.authKeys)
	}
}

func TestRemoveWithRevertCleansProxmox(t *testing.T) {
	host := newFakeProxmox("lab", "pve1", "pve2", "pve3")
	e := newEnv(t, host)
	// An unrelated key must survive the revert.
	host.authKeys = "ssh-rsa AAAAother admin@pc\n"
	res := probeOK(t, e, "proxmox")
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	if j := e.waitJob(job); j.Status != store.JobDone {
		t.Fatalf("%s\n%s", j.Error, e.jobText(j))
	}
	ts, _ := e.st.ListTargets(context.Background())
	ref := ts[0].TokenSecretRef

	rj, err := e.svc.Remove(context.Background(), ts[0].ID, true)
	if err != nil {
		t.Fatal(err)
	}
	j := e.waitJob(rj)
	if j.Status != store.JobDone {
		t.Fatalf("%s %s\n%s", j.Status, j.Error, e.jobText(j))
	}
	if len(host.roles) != 0 || len(host.users) != 0 || len(host.acl) != 0 || len(host.tokens) != 0 {
		t.Fatalf("not reverted: %v %v %v %v", host.roles, host.users, host.acl, host.tokens)
	}
	if host.authKeys != "ssh-rsa AAAAother admin@pc\n" {
		t.Fatalf("authorized_keys: %q", host.authKeys)
	}
	if ts, _ := e.st.ListTargets(context.Background()); len(ts) != 0 {
		t.Fatal("target not removed")
	}
	if _, err := e.sec.Get(context.Background(), ref); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("token secret survived: %v", err)
	}
}

func TestRemoveWithoutRevertOnlyForgets(t *testing.T) {
	host := newFakeProxmox("", "solo")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	e.waitJob(job)
	ts, _ := e.st.ListTargets(context.Background())
	before := len(host.commands())

	rj, err := e.svc.Remove(context.Background(), ts[0].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if j := e.waitJob(rj); j.Status != store.JobDone {
		t.Fatal(j.Error)
	}
	if len(host.commands()) != before {
		t.Fatal("revert=false touched the target")
	}
	if !host.users[proxmox.UserID] || host.tokens["hestia"] == "" {
		t.Fatal("remote state changed")
	}
	if ts, _ := e.st.ListTargets(context.Background()); len(ts) != 0 {
		t.Fatal("not forgotten")
	}
}

func TestRemoveWithRevertFailsOnChangedHostKey(t *testing.T) {
	host := newFakeProxmox("", "solo")
	e := newEnv(t, host)
	res := probeOK(t, e, "proxmox")
	job, _ := e.svc.Connect(context.Background(), e.confirm(res))
	e.waitJob(job)
	ts, _ := e.st.ListTargets(context.Background())
	e.main.SetHostKey(sshxtest.NewSigner(t))
	rj, _ := e.svc.Remove(context.Background(), ts[0].ID, true)
	j := e.waitJob(rj)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "изменился") || !strings.Contains(j.Error, "без отката") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if ts2, _ := e.st.ListTargets(context.Background()); len(ts2) != 1 {
		t.Fatal("target removed although the revert failed")
	}
	if !host.users[proxmox.UserID] {
		t.Fatal("remote state changed over an untrusted connection")
	}
}

func TestRemoveUnknownTarget(t *testing.T) {
	e := newEnv(t, newFakeProxmox("", "solo"))
	if _, err := e.svc.Remove(context.Background(), 999, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
