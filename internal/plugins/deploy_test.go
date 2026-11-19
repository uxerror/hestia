package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/plugins/deploytest"
	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

const (
	pveToken  = "hestia@pve!plugins"
	pveSecret = "0000-test-secret-1111"
)

// fakeLXC is the Proxmox API (TLS, token checked) answering the config of
// one container.
type fakeLXC struct {
	mu    sync.Mutex
	cfg   map[string]any
	calls []string
}

func (f *fakeLXC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "PVEAPIToken="+pveToken+"="+pveSecret {
		http.Error(w, "no auth", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/lxc/105/config" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": f.cfg})
}

func (f *fakeLXC) set(cfg map[string]any) {
	f.mu.Lock()
	f.cfg = cfg
	f.mu.Unlock()
}

type deployEnv struct {
	h   *harness
	tg  *deploytest.Target
	pve *fakeLXC
	ssh string
	lxc string
	iid int64
	s   *session
}

func newDeployEnv(t *testing.T) *deployEnv {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	if j := h.install(pkgFor(t, newKey(t), "v0.1.0", sdk.PermTargetsRead, sdk.PermDeployDocker)); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	h.waitConnected("demo")
	id, err := h.sec.EnsureIdentity(ctx, "testhost")
	if err != nil {
		t.Fatal(err)
	}
	tg := deploytest.New(t, id.Signer.PublicKey())

	pve := &fakeLXC{cfg: map[string]any{"unprivileged": 1, "features": "nesting=1", "hostname": "ct"}}
	srv := httptest.NewTLSServer(pve)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	ref, err := h.sec.Put(ctx, "proxmox-token", []byte(pveSecret))
	if err != nil {
		t.Fatal(err)
	}
	sshT := &store.Target{Kind: store.KindSSH, Name: "web", Host: tg.Srv.Host, Port: tg.Srv.Port, SSHUser: "root", HostKeyFP: tg.Srv.HostKeyFP()}
	pveT := &store.Target{Kind: store.KindProxmox, Name: "pve", Host: "localhost", Port: tg.Srv.Port, SSHUser: "root",
		APICertFP: proxmox.CertFingerprint(srv.Certificate().Raw), TokenID: pveToken, TokenSecretRef: ref,
		Nodes: []store.Node{{Name: "pve1", IP: tg.Srv.Host, Online: true, HostKeyFP: tg.Srv.HostKeyFP(), HostKeyType: "ssh-ed25519"}}}
	for _, x := range []*store.Target{sshT, pveT} {
		if err := h.st.CreateTarget(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	e := &deployEnv{h: h, tg: tg, pve: pve, ssh: fmt.Sprintf("ssh:%d", sshT.ID), lxc: fmt.Sprintf("lxc:%d:pve1:105", pveT.ID)}
	h.m.Targets = &SSHTargets{Store: h.st, Identity: id}
	h.m.PVEPort = port
	h.m.DeployPoll = 10 * time.Millisecond
	h.m.DeployWaitRunning = 500 * time.Millisecond
	h.m.DeployCTTimeout = 5 * time.Second

	inst := &store.PluginInstance{PluginID: "demo", Name: "x", Config: "{}", Status: "unknown"}
	if err := h.st.CreateInstance(ctx, inst, []store.PluginGrant{{Kind: "ssh", Ref: e.ssh}, {Kind: "lxc", Ref: e.lxc}}); err != nil {
		t.Fatal(err)
	}
	e.iid = inst.ID
	e.s = &session{m: h.m, pluginID: "demo", perms: map[string]bool{sdk.PermDeployDocker: true}, authed: true}
	return e
}

func (e *deployEnv) call(s *session, method string, params any) (json.RawMessage, error) {
	b, _ := json.Marshal(params)
	res, err := e.h.m.hostCall(context.Background(), s, method, b)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(res)
	return out, nil
}

// inJob runs fn inside an apply job of the instance (as instance.apply would).
func (e *deployEnv) inJob(t *testing.T, iid int64, confirmed bool, fn func(jobID string) error) store.Job {
	t.Helper()
	m := e.h.m
	job, err := e.h.runner.Start(JobApply, "deploy test", func(ctx context.Context, run *jobs.Run) error {
		a := &applyJob{pluginID: "demo", instanceID: iid, run: run, confirmed: confirmed}
		m.mu.Lock()
		m.applying[run.ID()] = a
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			delete(m.applying, run.ID())
			m.mu.Unlock()
		}()
		err := fn(run.ID())
		a.stepDone(err)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return e.h.wait(job.ID)
}

func helloCompose(port int, msg string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"services": map[string]any{"app": map[string]any{
		"image": "traefik/whoami:v1.10", "command": []string{"--name", msg}, "ports": []string{fmt.Sprintf("%d:80", port)},
		"restart": "unless-stopped", "volumes": []string{"./data:/data"},
	}}})
	return b
}

func (e *deployEnv) req(target, job string, compose json.RawMessage, files ...sdk.DeployFile) sdk.DeployRequest {
	return sdk.DeployRequest{JobID: job, Instance: e.iid, Target: target, Project: "web", Compose: compose, Files: files}
}

func (e *deployEnv) plan(t *testing.T, target string, compose json.RawMessage, files ...sdk.DeployFile) sdk.DeployPlan {
	t.Helper()
	b, err := e.call(e.s, sdk.MethodDeployPlan, e.req(target, "", compose, files...))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var pl sdk.DeployPlan
	if err := json.Unmarshal(b, &pl); err != nil {
		t.Fatal(err)
	}
	return pl
}

func (e *deployEnv) up(t *testing.T, target string, confirmed bool, compose json.RawMessage, files ...sdk.DeployFile) (store.Job, error) {
	t.Helper()
	var callErr error
	j := e.inJob(t, e.iid, confirmed, func(id string) error {
		_, callErr = e.call(e.s, sdk.MethodDeployUp, e.req(target, id, compose, files...))
		return callErr
	})
	return j, callErr
}

func titles(as []sdk.Action) string {
	var out []string
	for _, a := range as {
		out = append(out, a.Risk+": "+a.Title)
	}
	return strings.Join(out, "\n")
}

// Every deploy.* call checks the permission, the instance and the grant;
// up/down also the apply job.
func TestDeployDenied(t *testing.T) {
	e := newDeployEnv(t)
	ctx := context.Background()
	other := &store.PluginInstance{PluginID: "demo", Name: "y", Config: "{}", Status: "unknown"}
	if err := e.h.st.CreateInstance(ctx, other, nil); err != nil {
		t.Fatal(err)
	}
	compose := helloCompose(8080, "hi")
	noPerm := &session{m: e.h.m, pluginID: "demo", perms: map[string]bool{sdk.PermTargetsExec: true}, authed: true}
	foreign := &session{m: e.h.m, pluginID: "intruder", perms: map[string]bool{sdk.PermDeployDocker: true}, authed: true}
	type call struct {
		method string
		params func(job string) any
	}
	calls := []call{
		{sdk.MethodDeployPlan, func(job string) any { return e.req(e.ssh, job, compose) }},
		{sdk.MethodDeployUp, func(job string) any { return e.req(e.ssh, job, compose) }},
		{sdk.MethodDeployDown, func(job string) any {
			return sdk.DeployDownRequest{JobID: job, Instance: e.iid, Target: e.ssh, Project: "web"}
		}},
		{sdk.MethodDeployStatus, func(string) any { return sdk.DeployStatusRequest{Instance: e.iid, Target: e.ssh, Project: "web"} }},
	}
	want := func(t *testing.T, err error, sub string) {
		t.Helper()
		if !rpc.IsCode(err, rpc.CodePermission) || !strings.Contains(err.Error(), sub) {
			t.Fatalf("want permission denied (%s), got %v", sub, err)
		}
	}
	for _, c := range calls {
		t.Run(c.method, func(t *testing.T) {
			e.inJob(t, e.iid, false, func(job string) error {
				// No deploy.docker.
				_, err := e.call(noPerm, c.method, c.params(job))
				want(t, err, sdk.PermDeployDocker)
				// Instance of another plugin.
				_, err = e.call(foreign, c.method, c.params(job))
				want(t, err, "принадлежит другому плагину")
				// Unknown instance.
				b, _ := json.Marshal(c.params(job))
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				m["instance"] = 9999
				_, err = e.call(e.s, c.method, m)
				want(t, err, "не найден")
				// A target not granted to the instance.
				m["instance"], m["target"] = e.iid, "ssh:4242"
				_, err = e.call(e.s, c.method, m)
				want(t, err, "не выдана")
				if c.method == sdk.MethodDeployUp || c.method == sdk.MethodDeployDown {
					// No such job / the job of another instance.
					_, err = e.call(e.s, c.method, c.params("nope"))
					want(t, err, "не выполняется")
				}
				return nil
			})
		})
	}
	// The job of another instance.
	e.inJob(t, other.ID, false, func(job string) error {
		_, err := e.call(e.s, sdk.MethodDeployUp, e.req(e.ssh, job, compose))
		want(t, err, "не выполняется")
		return nil
	})
	// Nothing reached the target except the calls allowed above.
	for _, c := range e.tg.Commands() {
		if strings.Contains(c, "4242") {
			t.Fatalf("denied call reached the target: %s", c)
		}
	}
	// Bad parameters.
	for name, p := range map[string]sdk.DeployRequest{
		"project":  {Instance: e.iid, Target: e.ssh, Project: "../x", Compose: compose},
		"compose":  {Instance: e.iid, Target: e.ssh, Project: "web", Compose: json.RawMessage(`{"services":{"a":{"image":"x","privileged":true}}}`)},
		"file":     {Instance: e.iid, Target: e.ssh, Project: "web", Compose: compose, Files: []sdk.DeployFile{{Name: "a/b"}}},
		"reserved": {Instance: e.iid, Target: e.ssh, Project: "web", Compose: compose, Files: []sdk.DeployFile{{Name: "compose.yaml"}}},
		"big":      {Instance: e.iid, Target: e.ssh, Project: "web", Compose: compose, Files: []sdk.DeployFile{{Name: "x", Data: make([]byte, maxDeployFile+1)}}},
	} {
		if _, err := e.call(e.s, sdk.MethodDeployPlan, p); !rpc.IsCode(err, rpc.CodeInvalidParams) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDeployPlanSSH(t *testing.T) {
	e := newDeployEnv(t)
	env := sdk.DeployFile{Name: ".env", Data: []byte("A=1\n")}

	// Docker present, a new project.
	pl := e.plan(t, e.ssh, helloCompose(8080, "hi"), env)
	if pl.Project != fmt.Sprintf("hestia-%d-web", e.iid) || pl.Dir != fmt.Sprintf("/opt/hestia/%d-web", e.iid) ||
		pl.InstallDocker || pl.EnableFeatures || pl.Exists || len(pl.Files) != 2 || pl.Files[0].Action != sdk.FileCreate {
		t.Fatalf("%+v", pl)
	}
	got := titles(pl.Actions)
	if !strings.Contains(got, "change: Создать проект") || !strings.Contains(got, "up -d --remove-orphans") || len(pl.Warnings) != 0 {
		t.Fatalf("%s %v", got, pl.Warnings)
	}

	// The port is taken by something else: a warning.
	e.tg.Set("ss", "LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\n")
	pl = e.plan(t, e.ssh, helloCompose(8080, "hi"))
	if len(pl.Warnings) != 1 || !strings.Contains(pl.Warnings[0], "8080") {
		t.Fatalf("%v", pl.Warnings)
	}
	e.tg.Set("ss", "")

	// No Docker on Debian: install from the distribution.
	e.tg.RemoveDocker()
	pl = e.plan(t, e.ssh, helloCompose(8080, "hi"))
	if !pl.InstallDocker || !strings.Contains(titles(pl.Actions), "apt-get install -y docker.io docker-compose") {
		t.Fatalf("%s", titles(pl.Actions))
	}
	// Ubuntu: compose v2 has its own package.
	e.tg.SetOS("ubuntu", "debian", "Ubuntu 24.04 LTS")
	pl = e.plan(t, e.ssh, helloCompose(8080, "hi"))
	if !strings.Contains(titles(pl.Actions), "docker.io docker-compose-v2") {
		t.Fatalf("%s", titles(pl.Actions))
	}
	// Another OS: an error with the command.
	e.tg.SetOS("alpine", "", "Alpine Linux v3.20")
	_, err := e.call(e.s, sdk.MethodDeployPlan, e.req(e.ssh, "", helloCompose(8080, "hi")))
	if err == nil || !strings.Contains(err.Error(), "get.docker.com") || !strings.Contains(err.Error(), "Alpine") {
		t.Fatalf("%v", err)
	}
	// Docker without compose v2 (Debian): only the compose package.
	e.tg.SetOS("debian", "", "Debian GNU/Linux 13 (trixie)")
	e.tg.InstallDocker()
	e.tg.Flag("no-compose", true)
	pl = e.plan(t, e.ssh, helloCompose(8080, "hi"))
	if !pl.InstallDocker || !strings.Contains(titles(pl.Actions), "Установить docker compose v2: apt-get install -y docker-compose") {
		t.Fatalf("%s", titles(pl.Actions))
	}
}

func TestDeployUpUpdateRollback(t *testing.T) {
	e := newDeployEnv(t)
	dir := fmt.Sprintf("/opt/hestia/%d-web", e.iid)
	proj := fmt.Sprintf("hestia-%d-web", e.iid)
	env1 := sdk.DeployFile{Name: ".env", Data: []byte("A=1\n")}
	extra := sdk.DeployFile{Name: "extra.txt", Data: []byte("x\n")}

	// A new project.
	j, err := e.up(t, e.ssh, false, helloCompose(8080, "one"), env1, extra)
	if err != nil || j.Status != store.JobDone {
		t.Fatalf("%v\n%s", err, jobLog(j))
	}
	compose, ok := e.tg.File(dir + "/compose.yaml")
	if !ok || !strings.Contains(compose, `"hestia.plugin": "demo"`) || !strings.Contains(compose, `"one"`) {
		t.Fatalf("compose.yaml: %q", compose)
	}
	if v, _ := e.tg.File(dir + "/.env"); v != "A=1\n" {
		t.Fatalf(".env %q", v)
	}
	if list, _ := e.tg.File(dir + "/.hestia-files"); list != ".env\ncompose.yaml\nextra.txt\n" {
		t.Fatalf("list %q", list)
	}
	if !strings.Contains(e.tg.Log("docker.log"), "compose -p "+proj+" -f compose.yaml up -d --remove-orphans") {
		t.Fatal(e.tg.Log("docker.log"))
	}
	log := jobLog(j)
	for _, s := range []string{"step Проверка цели", "step Запись файлов", "step docker compose up -d", "step Ожидание запуска", proj + "-app-1: Up"} {
		if !strings.Contains(log, s) {
			t.Fatalf("no %q in\n%s", s, log)
		}
	}

	// Same content: unchanged.
	pl := e.plan(t, e.ssh, helloCompose(8080, "one"), env1, extra)
	if pl.Changed || !pl.Exists || !strings.Contains(titles(pl.Actions), "info: Файлы проекта") {
		t.Fatalf("%s", titles(pl.Actions))
	}
	// A new message, extra.txt dropped: update with a diff.
	env2 := sdk.DeployFile{Name: ".env", Data: []byte("A=2\n")}
	pl = e.plan(t, e.ssh, helloCompose(8080, "two"), env2)
	got := titles(pl.Actions)
	if !pl.Changed || !strings.Contains(got, "Изменить файлы проекта") || !strings.Contains(pl.Actions[0].Detail, "extra.txt: будет удалён") {
		t.Fatalf("%s %+v", got, pl.Actions)
	}

	// The update fails in `up`: the old files come back and are started.
	e.tg.Flag("fail-up", true)
	j, err = e.up(t, e.ssh, false, helloCompose(8080, "two"), env2)
	if err == nil || j.Status != store.JobFailed || !strings.Contains(j.Error, "fake failure") {
		t.Fatalf("%v %s\n%s", err, j.Error, jobLog(j))
	}
	if !strings.Contains(jobLog(j), "step Откат проекта") {
		t.Fatal(jobLog(j))
	}
	compose, _ = e.tg.File(dir + "/compose.yaml")
	if !strings.Contains(compose, `"one"`) {
		t.Fatalf("not rolled back: %s", compose)
	}
	if v, _ := e.tg.File(dir + "/extra.txt"); v != "x\n" {
		t.Fatalf("extra.txt %q", v)
	}
	if v, _ := e.tg.File(dir + "/.env"); v != "A=1\n" {
		t.Fatalf(".env %q", v)
	}
	if _, ok := e.tg.File(dir + "/.hestia-prev/.env"); ok {
		t.Fatal("backup left behind")
	}

	// The update succeeds; the stale file is removed.
	e.tg.Flag("fail-up", false)
	if j, err = e.up(t, e.ssh, false, helloCompose(8080, "two"), env2); err != nil {
		t.Fatalf("%v\n%s", err, jobLog(j))
	}
	if _, ok := e.tg.File(dir + "/extra.txt"); ok {
		t.Fatal("stale file kept")
	}
	if list, _ := e.tg.File(dir + "/.hestia-files"); list != ".env\ncompose.yaml\n" {
		t.Fatalf("list %q", list)
	}

	// Status.
	b, err := e.call(e.s, sdk.MethodDeployStatus, sdk.DeployStatusRequest{Instance: e.iid, Target: e.ssh, Project: "web"})
	if err != nil {
		t.Fatal(err)
	}
	var st sdk.DeployStatus
	_ = json.Unmarshal(b, &st)
	if !st.Exists || !st.Docker || !st.Running() || st.Containers[0].Ports[0].PublishedPort != 8080 {
		t.Fatalf("%s", b)
	}

	// Down with volumes.
	j = e.inJob(t, e.iid, false, func(job string) error {
		_, err := e.call(e.s, sdk.MethodDeployDown, sdk.DeployDownRequest{JobID: job, Instance: e.iid, Target: e.ssh, Project: "web", Volumes: true})
		return err
	})
	if j.Status != store.JobDone || !strings.Contains(e.tg.Log("docker.log"), "compose -p "+proj+" -f compose.yaml down -v --remove-orphans") {
		t.Fatalf("%s\n%s", jobLog(j), e.tg.Log("docker.log"))
	}
	if _, ok := e.tg.File(dir + "/compose.yaml"); ok {
		t.Fatal("directory kept")
	}
	b, _ = e.call(e.s, sdk.MethodDeployStatus, sdk.DeployStatusRequest{Instance: e.iid, Target: e.ssh, Project: "web"})
	_ = json.Unmarshal(b, &st)
	if st.Exists || len(st.Containers) != 0 {
		t.Fatalf("%s", b)
	}
}

func TestDeployNewProjectFails(t *testing.T) {
	e := newDeployEnv(t)
	dir := fmt.Sprintf("/opt/hestia/%d-web", e.iid)
	// Containers do not reach "running": the new project is taken down.
	e.tg.Set("state", "restarting")
	j, err := e.up(t, e.ssh, false, helloCompose(8080, "one"))
	if err == nil || !strings.Contains(j.Error, "не запустились") {
		t.Fatalf("%v %s\n%s", err, j.Error, jobLog(j))
	}
	if !strings.Contains(e.tg.Log("down.log"), "down -v --remove-orphans") {
		t.Fatal(e.tg.Log("down.log"))
	}
	if _, ok := e.tg.File(dir + "/compose.yaml"); ok {
		t.Fatal("new project directory kept")
	}
}

func TestDeployInstallsDocker(t *testing.T) {
	e := newDeployEnv(t)
	e.tg.RemoveDocker()
	j, err := e.up(t, e.ssh, false, helloCompose(8080, "one"))
	if err != nil {
		t.Fatalf("%v\n%s", err, jobLog(j))
	}
	if !strings.Contains(e.tg.Log("apt.log"), "install -y -q docker.io docker-compose") ||
		!strings.Contains(jobLog(j), "step Установка Docker") || !strings.Contains(jobLog(j), "docker compose 2.26.1") {
		t.Fatalf("%s\n%s", e.tg.Log("apt.log"), jobLog(j))
	}
	// apt fails: nothing is written.
	e2 := newDeployEnv(t)
	e2.tg.RemoveDocker()
	e2.tg.Flag("fail-apt", true)
	if j, err := e2.up(t, e2.ssh, false, helloCompose(8080, "one")); err == nil || !strings.Contains(j.Error, "fake apt failure") {
		t.Fatalf("%v %s", err, j.Error)
	}
	if _, ok := e2.tg.File(fmt.Sprintf("/opt/hestia/%d-web/compose.yaml", e2.iid)); ok {
		t.Fatal("files written after a failed install")
	}
}

func TestDeployLXCFeatures(t *testing.T) {
	e := newDeployEnv(t)
	// Unprivileged with nesting only: keyctl is missing → a danger action.
	pl := e.plan(t, e.lxc, helloCompose(8080, "one"))
	if !pl.EnableFeatures || pl.Actions[0].Risk != sdk.RiskDanger || !strings.Contains(pl.Actions[0].Title, "nesting и keyctl для CT 105") ||
		!strings.Contains(pl.Actions[0].Detail, "nesting=1,keyctl=1") {
		t.Fatalf("%+v", pl.Actions)
	}
	// The commands of the plan ran inside the container.
	if !strings.Contains(strings.Join(e.tg.Commands(), "\n"), "pct exec 105 -- sh -c") {
		t.Fatal(e.tg.Commands())
	}
	// Not confirmed: refused before anything changes.
	j, err := e.up(t, e.lxc, false, helloCompose(8080, "one"))
	if err == nil || !strings.Contains(j.Error, "не подтверждено") || strings.Contains(e.tg.Log("pct.log"), "--features") {
		t.Fatalf("%v %s %s", err, j.Error, e.tg.Log("pct.log"))
	}
	// Confirmed: pct set + reboot on the node, then the deploy.
	j, err = e.up(t, e.lxc, true, helloCompose(8080, "one"))
	if err != nil {
		t.Fatalf("%v\n%s", err, jobLog(j))
	}
	pct := e.tg.Log("pct.log")
	if !strings.Contains(pct, "set 105 --features nesting=1,keyctl=1") || !strings.Contains(pct, "reboot 105") {
		t.Fatal(pct)
	}
	// The node failing to change the features stops the deploy.
	e.tg.Flag("fail-pct", true)
	if _, err := e.up(t, e.lxc, true, helloCompose(8080, "one")); err == nil || !strings.Contains(err.Error(), "fake failure") {
		t.Fatalf("%v", err)
	}
	e.tg.Flag("fail-pct", false)

	// Privileged with nesting: nothing to do (keyctl is not needed).
	e.pve.set(map[string]any{"features": "nesting=1"})
	if pl := e.plan(t, e.lxc, helloCompose(8080, "one")); pl.EnableFeatures {
		t.Fatalf("%+v", pl.Actions)
	}
	// Privileged without nesting.
	e.pve.set(map[string]any{"features": "fuse=1"})
	if pl := e.plan(t, e.lxc, helloCompose(8080, "one")); !pl.EnableFeatures || !strings.Contains(pl.Actions[0].Detail, "fuse=1,nesting=1") ||
		strings.Contains(pl.Actions[0].Title, "keyctl") {
		t.Fatalf("%+v", pl.Actions)
	}
	// The API refuses: the plan fails with the reason.
	e.h.m.PVE = func(ctx context.Context, tg store.Target) (LXCConfigAPI, error) {
		return proxmox.NewClient(proxmox.ClientConfig{Host: tg.Host, Port: e.h.m.PVEPort, TokenID: tg.TokenID, Secret: "wrong", PinFP: tg.APICertFP}), nil
	}
	if _, err := e.call(e.s, sdk.MethodDeployPlan, e.req(e.lxc, "", helloCompose(8080, "one"))); err == nil || !strings.Contains(err.Error(), "API Proxmox") {
		t.Fatalf("%v", err)
	}
}

// deployPlugin plans and applies through the SDK (the real call path).
type deployPlugin struct{ testPlugin }

func (p *deployPlugin) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	h := sdk.HostFrom(ctx)
	if req.Action == sdk.ActionRemove {
		return sdk.Plan{Actions: []sdk.Action{{Title: "down", Risk: sdk.RiskChange}}}, nil
	}
	dp, err := h.DeployPlan(ctx, sdk.DeployRequest{Instance: req.Instance.ID, Target: req.Config.String("target"), Project: "web",
		Compose: helloCompose(8080, req.Config.String("message"))})
	if err != nil {
		return sdk.Plan{}, err
	}
	return sdk.Plan{Actions: dp.Actions, Warnings: dp.Warnings}, nil
}

func (p *deployPlugin) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	h := job.Host()
	tgt := req.Instance.Config.String("target")
	if req.Action == sdk.ActionRemove {
		return h.DeployDown(ctx, sdk.DeployDownRequest{JobID: job.ID, Instance: req.Instance.ID, Target: tgt, Project: "web", Volumes: true})
	}
	st, err := h.DeployUp(ctx, sdk.DeployRequest{JobID: job.ID, Instance: req.Instance.ID, Target: req.Config.String("target"), Project: "web",
		Compose: helloCompose(8080, req.Config.String("message"))})
	if err != nil {
		return err
	}
	job.Logf("running=%v", st.Running())
	return nil
}

func (p *deployPlugin) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	st, err := sdk.HostFrom(ctx).DeployStatus(ctx, sdk.DeployStatusRequest{Instance: inst.ID, Target: inst.Config.String("target"), Project: "web"})
	if err != nil {
		return sdk.Status{}, err
	}
	if st.Running() {
		return sdk.Status{State: sdk.StateOK}, nil
	}
	return sdk.Status{State: sdk.StateDown}, nil
}

func TestDeployThroughSDK(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dp := &deployPlugin{}
	h.plug = func(string) sdk.Plugin { return dp }
	if j := h.install(pkgFor(t, newKey(t), "v0.1.0", sdk.PermTargetsRead, sdk.PermDeployDocker)); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	h.waitConnected("demo")
	id, _ := h.sec.EnsureIdentity(ctx, "testhost")
	tg := deploytest.New(t, id.Signer.PublicKey())
	st := &store.Target{Kind: store.KindSSH, Name: "web", Host: tg.Srv.Host, Port: tg.Srv.Port, SSHUser: "root", HostKeyFP: tg.Srv.HostKeyFP()}
	if err := h.st.CreateTarget(ctx, st); err != nil {
		t.Fatal(err)
	}
	h.m.Targets = &SSHTargets{Store: h.st, Identity: id}
	h.m.DeployPoll = 10 * time.Millisecond
	ref := fmt.Sprintf("ssh:%d", st.ID)

	pv, err := h.m.CreatePlan(ctx, "demo", "", map[string]any{"target": ref, "message": "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(titles(pv.Plan.Actions), "Создать проект") {
		t.Fatalf("%+v", pv.Plan)
	}
	j := applyPlan(t, h, pv, false)
	if j.Status != store.JobDone || !strings.Contains(jobLog(j), "running=true") {
		t.Fatal(jobLog(j))
	}
	v, err := h.m.Instance(ctx, pv.Instance.ID, true)
	if err != nil || v.Status != "ok" {
		t.Fatalf("%v %+v", err, v)
	}
	pv, err = h.m.ChangePlan(ctx, pv.Instance.ID, "remove", nil)
	if err != nil {
		t.Fatal(err)
	}
	if j := applyPlan(t, h, pv, false); j.Status != store.JobDone || !strings.Contains(tg.Log("down.log"), "down -v") {
		t.Fatalf("%s\n%s", jobLog(j), tg.Log("down.log"))
	}
}

// A container that could write into the project directory must not make
// Hestia (root) touch files outside it through .hestia-files.
func TestDeployTamperedList(t *testing.T) {
	e := newDeployEnv(t)
	dir := fmt.Sprintf("/opt/hestia/%d-web", e.iid)
	if _, err := e.up(t, e.ssh, false, helloCompose(8080, "one")); err != nil {
		t.Fatal(err)
	}
	e.tg.WriteFile("/opt/hestia/victim", "keep\n")
	e.tg.WriteFile(dir+"/.hestia-files", "../victim\ncompose.yaml\n*\n")
	pl := e.plan(t, e.ssh, helloCompose(8080, "two"))
	for _, f := range pl.Files {
		if strings.Contains(f.Name, "victim") || f.Name == "*" {
			t.Fatalf("foreign name in the plan: %+v", pl.Files)
		}
	}
	e.tg.Flag("fail-up", true)
	if _, err := e.up(t, e.ssh, false, helloCompose(8080, "two")); err == nil {
		t.Fatal("up did not fail")
	}
	if v, ok := e.tg.File("/opt/hestia/victim"); !ok || v != "keep\n" {
		t.Fatalf("file outside the project touched: %q %v", v, ok)
	}
	if c, _ := e.tg.File(dir + "/compose.yaml"); !strings.Contains(c, `"one"`) {
		t.Fatalf("not rolled back: %s", c)
	}
}
