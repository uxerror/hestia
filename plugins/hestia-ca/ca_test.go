package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/caserver"
	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/sdktest"
	"github.com/uxerror/hestia/sdk/types"
)

// env is the plugin against a fake Hestia and an in-process ca-server
// standing for the container (deploy.up hands it the token's sha256).
type env struct {
	t    *testing.T
	h    *sdktest.Host
	p    *caPlugin
	srv  *caserver.Server
	addr string

	mu       sync.Mutex
	composes []map[string]any
	downs    []sdk.DeployDownRequest
	pinLie   bool
	osRel    map[string]string // device → /etc/os-release
	inBundle map[string]bool
	execs    []sdk.ExecRequest
}

const inst = int64(7)

func newEnv(t *testing.T) *env {
	t.Helper()
	healthWait, healthPoll = 3*time.Second, 20*time.Millisecond
	srv := &caserver.Server{Dir: filepath.Join(t.TempDir(), "data"), LeafMax: 90 * 24 * time.Hour, Version: "v0.1.0",
		FailDelay: 10 * time.Millisecond, BackupIter: 100000, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := srv.APICert(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	e := &env{t: t, srv: srv, addr: ln.Addr().String(), osRel: map[string]string{}, inBundle: map[string]bool{}}
	e.p = &caPlugin{Version: "v0.1.0", TestAddr: e.addr, StateDir: t.TempDir()}
	e.h = sdktest.New(t, manifest, e.p)
	e.h.Handle(sdk.MethodTargetList, func(json.RawMessage) (any, error) {
		return []sdk.TargetInfo{{ID: "ssh:1", Kind: "ssh", Name: "ca", Address: "10.10.10.40", DockerCapable: true}}, nil
	})
	e.h.OnDeployPlan(func(r sdk.DeployRequest) (sdk.DeployPlan, error) {
		if len(r.Images) != 1 || r.Images[0] != imageName {
			return sdk.DeployPlan{}, errors.New("no images")
		}
		return sdk.DeployPlan{Actions: []sdk.Action{{Title: "Загрузить образ ca-server", Risk: sdk.RiskChange}}}, nil
	})
	e.h.OnDeployUp(func(r sdk.DeployRequest) (sdk.DeployStatus, error) {
		var c map[string]any
		_ = json.Unmarshal(r.Compose, &c)
		e.mu.Lock()
		e.composes = append(e.composes, c)
		e.mu.Unlock()
		env := c["services"].(map[string]any)["ca"].(map[string]any)["environment"].(map[string]any)
		srv.SetTokenSHA(env["HESTIA_CA_TOKEN_SHA256"].(string))
		return sdk.DeployStatus{}, nil
	})
	e.h.OnDeployDown(func(r sdk.DeployDownRequest) error {
		e.mu.Lock()
		e.downs = append(e.downs, r)
		e.mu.Unlock()
		return nil
	})
	e.h.OnExec(func(r sdk.ExecRequest) (sdk.ExecResult, error) {
		e.mu.Lock()
		e.execs = append(e.execs, r)
		lie := e.pinLie
		e.mu.Unlock()
		switch {
		case strings.HasPrefix(r.Cmd, "docker exec "+containerName(inst)+" /ca-server api-pin"):
			pin, err := caserver.APIPin(srv.Dir)
			if lie {
				pin = strings.Repeat("a", 64)
			}
			return sdk.ExecResult{Stdout: pin + "\n"}, err
		case strings.HasPrefix(r.Cmd, "docker exec "+containerName(inst)+" /ca-server root-sha256"):
			fp, err := caserver.RootSHA256(srv.Dir)
			return sdk.ExecResult{Stdout: fp + "\n"}, err
		case r.Cmd == osProbe:
			e.mu.Lock()
			defer e.mu.Unlock()
			return sdk.ExecResult{Stdout: e.osRel[r.Target]}, nil
		case strings.Contains(r.Cmd, "grep -qxF"):
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.inBundle[r.Target] {
				return sdk.ExecResult{Stdout: "found\n"}, nil
			}
			return sdk.ExecResult{Stdout: "missing\n"}, nil
		}
		return sdk.ExecResult{}, nil
	})
	return e
}

func cfg(mod map[string]any) sdk.Config {
	c := sdk.Config{"target": "ssh:1", "port": float64(9443), "zones": "home,home.arpa", "ip_ranges": pki.DefaultIPRanges,
		"init": "new", "leaf_days": float64(90), "root_years": float64(10), "test_lifetime_min": float64(0)}
	for k, v := range mod {
		c[k] = v
	}
	return c
}

func (e *env) create(c sdk.Config) error {
	ctx := context.Background()
	pl, err := e.h.Plan(ctx, sdk.PlanRequest{Instance: sdk.Instance{ID: inst, Name: "HestiaCA"}, Config: c, Action: sdk.ActionCreate})
	if err != nil {
		return err
	}
	return e.h.Apply(ctx, sdk.ApplyRequest{JobID: "j1", Instance: sdk.Instance{ID: inst, Name: "HestiaCA", Config: c}, Config: c,
		Action: sdk.ActionCreate, Plan: pl})
}

func (e *env) instance(c sdk.Config) sdk.Instance {
	return sdk.Instance{ID: inst, Name: "HestiaCA", Config: c}
}

func newCSR(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := pki.NewCSR(k, "x")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCreateIssueAndActions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := cfg(nil)
	pl, err := e.h.Plan(ctx, sdk.PlanRequest{Instance: sdk.Instance{ID: inst}, Config: c, Action: sdk.ActionCreate})
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, a := range pl.Actions {
		titles = append(titles, a.Title)
	}
	if !strings.Contains(strings.Join(titles, "\n"), "Создать корневой CA (ECDSA P-256, 10 лет, зоны: home, home.arpa") ||
		!strings.Contains(strings.Join(pl.Warnings, "\n"), "Зоны нельзя будет изменить") {
		t.Fatalf("%v %v", titles, pl.Warnings)
	}
	if err := e.create(c); err != nil {
		t.Fatal(err)
	}
	tok, ok := e.h.Secret(inst, secretToken)
	pin, ok2 := e.h.Secret(inst, secretPin)
	if !ok || !ok2 || len(tok) != 64 || len(pin) != 64 {
		t.Fatal("secrets")
	}
	svc := e.composes[len(e.composes)-1]["services"].(map[string]any)["ca"].(map[string]any)
	b, _ := json.Marshal(svc)
	for _, want := range []string{`"image":"hestia.local/hestia-ca/ca-server:v0.1.0"`, `"read_only":true`, `"cap_drop":["ALL"]`,
		`"pull_policy":"never"`, caserver.HashToken(tok), `"ca-data:/data"`, `"HESTIA_CA_LEAF_MAX":"2160h"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("compose has no %s: %s", want, b)
		}
	}
	if strings.Contains(string(b), tok) {
		t.Fatal("the token itself is in the compose file")
	}
	st, err := e.h.Status(ctx, e.instance(c))
	if err != nil || st.State != sdk.StateOK || !strings.Contains(st.Detail, "Корень до") || strings.Join(st.ActionsEnabled, ",") != "root,backup" {
		t.Fatalf("status %+v %v", st, err)
	}

	// tls: the preview is checked against the zones of the root.
	lreq := sdk.LinkRequest{Link: 5, Kind: sdk.LinkService, Role: sdk.RoleProvider, Instance: e.instance(c), Port: portTLS, Type: types.TLSCertType}
	lreq.Request = json.RawMessage(`{"dns":["hestia.lan"],"ips":["10.10.10.30"]}`)
	if _, err := e.h.LinkPlan(ctx, lreq); err == nil || !strings.Contains(err.Error(), "hestia.lan") {
		t.Fatalf("out of zones: %v", err)
	}
	lreq.Request = json.RawMessage(`{"dns":["hestia.home"],"ips":["10.10.10.30"]}`)
	lpl, err := e.h.LinkPlan(ctx, lreq)
	if err != nil || !strings.Contains(lpl.Actions[0].Title, "Выпустить сертификат на hestia.home, 10.10.10.30 сроком 90 дней") {
		t.Fatalf("plan %+v %v", lpl, err)
	}
	r := types.TLSRequest{CSRPEM: newCSR(t), DNS: []string{"hestia.home"}, IPs: []string{"10.10.10.30"}}
	lreq.Request, _ = json.Marshal(r)
	raw, err := e.h.LinkApply(ctx, lreq)
	if err != nil {
		t.Fatal(err)
	}
	var bnd types.TLSCert
	if err := json.Unmarshal(raw, &bnd); err != nil {
		t.Fatal(err)
	}
	if _, err := types.Validate(types.TLSCertType, raw, false); err != nil {
		t.Fatal(err)
	}
	if err := types.CheckTLSCert(bnd, r, "", time.Now()); err != nil {
		t.Fatalf("Hestia would refuse the binding: %v", err)
	}
	if ls, _ := e.h.LinkStatus(ctx, lreq); ls.State != sdk.StateOK {
		t.Fatalf("link status %+v", ls)
	}
	if err := e.h.LinkRemove(ctx, lreq); err != nil {
		t.Fatal(err)
	}
	if ls, _ := e.h.LinkStatus(ctx, lreq); ls.State != sdk.StateDown {
		t.Fatalf("after revoke %+v", ls)
	}
	// ca.issuer service binding.
	treq := sdk.LinkRequest{Link: 6, Kind: sdk.LinkService, Role: sdk.RoleProvider, Instance: e.instance(c), Port: portTrust, Type: types.CAIssuerType}
	if raw, err := e.h.LinkApply(ctx, treq); err != nil || !strings.Contains(string(raw), `"issue":"tls.cert"`) {
		t.Fatalf("issuer %s %v", raw, err)
	}

	// Actions: root, backup (encrypted; the passphrase is nowhere).
	res, err := e.h.Action(ctx, sdk.ActionRequest{JobID: "a1", Instance: e.instance(c), Action: "root"})
	if err != nil || res.Download == nil || !strings.Contains(string(res.Download.Data), "BEGIN CERTIFICATE") {
		t.Fatalf("root %+v %v", res, err)
	}
	pass := "a long backup passphrase"
	res, err = e.h.Action(ctx, sdk.ActionRequest{JobID: "a2", Instance: e.instance(c), Action: "backup", Params: sdk.Config{"passphrase": pass}})
	if err != nil || res.Download == nil || !strings.HasPrefix(res.Download.Name, "hestia-ca-") {
		t.Fatalf("backup %+v %v", res, err)
	}
	if strings.Contains(string(res.Download.Data), "PRIVATE KEY") || e.p.lastBackup(inst) == "" {
		t.Fatal("backup not encrypted or not remembered")
	}
	all, _ := json.Marshal([]any{e.h.JobLog(), e.h.SysLog(), e.h.Steps()})
	for _, s := range []string{pass, tok} {
		if strings.Contains(string(all), s) {
			t.Fatalf("a secret is in the logs: %s", all)
		}
	}
	// A wrong or short passphrase comes back as the CA's message only.
	if _, err := e.h.Action(ctx, sdk.ActionRequest{JobID: "a3", Instance: e.instance(c), Action: "backup", Params: sdk.Config{"passphrase": "short"}}); err == nil {
		t.Fatal("short passphrase accepted")
	}

	// update: immutable fields are refused, the port is fine.
	_, err = e.h.Plan(ctx, sdk.PlanRequest{Instance: e.instance(c), Config: cfg(map[string]any{"zones": "lan"}), Action: sdk.ActionUpdate})
	if err == nil || !strings.Contains(err.Error(), "zones") {
		t.Fatalf("zones changed: %v", err)
	}
	if _, err := e.h.Plan(ctx, sdk.PlanRequest{Instance: e.instance(c), Config: cfg(map[string]any{"leaf_days": float64(60)}), Action: sdk.ActionUpdate}); err != nil {
		t.Fatal(err)
	}
	// remove: danger, with the date of the backup.
	rp, err := e.h.Plan(ctx, sdk.PlanRequest{Instance: e.instance(c), Config: c, Action: sdk.ActionRemove})
	if err != nil || rp.Actions[0].Risk != sdk.RiskDanger || !strings.Contains(strings.Join(rp.Warnings, ""), "Последняя резервная копия") {
		t.Fatalf("remove %+v %v", rp, err)
	}
}

func TestCreatePinMismatch(t *testing.T) {
	e := newEnv(t)
	e.pinLie = true
	err := e.create(cfg(nil))
	if err == nil || !strings.Contains(err.Error(), "пин") {
		t.Fatalf("want pin error, got %v", err)
	}
	if len(e.downs) == 0 || !e.downs[0].Volumes {
		t.Fatalf("no rollback with volumes: %+v", e.downs)
	}
	if _, ok := e.h.Secret(inst, secretToken); ok {
		t.Fatal("token left after rollback")
	}
}

func TestRestorePath(t *testing.T) {
	// A backup from another CA.
	src := newEnv(t)
	if err := src.create(cfg(nil)); err != nil {
		t.Fatal(err)
	}
	pass := "another long passphrase"
	res, err := src.h.Action(context.Background(), sdk.ActionRequest{JobID: "a", Instance: src.instance(cfg(nil)), Action: "backup", Params: sdk.Config{"passphrase": pass}})
	if err != nil {
		t.Fatal(err)
	}
	srcFP, _ := caserver.RootSHA256(src.srv.Dir)

	e := newEnv(t)
	ctx := context.Background()
	c := cfg(map[string]any{"init": "restore"})
	if err := e.create(c); err != nil {
		t.Fatal(err)
	}
	st, _ := e.h.Status(ctx, e.instance(c))
	if st.State != sdk.StateDegraded || strings.Join(st.ActionsEnabled, ",") != "restore" {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.h.Action(ctx, sdk.ActionRequest{JobID: "r0", Instance: e.instance(c), Action: "restore",
		Params: sdk.Config{"backup": string(res.Download.Data), "passphrase": "wrong passphrase!"}}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	out, err := e.h.Action(ctx, sdk.ActionRequest{JobID: "r1", Instance: e.instance(c), Action: "restore",
		Params: sdk.Config{"backup": string(res.Download.Data), "passphrase": pass}})
	if err != nil || !strings.Contains(out.Message, pki.FingerprintColon(srcFP)) {
		t.Fatalf("restore %+v %v", out, err)
	}
	if st, _ := e.h.Status(ctx, e.instance(c)); st.State != sdk.StateOK {
		t.Fatalf("after restore %+v", st)
	}
}

func TestTrustDevice(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := cfg(nil)
	if err := e.create(c); err != nil {
		t.Fatal(err)
	}
	fp, _ := caserver.RootSHA256(e.srv.Dir)
	e.osRel["ssh:2"] = "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 12\"\nHESTIA_HAS_UPDATE=1\n"
	e.osRel["ssh:3"] = "ID=garuda\nID_LIKE=arch\nPRETTY_NAME=Garuda\n"
	e.osRel["ssh:4"] = "ID=freebsd\n"
	req := func(dev string, link int64) sdk.LinkRequest {
		return sdk.LinkRequest{Link: link, Kind: sdk.LinkDevice, Role: sdk.RoleClient, Instance: e.instance(c), Port: portTrust, Type: types.CAIssuerType,
			Device: &sdk.TargetInfo{ID: dev, Name: "CT 902"}}
	}
	pl, err := e.h.LinkPlan(ctx, req("ssh:2", 10))
	if err != nil || !strings.Contains(pl.Actions[0].Title, "Установить корень Hestia (SHA-256 "+pki.FingerprintColon(fp)) ||
		!strings.Contains(pl.Actions[0].Title, "Debian") {
		t.Fatalf("plan %+v %v", pl, err)
	}
	if _, err := e.h.LinkPlan(ctx, req("ssh:4", 12)); err == nil || !strings.Contains(err.Error(), "Не поддерживается: freebsd") {
		t.Fatalf("unknown os: %v", err)
	}
	r := req("ssh:2", 10)
	r.Plan = &pl
	if _, err := e.h.LinkApply(ctx, r); err != nil {
		t.Fatal(err)
	}
	last := e.execs[len(e.execs)-1]
	if !strings.Contains(last.Cmd, "/usr/local/share/ca-certificates/hestia-root-"+fp[:16]+".crt") || !strings.Contains(last.Cmd, "update-ca-certificates") ||
		!strings.Contains(last.Stdin, "BEGIN CERTIFICATE") {
		t.Fatalf("install %+v", last)
	}
	if ls, _ := e.h.LinkStatus(ctx, r); ls.State != sdk.StateDown {
		t.Fatalf("status before the bundle %+v", ls)
	}
	e.inBundle["ssh:2"] = true
	if ls, _ := e.h.LinkStatus(ctx, r); ls.State != sdk.StateOK {
		t.Fatalf("status %+v", ls)
	}
	// Arch: trust anchor.
	pa, err := e.h.LinkPlan(ctx, req("ssh:3", 11))
	if err != nil {
		t.Fatal(err)
	}
	ra := req("ssh:3", 11)
	ra.Plan = &pa
	if _, err := e.h.LinkApply(ctx, ra); err != nil {
		t.Fatal(err)
	}
	if last := e.execs[len(e.execs)-1]; !strings.Contains(last.Cmd, "trust anchor --store") {
		t.Fatalf("arch %+v", last)
	}
	// Removal works from the remembered root, without the CA.
	e.p.TestAddr = "127.0.0.1:1"
	if err := e.h.LinkRemove(ctx, req("ssh:2", 10)); err != nil {
		t.Fatal(err)
	}
	if last := e.execs[len(e.execs)-1]; !strings.Contains(last.Cmd, "rm -f /usr/local/share/ca-certificates/hestia-root-"+fp[:16]+".crt") ||
		!strings.Contains(last.Cmd, "--fresh") {
		t.Fatalf("remove %+v", last)
	}
	if err := e.h.LinkRemove(ctx, req("ssh:3", 11)); err != nil {
		t.Fatal(err)
	}
	if last := e.execs[len(e.execs)-1]; !strings.Contains(last.Cmd, "trust anchor --remove") {
		t.Fatalf("arch remove %+v", last)
	}
}

func TestParseOSRelease(t *testing.T) {
	for in, want := range map[string]string{
		"ID=ubuntu\nID_LIKE=debian\n":     famDebian,
		"ID=manjaro\nID_LIKE=arch\n":      famArch,
		"ID=\"garuda\"\nID_LIKE=\"arch\"": famArch,
		"ID=alpine\n":                     famAlpine,
		"ID=fedora\n":                     "",
	} {
		if got := parseOSRelease(in).Family; got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	_ = fmt.Sprint
}
