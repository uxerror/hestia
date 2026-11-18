package dnsname

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hestia/internal/integrations/adguard"
	"hestia/internal/netscan"
	"hestia/internal/store"
)

var bg = context.Background()

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{"hestia.home": "hestia.home", " Hestia.HOME. ": "hestia.home", "robot": "robot", "a-b.c1.lan": "a-b.c1.lan"} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "*.home", "a..b", ".home", "-a.home", "a-.home", "a b.home", "яндекс.рф", "a_b.home", strings.Repeat("a", 64) + ".home", strings.Repeat("a.", 130) + "x"} {
		if got, err := NormalizeDomain(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestDefaultZone(t *testing.T) {
	rw := func(ds ...string) []adguard.Rewrite {
		var l []adguard.Rewrite
		for _, d := range ds {
			l = append(l, adguard.Rewrite{Domain: d, Answer: "10.10.10.1"})
		}
		return l
	}
	cases := []struct {
		name string
		list []adguard.Rewrite
		want string
	}{
		{"empty", nil, "home"},
		{"most frequent", rw("a.lan", "b.lan", "c.home", "robot"), "lan"},
		{"wildcards and dotless ignored", rw("*.web.home", "*.web.home", "robot", "nas", "x.lan"), "lan"},
		{"only ignored", rw("*.home", "robot"), "home"},
		{"tie: alphabetical", rw("a.lan", "b.home"), "home"},
		{"subdomain zone", rw("a.b.lan", "c.b.lan", "d.lan"), "b.lan"},
		{"case and trailing dot", rw("A.LAN.", "b.lan"), "lan"},
	}
	for _, c := range cases {
		if got := DefaultZone(c.list); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if DefaultDomain(rw("a.lan")) != "hestia.lan" {
		t.Fatal("default domain")
	}
}

func TestCandidatesGroupEndpointsPerHost(t *testing.T) {
	ag := func(proto string, port int) netscan.ServiceInfo {
		return netscan.ServiceInfo{Port: port, Proto: proto, Rule: "adguard", Name: "AdGuard Home"}
	}
	hosts := []netscan.Host{
		{IP: "10.10.10.20", Alive: true, Services: []netscan.ServiceInfo{ag("http", 3000)}},
		{IP: "10.10.10.15", Alive: true, Services: []netscan.ServiceInfo{ag("http", 9091), {Port: 22, Proto: "ssh", Rule: "ssh"}, ag("https", 443), ag("http", 80)}},
		{IP: "10.10.10.9", Alive: false, Services: []netscan.ServiceInfo{ag("http", 3000)}},
		{IP: "10.10.10.3", Alive: true, Services: []netscan.ServiceInfo{{Port: 80, Proto: "http", Rule: "nginx"}}},
	}
	got := candidatesOf(hosts)
	if len(got) != 2 || got[0].Host != "10.10.10.15" || got[1].Host != "10.10.10.20" {
		t.Fatalf("%+v", got)
	}
	var urls []string
	for _, e := range got[0].Endpoints {
		urls = append(urls, e.URL)
	}
	if strings.Join(urls, " ") != "https://10.10.10.15 http://10.10.10.15 http://10.10.10.15:9091" {
		t.Fatalf("HTTPS first, default ports omitted: %v", urls)
	}
	if got[1].Endpoints[0].URL != "http://10.10.10.20:3000" || got[1].Endpoints[0].Port != 3000 {
		t.Fatalf("%+v", got[1])
	}
	if len(candidatesOf(nil)) != 0 {
		t.Fatal("no hosts, no candidates")
	}
}

func TestConnectChecksLoginAndHidesPassword(t *testing.T) {
	r := newRig(t, false)
	r.ag.set("nas.lan", "10.10.10.4")
	r.ag.set("tv.lan", "10.10.10.6")

	_, err := r.svc.Connect(bg, ConnectRequest{URL: r.ag.srv.URL, Username: agUser, Password: "wrong-password-xyz"}, false)
	var de *Error
	if !errors.As(err, &de) || de.Code != "auth_failed" || de.HTTP != 400 {
		t.Fatalf("wrong password: %v", err)
	}
	if strings.Contains(err.Error(), "wrong-password-xyz") {
		t.Fatal("password in the error")
	}
	if _, err := r.st.GetIntegrationByKind(bg, store.KindAdGuard); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("nothing must be saved after a failed login")
	}

	res := r.connect()
	if res.Server.Version != "v0.107.79" || !res.Server.Running || res.Server.DNSPort != r.ag.dnsPort {
		t.Fatalf("%+v", res.Server)
	}
	if res.DefaultDomain != "hestia.lan" || res.ControllerIP != "127.0.0.1" {
		t.Fatalf("%+v", res)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "открытым текстом") {
		t.Fatalf("http warning: %v", res.Warnings)
	}
	iv := res.Integration
	if iv.ID != 1 || !iv.HasPassword || iv.Username != agUser || iv.Name != "AdGuard Home (127.0.0.1)" || iv.TLSPin != "" {
		t.Fatalf("%+v", iv)
	}

	// The password lives encrypted in secrets with the purpose adguard:<id>.
	in, _ := r.st.GetIntegrationByKind(bg, store.KindAdGuard)
	row, err := r.st.GetSecret(bg, in.SecretID)
	if err != nil || row.Purpose != "adguard:1" {
		t.Fatalf("%+v %v", row, err)
	}
	if pw, err := r.sec.Get(bg, in.SecretID); err != nil || string(pw) != agPassword {
		t.Fatalf("%q %v", pw, err)
	}
	// ... and nowhere in plain text in the database files.
	files, _ := filepath.Glob(filepath.Join(r.dir, "hestia.db*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), agPassword) {
			t.Fatalf("password found in %s", f)
		}
	}

	// A second connection is refused; PUT with no password keeps the stored one.
	if _, err := r.svc.Connect(bg, ConnectRequest{URL: r.ag.srv.URL, Username: agUser, Password: agPassword}, false); err == nil {
		t.Fatal("second connection accepted")
	}
	if _, err := r.svc.Connect(bg, ConnectRequest{URL: r.ag.srv.URL, Username: agUser}, true); err != nil {
		t.Fatal(err)
	}
	// PUT with a new password: the old secret is gone.
	r.ag.mu.Lock()
	r.ag.pass = "new-pass-123"
	r.ag.mu.Unlock()
	if _, err := r.svc.Connect(bg, ConnectRequest{URL: r.ag.srv.URL, Username: agUser, Password: "new-pass-123"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.GetSecret(bg, in.SecretID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("old secret kept")
	}
	// Disconnect removes the secret too.
	in2, _ := r.st.GetIntegrationByKind(bg, store.KindAdGuard)
	if err := r.svc.Disconnect(bg); err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.GetSecret(bg, in2.SecretID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("secret kept after disconnect")
	}
	if err := r.svc.Disconnect(bg); err == nil {
		t.Fatal("disconnect of nothing")
	}
}

func TestConnectWarnsWhenRewritesAreOff(t *testing.T) {
	r := newRig(t, false)
	r.ag.rewrites = false
	res := r.connect()
	found := false
	for _, w := range res.Warnings {
		found = found || strings.Contains(w, "выключены")
	}
	if !found {
		t.Fatalf("%v", res.Warnings)
	}
}

func TestHTTPSPin(t *testing.T) {
	r := newRig(t, true)
	req := ConnectRequest{URL: r.ag.srv.URL, Username: agUser, Password: agPassword}

	// No pin: refused before any request.
	_, err := r.svc.Connect(bg, req, false)
	var de *Error
	if !errors.As(err, &de) || de.Code != "no_pin" {
		t.Fatalf("%v", err)
	}
	// A wrong pin: cert_changed with the presented fingerprint; no request with the password was sent.
	req.TLSPin = strings.Repeat("AB:", 31) + "AB"
	_, err = r.svc.Connect(bg, req, false)
	if !errors.As(err, &de) || de.Code != "cert_changed" || de.HTTP != 409 || de.Fingerprint != r.ag.pin() {
		t.Fatalf("%v (%+v)", err, de)
	}
	r.ag.mu.Lock()
	n, m := r.ag.authed, len(r.ag.methods)
	r.ag.mu.Unlock()
	if n != 0 || m != 0 {
		t.Fatalf("a request with credentials reached AdGuard despite the wrong pin (%d, %d)", n, m)
	}
	// The right pin, in any notation.
	req.TLSPin = strings.ToLower(strings.ReplaceAll(r.ag.pin(), ":", ""))
	res, err := r.svc.Connect(bg, req, false)
	if err != nil || res.Integration.TLSPin != r.ag.pin() {
		t.Fatalf("%v %+v", err, res)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("https needs no plaintext warning: %v", res.Warnings)
	}

	// A client without a pin cannot be built for https at all.
	if _, err := adguard.NewClient(adguard.Config{BaseURL: r.ag.srv.URL, Password: "x"}); !errors.Is(err, adguard.ErrNoPin) {
		t.Fatalf("%v", err)
	}
}

func TestProbe(t *testing.T) {
	r := newRig(t, true)
	res, err := r.svc.Probe(bg, r.ag.srv.URL)
	if err != nil || res.StatusCode != 401 || res.TLS == nil || res.TLS.SHA256 != r.ag.pin() || res.Warning != "" {
		t.Fatalf("%+v %v", res, err)
	}
	if res.TLS.NotAfter.IsZero() || res.TLS.Subject == "" {
		t.Fatalf("%+v", res.TLS)
	}
	r.ag.mu.Lock()
	if r.ag.authed != 0 {
		t.Fatal("probe must not send credentials")
	}
	r.ag.mu.Unlock()

	plain := newRig(t, false)
	res, err = plain.svc.Probe(bg, plain.ag.srv.URL)
	if err != nil || res.TLS != nil || res.StatusCode != 401 || !strings.Contains(res.Warning, "открытым текстом") {
		t.Fatalf("%+v %v", res, err)
	}
	for _, bad := range []string{"", "ftp://10.10.10.2", "http://u:p@10.10.10.2", "http://10.10.10.2/x", "10.10.10.2", "http://10.10.10.2:99999"} {
		if _, err := r.svc.Probe(bg, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := r.svc.Probe(bg, "http://127.0.0.1:1"); err == nil {
		t.Fatal("closed port")
	}
}

func TestPlanScenarios(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.ag.set("*.home", "10.10.10.1")
	r.ag.set("robot", "10.10.10.8")
	r.hostsrc.hosts = []netscan.Host{{IP: "10.10.10.77", Names: []netscan.Name{{Name: "printer", Source: "ptr"}}}}

	// No record → add; the wildcard is only a warning; a PC controller too.
	r.svc.Local = func(context.Context) bool { return true }
	p, err := r.svc.MakePlan(bg, ActionAdd, "Hestia.Home")
	if err != nil {
		t.Fatal(err)
	}
	if p.Domain != "hestia.home" || p.Answer != "127.0.0.1" || p.NoOp || len(p.Conflicts) != 0 || p.PlanID == "" || p.Hash == "" {
		t.Fatalf("%+v", p)
	}
	kinds := []string{}
	for _, a := range p.Actions {
		kinds = append(kinds, a.Kind)
	}
	if strings.Join(kinds, ",") != "add,verify,verify,bind" {
		t.Fatalf("%v", kinds)
	}
	joined := strings.Join(p.Warnings, "|")
	if !strings.Contains(joined, "*.home") || !strings.Contains(joined, "на этом компьютере") || !strings.Contains(joined, "виден только на этом") {
		t.Fatalf("warnings: %v", p.Warnings)
	}

	// Same answer → noop.
	r.ag.set("same.home", "127.0.0.1")
	p, err = r.svc.MakePlan(bg, ActionAdd, "same.home")
	if err != nil || !p.NoOp || len(p.Conflicts) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, a := range p.Actions {
		if a.Kind == "add" || a.Kind == "update" {
			t.Fatal("noop plan changes AdGuard")
		}
	}

	// Another answer → conflict naming the owner; nothing to apply.
	r.ag.set("taken.home", "10.10.10.77")
	p, err = r.svc.MakePlan(bg, ActionAdd, "taken.home")
	if err != nil || len(p.Conflicts) != 1 || p.Conflicts[0].Answer != "10.10.10.77" || !strings.Contains(p.Conflicts[0].Owner, "printer") || len(p.Actions) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := r.svc.Apply(bg, p.PlanID, p.Hash); err == nil || !strings.Contains(err.Error(), "нет действий") {
		t.Fatalf("a conflicting plan was applied: %v", err)
	}
	// Replace is a separate, explicit plan.
	p, err = r.svc.MakePlan(bg, ActionReplace, "taken.home")
	if err != nil || len(p.Actions) == 0 || p.Actions[0].Kind != "update" || !strings.Contains(p.Actions[0].Detail, "10.10.10.77 → 127.0.0.1") {
		t.Fatalf("%+v %v", p, err)
	}

	// Multiple records of a name cannot be replaced.
	r.ag.set("multi.home", "10.10.10.31")
	r.ag.set("multi.home", "10.10.10.32")
	if _, err := r.svc.MakePlan(bg, ActionReplace, "multi.home"); err == nil {
		t.Fatal("replace of several records")
	}

	// Invalid names, unknown actions, actions without a name.
	for _, d := range []string{"", "*.x", "a b"} {
		if _, err := r.svc.MakePlan(bg, ActionAdd, d); err == nil {
			t.Errorf("%q", d)
		}
	}
	if _, err := r.svc.MakePlan(bg, "explode", "x.home"); err == nil {
		t.Fatal("unknown action")
	}
	if _, err := r.svc.MakePlan(bg, ActionUpdateIP, ""); err == nil {
		t.Fatal("update_ip without a name")
	}
}

func TestPlanHashAndStale(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	p, _ := r.svc.MakePlan(bg, ActionAdd, "hestia.home")
	if _, err := r.svc.Apply(bg, p.PlanID, "deadbeef"); err == nil || !strings.Contains(err.Error(), "не тот план") {
		t.Fatalf("%v", err)
	}
	if _, err := r.svc.Apply(bg, "nope", p.Hash); err == nil {
		t.Fatal("unknown plan")
	}
	// The list changes after the plan was made: the job refuses, AdGuard is untouched.
	before := len(r.ag.records())
	r.ag.set("other.home", "10.10.10.50")
	job, err := r.applyPlan(p)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.JobFailed || !strings.Contains(job.Error, "план устарел") {
		t.Fatalf("%+v", job)
	}
	if len(r.ag.records()) != before+1 {
		t.Fatalf("the stale plan changed AdGuard: %+v", r.ag.records())
	}
	if _, err := r.st.GetDNSName(bg); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("name saved")
	}
	// A plan is applied once.
	if _, err := r.svc.Apply(bg, p.PlanID, p.Hash); err == nil {
		t.Fatal("second apply of a plan")
	}
	// An expired plan.
	p2, _ := r.svc.MakePlan(bg, ActionAdd, "hestia.home")
	r.svc.Now = func() time.Time { return time.Now().Add(planTTL + time.Minute) }
	if _, err := r.svc.Apply(bg, p2.PlanID, p2.Hash); err == nil {
		t.Fatal("expired plan applied")
	}
}

func TestApplySuccess(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.ag.set("nas.home", "10.10.10.4")
	job, err := r.apply(ActionAdd, "hestia.home")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.JobDone || job.Kind != JobKind {
		t.Fatalf("%+v", job)
	}
	var steps []string
	for _, s := range job.Steps {
		steps = append(steps, s.Title)
	}
	if strings.Join(steps, "|") != "Проверка плана|Запись в AdGuard|Проверка DNS|Проверка доступности по имени|Сохранение" {
		t.Fatalf("%v", steps)
	}
	if got := r.ag.lookup("hestia.home"); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("%v", got)
	}
	n, err := r.st.GetDNSName(bg)
	if err != nil || n.Domain != "hestia.home" || n.Answer != "127.0.0.1" || n.Status != StatusOK || n.VerifiedAt == nil {
		t.Fatalf("%+v %v", n, err)
	}
	r.healthMu.Lock()
	host := r.healthHost
	r.healthMu.Unlock()
	if host != "hestia.home" {
		t.Fatalf("health check Host: %q", host)
	}
	if u := r.svc.PublicURL(bg); u != "http://hestia.home" {
		t.Fatalf("%q", u)
	}
	// Applying the same name again is a noop plan that only checks.
	p, _ := r.svc.MakePlan(bg, ActionAdd, "hestia.home")
	if !p.NoOp {
		t.Fatalf("%+v", p)
	}
	if job, _ := r.applyPlan(p); job.Status != store.JobDone || len(r.ag.records()) != 2 {
		t.Fatalf("%+v %v", job, r.ag.records())
	}
	// Nothing in the job shows the password.
	assertNoPassword(t, job)
}

func assertNoPassword(t *testing.T, jobs ...store.Job) {
	t.Helper()
	for _, j := range jobs {
		b := j.Title + j.Error
		for _, s := range j.Steps {
			b += s.Title + s.Error
		}
		for _, l := range j.Log {
			b += l.Line
		}
		if strings.Contains(b, agPassword) {
			t.Fatalf("password in job %s", j.ID)
		}
	}
}

func TestApplyRollsBackAddWhenDNSAnswersWrong(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.ag.set("nas.home", "10.10.10.4")
	r.dns.setOverride("10.10.10.99")
	job, err := r.apply(ActionAdd, "hestia.home")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.JobFailed || !strings.Contains(job.Error, "проверка DNS") || !strings.Contains(job.Error, "10.10.10.99") {
		t.Fatalf("%+v", job)
	}
	if got := r.ag.records(); len(got) != 1 || got[0].Domain != "nas.home" {
		t.Fatalf("the added record was not removed: %+v", got)
	}
	if _, err := r.st.GetDNSName(bg); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("name saved after a failed check")
	}
	last := job.Steps[len(job.Steps)-1]
	if last.Title != "Откат изменений в AdGuard" || last.Status != store.StepDone {
		t.Fatalf("%+v", job.Steps)
	}
	assertNoPassword(t, job)
}

func TestApplyRollsBackWhenHealthIsAnotherInstance(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.healthMu.Lock()
	r.healthID = "somebody-else"
	r.healthMu.Unlock()
	job, err := r.apply(ActionAdd, "hestia.home")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.JobFailed || !strings.Contains(job.Error, "другая Hestia") {
		t.Fatalf("%+v", job)
	}
	if len(r.ag.records()) != 0 {
		t.Fatalf("not rolled back: %+v", r.ag.records())
	}
}

func TestApplyReplaceRollbackRestoresOldAnswer(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.ag.set("hestia.home", "10.10.10.77")
	r.dns.setOverride("10.10.10.99")
	job, err := r.apply(ActionReplace, "hestia.home")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != store.JobFailed {
		t.Fatalf("%+v", job)
	}
	got := r.ag.records()
	if len(got) != 1 || got[0].Domain != "hestia.home" || got[0].Answer != "10.10.10.77" {
		t.Fatalf("old answer not restored: %+v", got)
	}

	// Without the fault the replacement sticks.
	r.dns.setOverride("")
	job, _ = r.apply(ActionReplace, "hestia.home")
	if job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	if got := r.ag.lookup("hestia.home"); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("%v", got)
	}
}

func TestApplyAddFailureLeavesNothing(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.ag.failAdd = true
	job, _ := r.apply(ActionAdd, "hestia.home")
	if job.Status != store.JobFailed || len(r.ag.records()) != 0 {
		t.Fatalf("%+v %v", job, r.ag.records())
	}
	assertNoPassword(t, job)
}

func TestNoopFailureDoesNotTouchExistingRecord(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.ag.set("hestia.home", "127.0.0.1")
	r.dns.setOverride("10.10.10.99")
	job, _ := r.apply(ActionAdd, "hestia.home")
	if job.Status != store.JobFailed || len(r.ag.records()) != 1 {
		t.Fatalf("a record that was already there must stay: %+v %v", job, r.ag.records())
	}
}

func TestSecondApplyWhileRunningIsRefused(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	r.dns.setOverride("10.10.10.99")
	r.svc.DNSPause = 300 * time.Millisecond
	r.svc.DNSAttempts = 3
	p1, _ := r.svc.MakePlan(bg, ActionAdd, "a.home")
	p2, _ := r.svc.MakePlan(bg, ActionAdd, "b.home")
	j1, err := r.svc.Apply(bg, p1.PlanID, p1.Hash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.svc.Apply(bg, p2.PlanID, p2.Hash)
	var de *Error
	if !errors.As(err, &de) || de.Code != "busy" || de.Job != j1.ID {
		t.Fatalf("%v", err)
	}
	if err := r.svc.Disconnect(bg); err == nil {
		t.Fatal("disconnect while a job runs")
	}
	r.runner.Wait()
}

func TestRemove(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	if job, _ := r.apply(ActionAdd, "hestia.home"); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	r.ag.set("keep.home", "10.10.10.4")

	job, err := r.apply(ActionRemove, "")
	if err != nil || job.Status != store.JobDone {
		t.Fatalf("%+v %v", job, err)
	}
	if got := r.ag.records(); len(got) != 1 || got[0].Domain != "keep.home" {
		t.Fatalf("%+v", got)
	}
	if _, err := r.st.GetDNSName(bg); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("name kept")
	}

	// The record in AdGuard is no longer ours: only the binding is removed.
	if job, _ := r.apply(ActionAdd, "hestia.home"); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	r.ag.mu.Lock()
	for i := range r.ag.list {
		if r.ag.list[i].Domain == "hestia.home" {
			r.ag.list[i].Answer = "10.10.10.200"
		}
	}
	r.ag.mu.Unlock()
	p, err := r.svc.MakePlan(bg, ActionRemove, "")
	if err != nil || len(p.Warnings) == 0 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, a := range p.Actions {
		if a.Kind == "delete" {
			t.Fatal("a foreign record would be deleted")
		}
	}
	if job, _ := r.applyPlan(p); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	var found bool
	for _, x := range r.ag.records() {
		found = found || (x.Domain == "hestia.home" && x.Answer == "10.10.10.200")
	}
	if !found {
		t.Fatalf("foreign record was touched: %+v", r.ag.records())
	}
	if _, err := r.st.GetDNSName(bg); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("name kept")
	}
}

func TestWatcherStatuses(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	if job, _ := r.apply(ActionAdd, "hestia.home"); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	status := func() NameView {
		t.Helper()
		if err := r.svc.Check(bg); err != nil {
			t.Fatal(err)
		}
		n, err := r.st.GetDNSName(bg)
		if err != nil || n.CheckedAt == nil {
			t.Fatalf("%+v %v", n, err)
		}
		return *nameView(n)
	}
	setRecord := func(answer string) {
		r.ag.mu.Lock()
		defer r.ag.mu.Unlock()
		r.ag.list = nil
		if answer != "" {
			r.ag.list = []adguard.Rewrite{{Domain: "hestia.home", Answer: answer}}
		}
	}
	setStored := func(answer string) {
		n, _ := r.st.GetDNSName(bg)
		if err := r.st.UpdateDNSNameStatus(bg, n.ID, StatusOK, "", answer, time.Now(), nil); err != nil {
			t.Fatal(err)
		}
	}

	if v := status(); v.Status != StatusOK {
		t.Fatalf("%+v", v)
	}
	if r.svc.PublicURL(bg) == "" {
		t.Fatal("ok status must be public")
	}

	// The controller got a new address: the record and the stored answer are the old one.
	setStored("10.10.10.7")
	setRecord("10.10.10.7")
	if v := status(); v.Status != StatusIPChanged || !strings.Contains(v.StatusDetail, "127.0.0.1") {
		t.Fatalf("%+v", v)
	}
	if r.svc.PublicURL(bg) != "" {
		t.Fatal("only an ok name is announced")
	}
	// The record points at somebody else.
	setRecord("10.10.10.9")
	if v := status(); v.Status != StatusChanged || !strings.Contains(v.StatusDetail, "10.10.10.9") {
		t.Fatalf("%+v", v)
	}
	// The record is gone.
	setRecord("")
	if v := status(); v.Status != StatusMissing {
		t.Fatalf("%+v", v)
	}
	// Somebody fixed the record to the current address: ok again, stored answer follows.
	setRecord("127.0.0.1")
	if v := status(); v.Status != StatusOK || v.Answer != "127.0.0.1" {
		t.Fatalf("%+v", v)
	}
	// Bad login.
	r.ag.mu.Lock()
	r.ag.pass = "changed-elsewhere"
	r.ag.mu.Unlock()
	if v := status(); v.Status != StatusAuthFailed {
		t.Fatalf("%+v", v)
	}
	// Unreachable.
	r.ag.srv.Close()
	if v := status(); v.Status != StatusUnreachable {
		t.Fatalf("%+v", v)
	}
}

func TestWatcherNeverWrites(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	if job, _ := r.apply(ActionAdd, "hestia.home"); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	r.ag.mu.Lock()
	r.ag.methods = nil
	r.ag.list = nil
	r.ag.mu.Unlock()
	if err := r.svc.Check(bg); err != nil {
		t.Fatal(err)
	}
	r.ag.mu.Lock()
	defer r.ag.mu.Unlock()
	if len(r.ag.methods) == 0 {
		t.Fatal("no check happened")
	}
	for _, m := range r.ag.methods {
		if !strings.HasPrefix(m, "GET ") {
			t.Fatalf("the watcher sent %s", m)
		}
	}
}

func TestWatcherCertChanged(t *testing.T) {
	r := newRig(t, true)
	r.connect()
	if job, _ := r.apply(ActionAdd, "hestia.home"); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	in, _ := r.st.GetIntegrationByKind(bg, store.KindAdGuard)
	in.TLSPin = strings.Repeat("11:", 31) + "11"
	if err := r.st.UpdateIntegration(bg, &in); err != nil {
		t.Fatal(err)
	}
	r.ag.mu.Lock()
	r.ag.authed = 0
	r.ag.mu.Unlock()
	if err := r.svc.Check(bg); err != nil {
		t.Fatal(err)
	}
	n, _ := r.st.GetDNSName(bg)
	if n.Status != StatusCertChanged || !strings.Contains(n.StatusDetail, r.ag.pin()) {
		t.Fatalf("%+v", n)
	}
	r.ag.mu.Lock()
	defer r.ag.mu.Unlock()
	if r.ag.authed != 0 {
		t.Fatal("credentials were sent to a server with another certificate")
	}
}

func TestWatcherStartsAndStops(t *testing.T) {
	r := newRig(t, false)
	r.connect()
	if job, _ := r.apply(ActionAdd, "hestia.home"); job.Status != store.JobDone {
		t.Fatalf("%+v", job)
	}
	r.ag.mu.Lock()
	r.ag.list = nil
	r.ag.mu.Unlock()
	r.svc.FirstCheck, r.svc.CheckEvery = 10*time.Millisecond, time.Hour
	ctx, cancel := context.WithCancel(bg)
	r.svc.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := r.st.GetDNSName(bg); n.Status == StatusMissing {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	r.svc.Wait()
	if n, _ := r.st.GetDNSName(bg); n.Status != StatusMissing {
		t.Fatalf("%+v", n)
	}
}

func TestViewAndDefaultDomain(t *testing.T) {
	r := newRig(t, false)
	v, err := r.svc.View(bg)
	if err != nil || v.Integration != nil || v.Name != nil || len(v.Candidates) != 0 || v.DefaultDomain != "hestia.home" {
		t.Fatalf("%+v %v", v, err)
	}
	r.connect()
	r.ag.set("a.lan", "10.10.10.4")
	v, err = r.svc.View(bg)
	if err != nil || v.Integration == nil || v.Integration.HasPassword != true || v.DefaultDomain != "hestia.lan" || v.ControllerIP != "127.0.0.1" {
		t.Fatalf("%+v %v", v, err)
	}
}
