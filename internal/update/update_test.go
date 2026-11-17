package update

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/selfinstall"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/testelf"
)

// fakeShell is the controller's machine: it records what is written and run.
type fakeShell struct {
	mu      sync.Mutex
	files   map[string][]byte
	modes   map[string]string
	owners  map[string]string
	cmds    []string
	version string // what `hestia.new version` prints
	unit    string
	closed  bool
}

func (f *fakeShell) Exec(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, script)
	switch {
	case script == newBinPath+" version":
		return sshx.Result{Stdout: "hestia " + f.version + "\n"}, nil
	case script == "cat "+selfinstall.UnitPath:
		return sshx.Result{Stdout: f.unit}, nil
	}
	return sshx.Result{}, nil
}

func (f *fakeShell) PutFile(ctx context.Context, log func(string), path string, data []byte, mode, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = append([]byte(nil), data...)
	f.modes[path], f.owners[path] = mode, owner
	return nil
}

func (f *fakeShell) Close() error { f.closed = true; return nil }

func (f *fakeShell) ran(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

type env struct {
	t      *testing.T
	st     *store.Store
	dir    string
	runner *jobs.Runner
	svc    *Service
	shell  *fakeShell
	opens  int
	loc    *selfinstall.Location
	gh     *httptest.Server
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	// release served by the fake GitHub
	tag     string
	bin     []byte
	badSig  bool
	status  int
	ghCalls int
}

var serverBin = testelf.Build(testelf.Opts{Payload: []byte("v2")})

func newEnv(t *testing.T, current string) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), tag: "v0.2.0", bin: serverBin, status: 200,
		loc: &selfinstall.Location{Kind: "lxc", TargetID: 1, Node: "pve1", VMID: 900, IP: "198.51.100.9"}}
	var err error
	if e.st, err = store.Open(e.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.st.Close() })
	if e.runner, err = jobs.NewRunner(context.Background(), e.st); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.runner.Shutdown)
	e.pub, e.priv, _ = GenerateKey()
	e.shell = &fakeShell{files: map[string][]byte{}, modes: map[string]string{}, owners: map[string]string{},
		version: e.tag, unit: "ExecStart=/usr/local/bin/hestia serve --listen :8081 --data /var/lib/hestia\n"}

	e.gh = httptest.NewServer(http.HandlerFunc(e.serveGitHub))
	t.Cleanup(e.gh.Close)
	e.svc = (&Service{
		Store: e.st, Runner: e.runner, DataDir: e.dir, Version: current, PubKey: e.pub,
		GitHub:   &GitHub{BaseURL: e.gh.URL, Repo: "o/r"},
		Location: func(context.Context) (*selfinstall.Location, error) { return e.loc, nil },
		Open: func(context.Context, selfinstall.Location) (Shell, error) {
			e.opens++
			return e.shell, nil
		},
	}).Init()
	return e
}

func (e *env) serveGitHub(w http.ResponseWriter, r *http.Request) {
	e.ghCalls++
	if e.status != 200 {
		http.Error(w, "nope", e.status)
		return
	}
	base := "http://" + r.Host
	switch r.URL.Path {
	case "/repos/o/r/releases/latest":
		a := func(n string) string {
			return fmt.Sprintf(`{"name":%q,"browser_download_url":%q,"size":1}`, n, base+"/dl/"+n)
		}
		fmt.Fprintf(w, `{"tag_name":%q,"html_url":%q,"assets":[%s,%s,%s]}`, e.tag, base+"/notes",
			a(ServerAsset), a(SumsName), a(SigName))
	case "/dl/" + ServerAsset:
		_, _ = w.Write(e.bin)
	case "/dl/" + SumsName:
		_, _ = w.Write(e.sums())
	case "/dl/" + SigName:
		sig := SignSums(e.priv, e.sums())
		if e.badSig {
			_, other, _ := GenerateKey()
			sig = SignSums(other, e.sums())
		}
		_, _ = w.Write(sig)
	default:
		http.NotFound(w, r)
	}
}

// sums is SHA256SUMS of the release as published (the real binary).
func (e *env) sums() []byte {
	return SumsFile(map[string][]byte{ServerAsset: serverBin, DesktopAsset: []byte("desktop")})
}

func (e *env) job(id string) store.Job {
	e.t.Helper()
	j, err := e.st.GetJob(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return j
}

// wait waits for the job body to return (a handed-off job stays "running").
func (e *env) wait(id string) store.Job {
	e.t.Helper()
	e.runner.Wait()
	return e.job(id)
}

func (e *env) errOf(err error) *Error {
	e.t.Helper()
	ue, ok := err.(*Error)
	if !ok {
		e.t.Fatalf("not an *Error: %v", err)
	}
	return ue
}

func TestStatusWithoutLocation(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.loc = nil
	st, err := e.svc.Status(context.Background())
	if err != nil || st.LocationOK || st.Reason == "" || st.Current != "v0.1.0" || !st.GitHub.Configured {
		t.Fatalf("%+v %v", st, err)
	}
	_, err = e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	if e.errOf(err).Status != http.StatusConflict {
		t.Fatalf("start: %v", err)
	}
}

func TestStatusNotConfigured(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.svc.PubKey = nil
	st, _ := e.svc.Status(context.Background())
	if st.GitHub.Configured || st.GitHub.Available {
		t.Fatalf("%+v", st)
	}
	if _, err := e.svc.CheckNow(context.Background()); err == nil || e.ghCalls != 0 {
		t.Fatalf("a check without a key must not call GitHub: %v calls=%d", err, e.ghCalls)
	}
}

func TestGitHubCheck(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, current, tag string
		status             int
		available          bool
		errPart            string
	}{
		{"newer", "v0.1.0", "v0.2.0", 200, true, ""},
		{"same", "v0.2.0", "v0.2.0", 200, false, ""},
		{"older release", "v0.3.0", "v0.2.0", 200, false, ""},
		{"commits after tag are newer than the tag", "v0.2.0-3-gabc1234", "v0.2.0", 200, false, ""},
		{"no releases", "v0.1.0", "v0.2.0", 404, false, "релизов пока нет"},
		{"server error", "v0.1.0", "v0.2.0", 500, false, "не удалось проверить"},
		{"odd tag", "v0.1.0", "nightly", 200, false, "необычный тег"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.current)
			e.tag, e.status = c.tag, c.status
			gh, err := e.svc.CheckNow(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if gh.Available != c.available || !strings.Contains(gh.Error, c.errPart) || (c.errPart != "" && gh.Error == "") {
				t.Fatalf("%+v", gh)
			}
			if c.status == 200 && gh.NotesURL == "" {
				t.Fatalf("notes url: %+v", gh)
			}
		})
	}
}

func TestCheckStateIsPersistedAndKeptOnError(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	if _, err := e.svc.CheckNow(ctx); err != nil {
		t.Fatal(err)
	}
	e.status = 500
	gh, _ := e.svc.CheckNow(ctx)
	if gh.Latest != "v0.2.0" || gh.Error == "" || !gh.Available {
		t.Fatalf("a failed check keeps the last known release: %+v", gh)
	}
	// a restart sees the saved state
	svc2 := (&Service{Store: e.st, DataDir: e.dir, Version: "v0.1.0", PubKey: e.pub,
		Location: func(context.Context) (*selfinstall.Location, error) { return e.loc, nil }}).Init()
	if st, _ := svc2.Status(ctx); st.GitHub.Latest != "v0.2.0" || st.GitHub.CheckedAt.IsZero() {
		t.Fatalf("%+v", st.GitHub)
	}
}

func TestGitHubUpdateJob(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	job, err := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	j := e.wait(job.ID)
	if j.Status != store.JobRunning {
		t.Fatalf("a handed-off job stays running: %s %s", j.Status, j.Error)
	}
	sh := e.shell
	if string(sh.files[newBinPath]) != string(serverBin) || sh.modes[newBinPath] != "0755" || sh.owners[newBinPath] != "root:root" {
		t.Fatalf("new binary: mode %q owner %q", sh.modes[newBinPath], sh.owners[newBinPath])
	}
	if string(sh.files[scriptPath]) != string(upgradeScript) || sh.modes[scriptPath] != "0755" {
		t.Fatal("upgrade.sh missing or not executable")
	}
	var h handoff
	if err := json.Unmarshal(sh.files["/var/lib/hestia/update.json"], &h); err != nil ||
		h.JobID != job.ID || h.From != "v0.1.0" || h.To != "v0.2.0" || sh.modes["/var/lib/hestia/update.json"] != "0600" || sh.owners["/var/lib/hestia/update.json"] != "hestia:hestia" {
		t.Fatalf("update.json: %+v %v", h, err)
	}
	if !sh.ran("systemd-run --unit hestia-upgrade-") || !sh.ran("--collect /usr/local/lib/hestia/upgrade.sh 8081") {
		t.Fatalf("commands: %q", sh.cmds)
	}
	if !sh.closed {
		t.Fatal("the connection must be closed")
	}
	if sh.ran("rm -f") {
		t.Fatalf("a handed-off update must not delete hestia.new: %q", sh.cmds)
	}
	last := j.Steps[len(j.Steps)-1]
	if last.Title != "Перезапуск контроллера" || last.Status != store.StepRunning {
		t.Fatalf("steps: %+v", j.Steps)
	}
	if !strings.Contains(strings.ToLower(j.Title), "github") {
		t.Fatalf("title %q", j.Title)
	}
}

func TestGitHubBadSignatureStopsBeforeTouchingTheMachine(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.badSig = true
	job, err := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	j := e.wait(job.ID)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "подпись") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if e.opens != 0 || len(e.shell.files) != 0 {
		t.Fatalf("machine touched: opens=%d files=%d", e.opens, len(e.shell.files))
	}
}

func TestGitHubTamperedBinaryIsRefused(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.bin = append(append([]byte(nil), serverBin...), 'x') // differs from SHA256SUMS
	job, _ := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	j := e.wait(job.ID)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "контрольная сумма") || e.opens != 0 {
		t.Fatalf("%s %q opens=%d", j.Status, j.Error, e.opens)
	}
}

func TestGitHubVersionMovedOn(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.tag = "v0.3.0"
	job, _ := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	if j := e.wait(job.ID); j.Status != store.JobFailed || !strings.Contains(j.Error, "v0.3.0") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
}

func TestStartRules(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.2.0")
	for _, c := range []struct {
		name string
		req  Request
		want int
	}{
		{"nothing", Request{}, 400},
		{"unknown upload", Request{UploadID: "nope"}, 410},
		{"bad version", Request{Source: "github", Version: "latest"}, 400},
		{"same version", Request{Source: "github", Version: "v0.2.0"}, 422},
		{"downgrade", Request{Source: "github", Version: "v0.1.0"}, 422},
		{"older commits", Request{Source: "github", Version: "v0.1.9-4-gabc1234"}, 422},
	} {
		if _, err := e.svc.Start(ctx, c.req); err == nil || e.errOf(err).Status != c.want {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if e.opens != 0 {
		t.Fatal("refused requests must not connect")
	}
}

func TestOnlyOneUpdateAtATime(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	job, err := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	// still "running": it is handed off
	e.wait(job.ID)
	_, err = e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	if err == nil || e.errOf(err).Status != http.StatusConflict {
		t.Fatalf("second start: %v", err)
	}
	if st, _ := e.svc.Status(context.Background()); st.RunningJob != job.ID {
		t.Fatalf("running job: %q", st.RunningJob)
	}
}

func doUpload(t *testing.T, e *env, b []byte, ver string) (Uploaded, error) {
	t.Helper()
	return e.svc.Upload(strings.NewReader(string(b)), ver)
}

func TestUploadChecks(t *testing.T) {
	e := newEnv(t, "v0.2.0")
	check := func(name string, b []byte, ver string, want int) {
		t.Helper()
		_, err := doUpload(t, e, b, ver)
		if err == nil || e.errOf(err).Status != want {
			t.Errorf("%s: %v (want %d)", name, err, want)
		}
	}
	check("not ELF", []byte("#!/bin/sh\necho hi\n"), "v0.3.0", 422)
	check("dynamic", testelf.Build(testelf.Opts{Dynamic: true}), "v0.3.0", 422)
	check("arm64", testelf.Build(testelf.Opts{Machine: 183}), "v0.3.0", 422)
	check("32-bit", testelf.Build(testelf.Opts{Class32: true}), "v0.3.0", 422)
	check("downgrade", serverBin, "v0.1.0", 422)
	check("same", serverBin, "v0.2.0", 422)
	check("no version", serverBin, "", 400)

	old := MaxUpload
	MaxUpload = 1000
	defer func() { MaxUpload = old }()
	check("too large", make([]byte, 1001), "v0.3.0", 413)
	MaxUpload = old

	up, err := doUpload(t, e, serverBin, "v0.3.0")
	if err != nil || up.UploadID == "" || up.Dirty || up.SHA256 == "" || up.Version != "v0.3.0" || up.Warning != "" {
		t.Fatalf("%+v %v", up, err)
	}
	fi, err := os.Stat(filepath.Join(e.dir, "update-tmp"))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("temp dir: %v %v", fi, err)
	}
}

func TestUploadDirtyNeedsConfirmation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.2.0")
	e.shell.version = "v0.2.0-3-gabc1234-dirty"
	up, err := doUpload(t, e, serverBin, "v0.2.0-3-gabc1234-dirty")
	if err != nil || !up.Dirty || up.Warning == "" {
		t.Fatalf("%+v %v", up, err)
	}
	_, err = e.svc.Start(ctx, Request{UploadID: up.UploadID})
	if ue := e.errOf(err); ue.Status != http.StatusConflict || !ue.Confirm {
		t.Fatalf("%v", err)
	}
	job, err := e.svc.Start(ctx, Request{UploadID: up.UploadID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if j := e.wait(job.ID); j.Status != store.JobRunning || !strings.Contains(j.Title, "приложения") {
		t.Fatalf("%s %q %q", j.Status, j.Title, j.Error)
	}
	// a started job owns the file; a handed-off one keeps it until the restart cleans it
	e.svc.CleanTemp()
	if _, err := os.Stat(filepath.Join(e.dir, "update-tmp")); err == nil {
		t.Fatal("CleanTemp must remove the temp dir")
	}
}

func TestUploadedFileIsRemovedAfterAFailedJob(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.shell.version = "v9.9.9" // the binary reports another version than claimed
	up, _ := doUpload(t, e, serverBin, "v0.2.0")
	job, err := e.svc.Start(context.Background(), Request{UploadID: up.UploadID})
	if err != nil {
		t.Fatal(err)
	}
	j := e.wait(job.ID)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "не совпала") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if !e.shell.ran("rm -f "+newBinPath) || !e.shell.closed {
		t.Fatalf("hestia.new must be removed after a failure: %q", e.shell.cmds)
	}
	ents, _ := os.ReadDir(filepath.Join(e.dir, "update-tmp"))
	if len(ents) != 0 {
		t.Fatalf("temp files left: %v", ents)
	}
	if _, ok := e.svc.uploads[up.UploadID]; ok {
		t.Fatal("upload still registered")
	}
	// a new update may start after a failure
	e.shell.version = "v0.2.0"
	up2, _ := doUpload(t, e, serverBin, "v0.2.0")
	if _, err := e.svc.Start(context.Background(), Request{UploadID: up2.UploadID}); err != nil {
		t.Fatal(err)
	}
}

func TestUploadExpires(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	now := time.Now()
	e.svc.Now = func() time.Time { return now }
	up, _ := doUpload(t, e, serverBin, "v0.2.0")
	now = now.Add(61 * time.Minute)
	_, err := e.svc.Start(context.Background(), Request{UploadID: up.UploadID})
	if err == nil || e.errOf(err).Status != http.StatusGone {
		t.Fatalf("%v", err)
	}
}

func TestPortFallsBackTo80(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	e.shell.unit = "garbage"
	job, _ := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	e.wait(job.ID)
	if !e.shell.ran("upgrade.sh 80") {
		t.Fatalf("%q", e.shell.cmds)
	}
}

// ---- after the restart ----

// handedOff leaves a job "running" on its last step, as an update does.
func handedOff(t *testing.T, e *env) string {
	t.Helper()
	job, err := e.runner.Start(JobKind, "update", func(ctx context.Context, run *jobs.Run) error {
		_ = run.Step("Скрипт обновления", func(context.Context) error { return nil })
		return run.Step("Перезапуск контроллера", func(context.Context) error { return jobs.ErrHandedOff })
	})
	if err != nil {
		t.Fatal(err)
	}
	e.wait(job.ID)
	return job.ID
}

func writeHandoff(t *testing.T, dir string, h handoff) {
	t.Helper()
	b, _ := json.Marshal(h)
	if err := os.WriteFile(filepath.Join(dir, StateFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeSuccess(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	id := handedOff(t, e)
	writeHandoff(t, e.dir, handoff{JobID: id, From: "v0.1.0", To: "v0.2.0"})
	_ = os.WriteFile(filepath.Join(e.dir, LogFile), []byte("12:00:00 обновление: порт 80\n12:00:09 новая версия работает: v0.2.0\n"), 0o644)

	if Pending(e.dir) != id {
		t.Fatal("Pending must name the job")
	}
	// the next process: the interrupted-job sweep must skip the handed-off job
	r2, err := jobs.NewRunner(ctx, e.st, Pending(e.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Shutdown()
	if j := e.job(id); j.Status != store.JobRunning {
		t.Fatalf("kept job must stay running: %s", j.Status)
	}
	if err := Finalize(ctx, e.st, e.dir, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	j := e.job(id)
	if j.Status != store.JobDone || j.Error != "" || j.FinishedAt == nil {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	last := j.Steps[len(j.Steps)-1]
	if last.Title != "Контроллер перезапущен, версия v0.2.0" || last.Status != store.StepDone {
		t.Fatalf("steps: %+v", j.Steps)
	}
	for _, s := range j.Steps {
		if s.Status != store.StepDone {
			t.Fatalf("step %q is %s", s.Title, s.Status)
		}
	}
	if !strings.Contains(logText(j), "новая версия работает") {
		t.Fatalf("log: %s", logText(j))
	}
	// kept until upgrade.sh confirms health; a repeated start is a no-op
	if _, err := os.Stat(filepath.Join(e.dir, StateFile)); err != nil {
		t.Fatal("update.json must stay until the script confirms health")
	}
	if err := Finalize(ctx, e.st, e.dir, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	if j := e.job(id); j.Status != store.JobDone {
		t.Fatalf("second finalize changed the job: %s", j.Status)
	}
	if _, err := os.Stat(filepath.Join(e.dir, StateFile)); err == nil {
		t.Fatal("update.json of a closed job must be removed")
	}
}

// The new version starts (closing the job) but dies before the health check
// passes: the script restores the old database, where the job is still
// running, and marks update.json rolled back. The old version must then
// report the failure.
func TestFinalizeLateRollback(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	id := handedOff(t, e)
	writeHandoff(t, e.dir, handoff{JobID: id, From: "v0.1.0", To: "v0.2.0"})
	// the restored (pre-update) database still has the job running; the new
	// version's Finalize ran against the database that was thrown away
	writeHandoff(t, e.dir, handoff{JobID: id, From: "v0.1.0", To: "v0.2.0", RolledBack: true, Reason: "новая версия не ответила за 60 с"})
	if err := Finalize(ctx, e.st, e.dir, "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	j := e.job(id)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "возвращена v0.1.0") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if _, err := os.Stat(filepath.Join(e.dir, StateFile)); err == nil {
		t.Fatal("update.json must be removed after a failure")
	}
}

func logText(j store.Job) string {
	var sb strings.Builder
	for _, l := range j.Log {
		sb.WriteString(l.Line + "\n")
	}
	return sb.String()
}

func TestFinalizeRollback(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	id := handedOff(t, e)
	// the old binary is running again: it is not the target version
	writeHandoff(t, e.dir, handoff{JobID: id, From: "v0.1.0", To: "v0.2.0", RolledBack: true, Reason: "новая версия не ответила за 60 с"})
	_ = os.WriteFile(filepath.Join(e.dir, LogFile), []byte("12:00:00 ОШИБКА: новая версия не ответила\n12:00:09 возврат выполнен\n"), 0o644)
	if err := Finalize(ctx, e.st, e.dir, "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	j := e.job(id)
	if j.Status != store.JobFailed || !strings.Contains(j.Error, "Новая версия не запустилась, возвращена v0.1.0") {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
	if !strings.Contains(logText(j), "возврат выполнен") {
		t.Fatalf("log tail missing: %s", logText(j))
	}
	if last := j.Steps[len(j.Steps)-1]; last.Status != store.StepFailed {
		t.Fatalf("steps: %+v", j.Steps)
	}
	if _, err := os.Stat(filepath.Join(e.dir, StateFile)); err == nil {
		t.Fatal("update.json must be removed")
	}
}

func TestFinalizeWrongVersionWithoutRollbackFlagIsAFailure(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	id := handedOff(t, e)
	writeHandoff(t, e.dir, handoff{JobID: id, From: "v0.1.0", To: "v0.2.0"})
	if err := Finalize(ctx, e.st, e.dir, "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	if j := e.job(id); j.Status != store.JobFailed {
		t.Fatalf("%s", j.Status)
	}
}

func TestFinalizeTolerance(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	if err := Finalize(ctx, e.st, e.dir, "v0.1.0"); err != nil { // no file
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(e.dir, StateFile), []byte("{broken"), 0o600)
	if err := Finalize(ctx, e.st, e.dir, "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, StateFile)); err == nil {
		t.Fatal("broken update.json must be removed")
	}
	writeHandoff(t, e.dir, handoff{JobID: "gone", To: "v0.2.0"}) // job unknown
	if err := Finalize(ctx, e.st, e.dir, "v0.2.0"); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryInterruptedJobsAreStillFailed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "v0.1.0")
	id := handedOff(t, e)
	// no update.json: the restart was not an update
	r2, err := jobs.NewRunner(ctx, e.st, Pending(e.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Shutdown()
	if j := e.job(id); j.Status != store.JobFailed || j.Error != jobs.InterruptedMsg {
		t.Fatalf("%s %q", j.Status, j.Error)
	}
}

func TestNoSecretsInJobLog(t *testing.T) {
	e := newEnv(t, "v0.1.0")
	job, _ := e.svc.Start(context.Background(), Request{Source: "github", Version: "v0.2.0"})
	j := e.wait(job.ID)
	text := logText(j)
	if strings.Contains(text, EncodePublicKey(e.pub)) || strings.Contains(text, string(EncodePrivateKey(e.priv))) {
		t.Fatalf("key material in the log: %s", text)
	}
}
