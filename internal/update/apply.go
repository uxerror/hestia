package update

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/version"
)

//go:embed upgrade.sh
var upgradeScript []byte

// Paths on the controller's machine.
const (
	scriptDir  = "/usr/local/lib/hestia"
	scriptPath = scriptDir + "/upgrade.sh"
	newBinPath = selfinstall.BinPath + ".new"
	// StateFile is the handoff file between the job and the restarted
	// controller, inside the data directory.
	StateFile = "update.json"
	// LogFile is the log of the last upgrade.sh run.
	LogFile = "upgrade.log"
)

// handoff is the content of update.json.
type handoff struct {
	JobID      string    `json:"job_id"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	StartedAt  time.Time `json:"started_at"`
	RolledBack bool      `json:"rolled_back,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

// Request is the body of POST /update.
type Request struct {
	UploadID string `json:"upload_id"`
	Source   string `json:"source"`  // "github"
	Version  string `json:"version"` // github: the tag to install
	// Confirm accepts the warning about an unknown or dirty version.
	Confirm bool `json:"confirm"`
}

var listenRe = regexp.MustCompile(`--listen\s+\S*:(\d+)`)

// Start validates the request and starts the update job.
func (s *Service) Start(ctx context.Context, req Request) (store.Job, error) {
	loc, err := s.Location(ctx)
	if err != nil {
		return store.Job{}, err
	}
	if loc == nil {
		return store.Job{}, newErr(http.StatusConflict, noLocationReason)
	}
	var (
		bin    []byte
		ver    string
		fetch  func(ctx context.Context) ([]byte, error)
		cleanF func()
		title  string
	)
	switch {
	case req.UploadID != "":
		s.mu.Lock()
		s.purgeLocked()
		u, ok := s.uploads[req.UploadID]
		s.mu.Unlock()
		if !ok {
			return store.Job{}, newErr(http.StatusGone, errNoUpload.Error())
		}
		b, err := os.ReadFile(u.path)
		if err != nil {
			return store.Job{}, newErr(http.StatusGone, errNoUpload.Error())
		}
		bin, ver = b, u.version
		cleanF = func() { s.dropUpload(req.UploadID) }
		title = "Обновление контроллера до " + ver + " (из приложения)"
	case req.Source == "github":
		if !s.Configured() {
			return store.Job{}, newErr(http.StatusConflict, ErrNotConfigured.Error())
		}
		ver = req.Version
		if _, ok := version.Parse(ver); !ok {
			return store.Job{}, newErr(http.StatusBadRequest, "неверная версия")
		}
		fetch = func(ctx context.Context) ([]byte, error) {
			dctx, cancel := context.WithTimeout(ctx, DownloadTimeout)
			defer cancel()
			rel, err := s.GitHub.Latest(dctx)
			if err != nil {
				return nil, err
			}
			if rel.Tag != ver {
				return nil, fmt.Errorf("последний релиз теперь %s, а не %s — проверьте обновления заново", rel.Tag, ver)
			}
			return s.GitHub.FetchVerified(dctx, rel, s.PubKey)
		}
		title = "Обновление контроллера до " + ver + " (GitHub)"
	default:
		return store.Job{}, newErr(http.StatusBadRequest, "укажите upload_id или source=github")
	}
	d := version.Decide(s.Version, ver)
	if !d.Allowed {
		return store.Job{}, newErr(http.StatusUnprocessableEntity, d.Reason)
	}
	if d.Confirm && !req.Confirm {
		e := newErr(http.StatusConflict, d.Warning)
		e.Confirm = true
		return store.Job{}, e
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return store.Job{}, newErr(http.StatusConflict, "обновление уже идёт")
	}
	s.running = true
	s.mu.Unlock()
	done := func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		if cleanF != nil {
			cleanF()
		}
	}
	job, err := s.Runner.Start(JobKind, title, func(jctx context.Context, run *jobs.Run) error {
		err := s.execute(jctx, run, *loc, ver, bin, fetch)
		if errors.Is(err, jobs.ErrHandedOff) {
			// The process is about to be stopped; if it is not, let a new
			// update be started after a while.
			time.AfterFunc(10*time.Minute, done)
			return err
		}
		done()
		return err
	})
	if err != nil {
		done()
		return store.Job{}, err
	}
	return job, nil
}

func (s *Service) dropUpload(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.uploads[id]; ok {
		_ = os.Remove(u.path)
		delete(s.uploads, id)
	}
}

// execute is the body of the update job (steps 1–4 of the plan).
func (s *Service) execute(ctx context.Context, run *jobs.Run, loc selfinstall.Location, want string, bin []byte, fetch func(context.Context) ([]byte, error)) error {
	var sh Shell
	defer func() {
		if sh != nil {
			// A failed update must not leave the half-copied binary behind.
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, _ = sh.Exec(cctx, "rm -f "+newBinPath, nil)
			cancel()
			_ = sh.Close()
		}
	}()
	if fetch != nil {
		if err := run.Step("Загрузка релиза с GitHub и проверка подписи", func(ctx context.Context) error {
			b, err := fetch(ctx)
			if err != nil {
				return err
			}
			bin = b
			run.Log("info", fmt.Sprintf("Подпись и контрольная сумма верны (%d байт)", len(b)))
			return nil
		}); err != nil {
			return err
		}
	}
	var sum string
	if err := run.Step("Проверка бинарника", func(ctx context.Context) error {
		if err := selfinstall.ValidateServerBinary(bin); err != nil {
			return err
		}
		h := sha256.Sum256(bin)
		sum = hex.EncodeToString(h[:])
		run.Log("info", fmt.Sprintf("ELF linux/amd64, статический, %d байт, sha256 %s", len(bin), sum))
		return nil
	}); err != nil {
		return err
	}
	var port int
	if err := run.Step("Загрузка на машину контроллера", func(ctx context.Context) error {
		var err error
		if sh, err = s.Open(ctx, loc); err != nil {
			return err
		}
		logf := func(l string) { run.Log("info", l) }
		if err := sh.PutFile(ctx, logf, newBinPath, bin, "0755", "root:root"); err != nil {
			return err
		}
		r, err := sh.Exec(ctx, newBinPath+" version", nil)
		if err != nil {
			return fmt.Errorf("новый бинарник не запускается: %w", err)
		}
		got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Stdout), "hestia"))
		if got != want {
			return fmt.Errorf("версия загруженного бинарника (%q) не совпала с ожидаемой (%q)", got, want)
		}
		// The downgrade rule is checked again on the version the binary reports.
		if d := version.Decide(s.Version, got); !d.Allowed {
			return errors.New(d.Reason)
		}
		run.Log("info", "Новый бинарник сообщает версию "+got)
		port = 80
		if u, err := sh.Exec(ctx, "cat "+selfinstall.UnitPath, nil); err == nil {
			if m := listenRe.FindStringSubmatch(u.Stdout); m != nil {
				port, _ = strconv.Atoi(m[1])
			}
		}
		return nil
	}); err != nil {
		return err
	}
	ts := s.Now().UTC()
	if err := run.Step("Скрипт обновления", func(ctx context.Context) error {
		if _, err := sh.Exec(ctx, "mkdir -p "+scriptDir+" && chmod 755 "+scriptDir, nil); err != nil {
			return err
		}
		logf := func(l string) { run.Log("info", l) }
		if err := sh.PutFile(ctx, logf, scriptPath, upgradeScript, "0755", "root:root"); err != nil {
			return err
		}
		st, _ := json.Marshal(handoff{JobID: run.ID(), From: s.Version, To: want, StartedAt: ts})
		return sh.PutFile(ctx, nil, selfinstall.DataPath+"/"+StateFile, append(st, '\n'), "0600", selfinstall.SvcUser+":"+selfinstall.SvcUser)
	}); err != nil {
		return err
	}
	// The last step never finishes in this process: the service is stopped
	// right after it. The next process closes the job (Finalize).
	unit := "hestia-upgrade-" + ts.Format("20060102-150405")
	return run.Step("Перезапуск контроллера", func(ctx context.Context) error {
		run.Log("info", "Перезапуск контроллера…")
		cmd := fmt.Sprintf("systemd-run --unit %s --collect %s %d", unit, scriptPath, port)
		run.Log("info", "$ "+cmd)
		if _, err := sh.Exec(ctx, cmd, nil); err != nil {
			return fmt.Errorf("запуск скрипта обновления: %w", err)
		}
		// The service is restarted under us: nothing to clean up.
		_ = sh.Close()
		sh = nil
		return jobs.ErrHandedOff
	})
}

// ---- after the restart ----

// Pending returns the id of the update job a previous process handed over
// (or "") so the job runner does not mark it interrupted.
func Pending(dataDir string) string {
	h, err := readHandoff(dataDir)
	if err != nil || h == nil {
		return ""
	}
	return h.JobID
}

func readHandoff(dataDir string) (*handoff, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h handoff
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

const logTailLines = 40

// Finalize closes the update job a previous process handed over, based on
// update.json and the version of this process, appends the tail of
// upgrade.log, and removes update.json.
func Finalize(ctx context.Context, st *store.Store, dataDir, current string) error {
	h, err := readHandoff(dataDir)
	if err != nil {
		// A broken file must not block start-up; drop it.
		_ = os.Remove(filepath.Join(dataDir, StateFile))
		return nil
	}
	if h == nil {
		return nil
	}
	statePath := filepath.Join(dataDir, StateFile)
	job, err := st.GetJob(ctx, h.JobID)
	if err != nil {
		_ = os.Remove(statePath)
		return nil // the job is gone: nothing to close
	}
	if job.Status != store.JobRunning && job.Status != store.JobQueued {
		// Already closed by an earlier start of this version (the script
		// removes the file only after its health check passed).
		_ = os.Remove(statePath)
		return nil
	}
	ok := !h.RolledBack && current == h.To
	if !ok {
		defer os.Remove(statePath)
	}
	// On success update.json is kept: upgrade.sh deletes it once the health
	// check passed. If the new version dies before that, the script restores
	// the old database (where this job is still running), marks the file
	// rolled back and the old version reports the failure.
	now := time.Now().UTC()
	log := func(level, line string) {
		_ = st.AppendLog(ctx, job.ID, store.LogLine{At: time.Now().UTC(), Level: level, Line: line})
	}
	if tail := logTail(filepath.Join(dataDir, LogFile), logTailLines); tail != "" {
		log("info", "— upgrade.log —")
		for _, l := range strings.Split(tail, "\n") {
			log("info", l)
		}
	}
	msg := ""
	next := 0
	for _, step := range job.Steps {
		if step.Idx >= next {
			next = step.Idx + 1
		}
		if step.Status == store.StepRunning || step.Status == store.StepPending {
			status, e := store.StepDone, ""
			if !ok {
				status, e = store.StepFailed, "новая версия не запустилась"
			}
			_ = st.UpdateStep(ctx, job.ID, step.Idx, status, &now, e)
		}
	}
	if ok {
		_ = st.InsertStep(ctx, job.ID, store.Step{Idx: next, Title: "Контроллер перезапущен, версия " + current, Status: store.StepDone, StartedAt: &now})
		_ = st.UpdateStep(ctx, job.ID, next, store.StepDone, &now, "")
		return st.UpdateJob(ctx, job.ID, store.JobDone, nil, &now, "")
	}
	msg = fmt.Sprintf("Новая версия не запустилась, возвращена %s", h.From)
	if h.Reason != "" {
		msg += " (" + h.Reason + ")"
	}
	log("error", msg)
	return st.UpdateJob(ctx, job.ID, store.JobFailed, nil, &now, msg)
}

func logTail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ---- uploads ----

// Upload stores a binary sent by the app (read from r, at most MaxUpload)
// and reports what it is. claimed is the version the sender says it is; it is
// verified later by running the binary on the controller's machine.
func (s *Service) Upload(r io.Reader, claimed string) (Uploaded, error) {
	if claimed == "" {
		return Uploaded{}, newErr(http.StatusBadRequest, "не указана версия загружаемой сборки")
	}
	b, err := io.ReadAll(io.LimitReader(r, MaxUpload+1))
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) || int64(len(b)) > MaxUpload {
		return Uploaded{}, newErr(http.StatusRequestEntityTooLarge, "файл больше 64 МБ")
	}
	if err != nil {
		return Uploaded{}, newErr(http.StatusBadRequest, "загрузка прервана: "+err.Error())
	}
	if err := selfinstall.ValidateServerBinary(b); err != nil {
		return Uploaded{}, newErr(http.StatusUnprocessableEntity, err.Error())
	}
	d := version.Decide(s.Version, claimed)
	if !d.Allowed {
		return Uploaded{}, newErr(http.StatusUnprocessableEntity, d.Reason)
	}
	if err := os.MkdirAll(s.uploadDir(), 0o700); err != nil {
		return Uploaded{}, err
	}
	id := randID()
	path := filepath.Join(s.uploadDir(), id+".bin")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return Uploaded{}, err
	}
	sum := sha256.Sum256(b)
	v, _ := version.Parse(claimed)
	s.mu.Lock()
	s.purgeLocked()
	s.uploads[id] = &upload{path: path, version: claimed, sha: hex.EncodeToString(sum[:]), expires: s.Now().Add(uploadTTL)}
	s.mu.Unlock()
	return Uploaded{UploadID: id, Version: claimed, SHA256: hex.EncodeToString(sum[:]), Dirty: v.Dirty, Warning: d.Warning}, nil
}

// CleanTemp removes leftovers of uploads from earlier processes; call at start.
func (s *Service) CleanTemp() { _ = os.RemoveAll(s.uploadDir()) }
