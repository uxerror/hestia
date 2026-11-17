// Package jobs runs background tasks with steps and a log, persisting
// everything to the store and publishing live events through a Hub.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"hestia/internal/store"
)

// InterruptedMsg is the error set on jobs left unfinished by a restart.
const InterruptedMsg = "прервано перезапуском"

// Func is the body of a job.
type Func func(ctx context.Context, r *Run) error

// Runner starts jobs in goroutines.
type Runner struct {
	store *store.Store
	hub   *Hub
	ctx   context.Context
	stop  context.CancelFunc
	wg    sync.WaitGroup
}

// NewRunner creates a Runner and marks jobs left unfinished by a previous
// process as failed.
func NewRunner(ctx context.Context, s *store.Store) (*Runner, error) {
	if _, err := s.FailUnfinished(ctx, InterruptedMsg, time.Now()); err != nil {
		return nil, err
	}
	rctx, stop := context.WithCancel(ctx)
	return &Runner{store: s, hub: NewHub(), ctx: rctx, stop: stop}, nil
}

// Hub returns the event hub.
func (r *Runner) Hub() *Hub { return r.hub }

// Shutdown cancels running jobs and waits for them to settle.
func (r *Runner) Shutdown() {
	r.stop()
	r.wg.Wait()
}

// Wait blocks until all started jobs have finished (useful in tests).
func (r *Runner) Wait() { r.wg.Wait() }

// Start creates a job and runs fn in a goroutine. The returned Job is the
// freshly created (queued) record.
func (r *Runner) Start(kind, title string, fn Func) (store.Job, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return store.Job{}, err
	}
	j := store.Job{
		ID: hex.EncodeToString(b), Kind: kind, Title: title,
		Status: store.JobQueued, CreatedAt: time.Now().UTC(),
		Steps: []store.Step{}, Log: []store.LogLine{},
	}
	if err := r.store.InsertJob(context.Background(), j); err != nil {
		return store.Job{}, err
	}
	r.wg.Add(1)
	go r.run(j, fn)
	return j, nil
}

func (r *Runner) run(j store.Job, fn Func) {
	defer r.wg.Done()
	bg := context.Background() // DB writes must survive cancellation of the job context
	run := &Run{runner: r, jobID: j.ID, ctx: r.ctx}

	started := time.Now().UTC()
	_ = r.store.UpdateJob(bg, j.ID, store.JobRunning, &started, nil, "")
	r.publishStatus(j.ID, store.JobRunning, "", nil)

	err := safeCall(r.ctx, run, fn)
	if err == nil {
		err = run.stepErr // a failed step fails the job even if fn swallowed the error
	}

	status, msg := store.JobDone, ""
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled) || r.ctx.Err() != nil:
		status, msg = store.JobCancelled, "отменено"
	default:
		status, msg = store.JobFailed, err.Error()
	}
	finished := time.Now().UTC()
	_ = r.store.UpdateJob(bg, j.ID, status, nil, &finished, msg)
	r.publishStatus(j.ID, status, msg, &finished)
}

func safeCall(ctx context.Context, run *Run, fn Func) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("паника в задаче: %v", p)
		}
	}()
	return fn(ctx, run)
}

func (r *Runner) publishStatus(id, status, errMsg string, finished *time.Time) {
	r.hub.Publish(id, Event{Type: "status", Data: StatusEvent{Status: status, Error: errMsg, FinishedAt: finished}})
}

// StatusEvent is the data of a "status" event.
type StatusEvent struct {
	Status     string     `json:"status"`
	Error      string     `json:"error"`
	FinishedAt *time.Time `json:"finished_at"`
}

// StepEvent is the data of a "step" event.
type StepEvent struct {
	Idx    int    `json:"idx"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

// Run is the handle a job body uses to report progress.
type Run struct {
	runner  *Runner
	jobID   string
	ctx     context.Context
	mu      sync.Mutex
	next    int
	stepErr error
}

// ID returns the job id.
func (r *Run) ID() string { return r.jobID }

// Log records a log line (level: info, warn, error).
func (r *Run) Log(level, line string) {
	l := store.LogLine{At: time.Now().UTC(), Level: level, Line: line}
	_ = r.runner.store.AppendLog(context.Background(), r.jobID, l)
	r.runner.hub.Publish(r.jobID, Event{Type: "log", Data: l})
}

// Step runs fn as the next step: it is recorded as running, then done or
// failed. It returns fn's error (or the context error if already cancelled).
func (r *Run) Step(title string, fn func(ctx context.Context) error) error {
	bg := context.Background()
	r.mu.Lock()
	idx := r.next
	r.next++
	r.mu.Unlock()

	now := time.Now().UTC()
	st := store.Step{Idx: idx, Title: title, Status: store.StepRunning, StartedAt: &now}
	_ = r.runner.store.InsertStep(bg, r.jobID, st)
	r.emitStep(st, "")

	err := r.ctx.Err()
	if err == nil {
		err = fn(r.ctx)
	}
	fin := time.Now().UTC()
	status, msg := store.StepDone, ""
	if err != nil {
		status, msg = store.StepFailed, err.Error()
		r.mu.Lock()
		if r.stepErr == nil {
			r.stepErr = err
		}
		r.mu.Unlock()
	}
	_ = r.runner.store.UpdateStep(bg, r.jobID, idx, status, &fin, msg)
	st.Status = status
	r.emitStep(st, msg)
	return err
}

func (r *Run) emitStep(st store.Step, msg string) {
	r.runner.hub.Publish(r.jobID, Event{Type: "step", Data: StepEvent{Idx: st.Idx, Title: st.Title, Status: st.Status, Error: msg}})
}
