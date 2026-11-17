package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"hestia/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRunnerPersistsStepsLogStatus(t *testing.T) {
	s := newStore(t)
	r, err := NewRunner(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	j, err := r.Start("t", "Тест", func(ctx context.Context, run *Run) error {
		run.Log("info", "привет")
		if err := run.Step("один", func(context.Context) error { return nil }); err != nil {
			return err
		}
		return run.Step("два", func(context.Context) error { return nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Wait()
	got, err := s.GetJob(context.Background(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.JobDone || got.StartedAt == nil || got.FinishedAt == nil {
		t.Fatalf("job = %+v", got)
	}
	if len(got.Steps) != 2 || got.Steps[0].Status != store.StepDone || got.Steps[1].Title != "два" {
		t.Fatalf("steps = %+v", got.Steps)
	}
	if len(got.Log) != 1 || got.Log[0].Line != "привет" {
		t.Fatalf("log = %+v", got.Log)
	}
}

func TestRunnerFailure(t *testing.T) {
	s := newStore(t)
	r, _ := NewRunner(context.Background(), s)
	j, _ := r.Start("t", "Падение", func(ctx context.Context, run *Run) error {
		return run.Step("плохо", func(context.Context) error { return errors.New("бум") })
	})
	r.Wait()
	got, _ := s.GetJob(context.Background(), j.ID)
	if got.Status != store.JobFailed || got.Error != "бум" || got.Steps[0].Status != store.StepFailed || got.Steps[0].Error != "бум" {
		t.Fatalf("job = %+v", got)
	}
}

func TestRunnerPanicBecomesFailure(t *testing.T) {
	s := newStore(t)
	r, _ := NewRunner(context.Background(), s)
	j, _ := r.Start("t", "Паника", func(context.Context, *Run) error { panic("x") })
	r.Wait()
	got, _ := s.GetJob(context.Background(), j.ID)
	if got.Status != store.JobFailed {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestRunnerShutdownCancels(t *testing.T) {
	s := newStore(t)
	r, _ := NewRunner(context.Background(), s)
	started := make(chan struct{})
	j, _ := r.Start("t", "Долго", func(ctx context.Context, run *Run) error {
		return run.Step("ждём", func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
	})
	<-started
	r.Shutdown()
	got, _ := s.GetJob(context.Background(), j.ID)
	if got.Status != store.JobCancelled {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestRestartMarksUnfinishedFailed(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"q", "r", "d"} {
		st := map[string]string{"q": store.JobQueued, "r": store.JobRunning, "d": store.JobDone}[id]
		if err := s.InsertJob(ctx, store.Job{ID: id, Kind: "k", Title: id, Status: st, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.InsertStep(ctx, "r", store.Step{Idx: 0, Title: "s0", Status: store.StepRunning, StartedAt: &now})
	_ = s.InsertStep(ctx, "r", store.Step{Idx: 1, Title: "s1", Status: store.StepPending})

	if _, err := NewRunner(ctx, s); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"q", "r"} {
		j, _ := s.GetJob(ctx, id)
		if j.Status != store.JobFailed || j.Error != InterruptedMsg || j.FinishedAt == nil {
			t.Errorf("%s: %+v", id, j)
		}
	}
	j, _ := s.GetJob(ctx, "r")
	if j.Steps[0].Status != store.StepFailed || j.Steps[1].Status != store.StepSkipped {
		t.Errorf("steps = %+v", j.Steps)
	}
	if d, _ := s.GetJob(ctx, "d"); d.Status != store.JobDone {
		t.Errorf("done job changed: %+v", d)
	}
}

func TestHubDropsSlowSubscriber(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe("j")
	defer cancel()
	for i := 0; i < subBuffer+1; i++ {
		h.Publish("j", Event{Type: "log"})
	}
	n := 0
	for range ch { // must terminate: channel was closed on overflow
		n++
	}
	if n != subBuffer {
		t.Fatalf("got %d events", n)
	}
}
