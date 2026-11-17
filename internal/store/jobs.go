package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Job and step statuses.
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobDone      = "done"
	JobFailed    = "failed"
	JobCancelled = "cancelled"

	StepPending = "pending"
	StepRunning = "running"
	StepDone    = "done"
	StepFailed  = "failed"
	StepSkipped = "skipped"
)

// Step is one stage of a job.
type Step struct {
	Idx        int        `json:"idx"`
	Title      string     `json:"title"`
	Status     string     `json:"status"`
	Error      string     `json:"error"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// LogLine is one job log entry.
type LogLine struct {
	At    time.Time `json:"at"`
	Level string    `json:"level"`
	Line  string    `json:"line"`
}

// Job is a background task with steps and a log.
type Job struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Title      string     `json:"title"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Error      string     `json:"error"`
	Steps      []Step     `json:"steps"`
	Log        []LogLine  `json:"log"`
}

// IsFinal reports whether the status can no longer change.
func IsFinal(status string) bool {
	return status == JobDone || status == JobFailed || status == JobCancelled
}

// InsertJob creates a queued job.
func (s *Store) InsertJob(ctx context.Context, j Job) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO jobs(id, kind, title, status, created_at) VALUES (?, ?, ?, ?, ?)`,
		j.ID, j.Kind, j.Title, j.Status, ms(j.CreatedAt))
	return err
}

// UpdateJob sets status, timestamps and error of a job.
func (s *Store) UpdateJob(ctx context.Context, id, status string, started, finished *time.Time, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = ?, started_at = COALESCE(?, started_at),
		finished_at = ?, error = ? WHERE id = ?`, status, nullMS(started), nullMS(finished), errMsg, id)
	return err
}

// InsertStep adds a step to a job.
func (s *Store) InsertStep(ctx context.Context, jobID string, st Step) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO job_steps(job_id, idx, title, status, started_at) VALUES (?, ?, ?, ?, ?)`,
		jobID, st.Idx, st.Title, st.Status, nullMS(st.StartedAt))
	return err
}

// UpdateStep sets status, finish time and error of a step.
func (s *Store) UpdateStep(ctx context.Context, jobID string, idx int, status string, finished *time.Time, errMsg string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ?, error = ? WHERE job_id = ? AND idx = ?`,
		status, nullMS(finished), errMsg, jobID, idx)
	return err
}

// AppendLog adds a log line to a job.
func (s *Store) AppendLog(ctx context.Context, jobID string, l LogLine) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO job_log(job_id, at, level, line) VALUES (?, ?, ?, ?)`,
		jobID, ms(l.At), l.Level, l.Line)
	return err
}

const jobCols = `id, kind, title, status, created_at, started_at, finished_at, error`

type rowScanner interface{ Scan(...any) error }

func scanJob(r rowScanner) (Job, error) {
	var j Job
	var created int64
	var started, finished sql.NullInt64
	if err := r.Scan(&j.ID, &j.Kind, &j.Title, &j.Status, &created, &started, &finished, &j.Error); err != nil {
		return Job{}, err
	}
	j.CreatedAt = fromMS(created)
	j.StartedAt = fromNullMS(started)
	j.FinishedAt = fromNullMS(finished)
	j.Steps = []Step{}
	j.Log = []LogLine{}
	return j, nil
}

// GetJob returns a job with all steps and log lines.
func (s *Store) GetJob(ctx context.Context, id string) (Job, error) {
	j, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT idx, title, status, started_at, finished_at, error
		FROM job_steps WHERE job_id = ? ORDER BY idx`, id)
	if err != nil {
		return Job{}, err
	}
	for rows.Next() {
		var st Step
		var started, finished sql.NullInt64
		if err := rows.Scan(&st.Idx, &st.Title, &st.Status, &started, &finished, &st.Error); err != nil {
			_ = rows.Close()
			return Job{}, err
		}
		st.StartedAt, st.FinishedAt = fromNullMS(started), fromNullMS(finished)
		j.Steps = append(j.Steps, st)
	}
	if err := closeRows(rows); err != nil {
		return Job{}, err
	}
	lrows, err := s.db.QueryContext(ctx, `SELECT at, level, line FROM job_log WHERE job_id = ? ORDER BY id`, id)
	if err != nil {
		return Job{}, err
	}
	for lrows.Next() {
		var l LogLine
		var at int64
		if err := lrows.Scan(&at, &l.Level, &l.Line); err != nil {
			_ = lrows.Close()
			return Job{}, err
		}
		l.At = fromMS(at)
		j.Log = append(j.Log, l)
	}
	if err := closeRows(lrows); err != nil {
		return Job{}, err
	}
	return j, nil
}

func closeRows(r *sql.Rows) error {
	if err := r.Err(); err != nil {
		_ = r.Close()
		return err
	}
	return r.Close()
}

// ListJobs returns the most recent jobs (without steps and log), newest first.
func (s *Store) ListJobs(ctx context.Context, limit int) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+` FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	jobs := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, closeRows(rows)
}

// FailUnfinished marks queued/running jobs as failed (used on process start)
// and settles their unfinished steps. Jobs listed in keep are left alone (the
// update job closes itself after the restart). It returns the number of jobs
// changed.
func (s *Store) FailUnfinished(ctx context.Context, msg string, now time.Time, keep ...string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	t := ms(now)
	// Only "?" placeholders are built here; the ids are bound as parameters.
	notKept, extra := "", []any(nil)
	if len(keep) > 0 {
		notKept = ` AND id NOT IN (?` + strings.Repeat(`,?`, len(keep)-1) + `)`
		for _, id := range keep {
			extra = append(extra, id)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ?, error = ?
		WHERE status = ? AND job_id IN (SELECT id FROM jobs WHERE status IN (?, ?)`+notKept+`)`,
		append([]any{StepFailed, t, msg, StepRunning, JobQueued, JobRunning}, extra...)...); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET status = ?, finished_at = ?
		WHERE status = ? AND job_id IN (SELECT id FROM jobs WHERE status IN (?, ?)`+notKept+`)`,
		append([]any{StepSkipped, t, StepPending, JobQueued, JobRunning}, extra...)...); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status = ?, finished_at = ?, error = ? WHERE status IN (?, ?)`+notKept,
		append([]any{JobFailed, t, msg, JobQueued, JobRunning}, extra...)...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), tx.Commit()
}
