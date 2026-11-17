package selfinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"hestia/internal/auth"
	"hestia/internal/secrets"
	"hestia/internal/store"
)

// bundle is the state shipped to the new controller.
type bundle struct {
	DB    []byte // hestia.db, single file
	Key   []byte // master.key
	Token string // one-time handoff token (in the DB copy only as a hash)
}

// buildBundle snapshots the database (VACUUM INTO a temporary directory
// inside the data directory, mode 0700) and prepares the copy for the new
// controller: it records where the controller lives, marks the running
// installation job as done and adds a one-time handoff token for the user who
// started it. The temporary files are removed before returning.
func (s *Service) buildBundle(ctx context.Context, jobID string, userID int64, loc Location) (*bundle, error) {
	tmp, err := os.MkdirTemp(s.DataDir, "transfer-")
	if err != nil {
		return nil, fmt.Errorf("временный каталог: %w", err)
	}
	defer os.RemoveAll(tmp)

	if _, err := s.Store.SnapshotTo(ctx, tmp); err != nil {
		return nil, err
	}
	cp, err := store.OpenCopy(tmp)
	if err != nil {
		return nil, fmt.Errorf("открытие копии базы: %w", err)
	}
	token, hash, err := auth.NewHandoff()
	if err != nil {
		_ = cp.Close()
		return nil, err
	}
	if err := s.prepareCopy(ctx, cp, jobID, userID, loc, hash); err != nil {
		_ = cp.Close()
		return nil, err
	}
	if err := cp.Close(); err != nil {
		return nil, err
	}
	db, err := os.ReadFile(filepath.Join(tmp, "hestia.db"))
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(s.DataDir, secrets.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("мастер-ключ: %w", err)
	}
	return &bundle{DB: db, Key: key, Token: token}, nil
}

func (s *Service) prepareCopy(ctx context.Context, cp *store.Store, jobID string, userID int64, loc Location, hash string) error {
	b, err := json.Marshal(loc)
	if err != nil {
		return err
	}
	if err := cp.SetSetting(ctx, store.SettingControllerLocation, string(b)); err != nil {
		return err
	}
	if err := cp.CreateHandoff(ctx, hash, userID, s.Now().Add(auth.HandoffTTL)); err != nil {
		return fmt.Errorf("токен входа: %w", err)
	}
	// The job that runs the transfer ends in the copy as finished: the new
	// controller must not report it as "interrupted by a restart".
	now := s.Now().UTC()
	j, err := cp.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	idx := 0
	for _, st := range j.Steps {
		if st.Idx >= idx {
			idx = st.Idx + 1
		}
		if st.Status == store.StepRunning {
			if err := cp.UpdateStep(ctx, jobID, st.Idx, store.StepDone, &now, ""); err != nil {
				return err
			}
		}
	}
	done := store.Step{Idx: idx, Title: "Состояние перенесено", Status: store.StepDone, StartedAt: &now}
	if err := cp.InsertStep(ctx, jobID, done); err != nil {
		return err
	}
	if err := cp.UpdateStep(ctx, jobID, idx, store.StepDone, &now, ""); err != nil {
		return err
	}
	_ = cp.AppendLog(ctx, jobID, store.LogLine{At: now, Level: "info", Line: "Состояние перенесено на новый контроллер"})
	return cp.UpdateJob(ctx, jobID, store.JobDone, nil, &now, "")
}

// switchOver makes this process a client of the new controller: remote.json
// is written first (from now on a restart opens in "moved" mode), the gate
// flips, and the local database and master key go to <data>/archive/<time>/.
func (in *installer) switchOver(ctx context.Context, res *Result) error {
	s := in.s
	id, err := s.Store.EnsureInstanceID(ctx)
	if err != nil {
		return err
	}
	remote := Remote{URL: res.URL, InstanceID: id, Location: in.location()}
	if err := WriteRemote(s.DataDir, remote); err != nil {
		return fmt.Errorf("запись %s: %w", RemoteFile, err)
	}
	s.Gate.SetMoved(remote)
	s.Gate.SetTransferring(false)
	if s.OnSwitched != nil {
		s.OnSwitched()
	}
	dir := filepath.Join(s.DataDir, "archive", s.Now().UTC().Format("20060102T150405Z"))
	if err := s.Store.Archive(ctx, s.DataDir, dir); err != nil {
		return fmt.Errorf("архивирование базы: %w", err)
	}
	if err := os.Rename(filepath.Join(s.DataDir, secrets.KeyFile), filepath.Join(dir, secrets.KeyFile)); err != nil {
		return fmt.Errorf("архивирование мастер-ключа: %w", err)
	}
	_ = os.Chmod(filepath.Join(dir, secrets.KeyFile), 0o600)
	in.run.Log("info", "Локальные база и ключ перенесены в "+dir)
	return nil
}
