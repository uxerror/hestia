package jobs

import (
	"context"
	"time"

	"hestia/internal/store"
)

// Demo starts the demonstration job: three ~1 s steps with log lines. It only
// exists to exercise the progress UI.
func (r *Runner) Demo() (store.Job, error) {
	return r.Start("demo", "Демонстрационная задача", func(ctx context.Context, run *Run) error {
		for _, title := range []string{"Подготовка", "Работа", "Завершение"} {
			err := run.Step(title, func(ctx context.Context) error {
				run.Log("info", "начало: "+title)
				select {
				case <-time.After(time.Second):
				case <-ctx.Done():
					return ctx.Err()
				}
				run.Log("info", "готово: "+title)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}
