package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/uxerror/hestia/sdk"
)

type hello struct{}

// planData travels from Plan to Apply unchanged (Hestia stores it).
type planData struct {
	Path      string `json:"path"`
	Target    string `json:"target"`
	OldTarget string `json:"old_target,omitempty"`
	Write     bool   `json:"write"`
}

func filePath(inst int64) string { return fmt.Sprintf("/tmp/hestia-hello-%d", inst) }

func content(msg string) string { return msg + "\n" }

func (h *hello) Validate(ctx context.Context, cfg sdk.Config) []sdk.FieldError {
	var errs []sdk.FieldError
	if strings.TrimSpace(cfg.String("message")) == "" {
		errs = append(errs, sdk.FieldError{Field: "message", Msg: "приветствие не может быть пустым"})
	}
	if cfg.String("target") == "" {
		errs = append(errs, sdk.FieldError{Field: "target", Msg: "выберите, где записать файл"})
	}
	return errs
}

// read returns the file on the target ("", false if there is none).
func read(ctx context.Context, host *sdk.Host, inst int64, target string) (string, bool, error) {
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: inst, Target: target,
		Cmd: "cat " + filePath(inst) + " 2>/dev/null || exit 3", TimeoutS: 30})
	if err != nil {
		return "", false, err
	}
	switch res.Code {
	case 0:
		return res.Stdout, true, nil
	case 3:
		return "", false, nil
	}
	return "", false, fmt.Errorf("cat: код %d: %s", res.Code, strings.TrimSpace(res.Stderr))
}

func (h *hello) targetName(ctx context.Context, host *sdk.Host, inst int64, id string) string {
	ts, err := host.Targets(ctx, inst)
	if err == nil {
		for _, t := range ts {
			if t.ID == id {
				return t.Name
			}
		}
	}
	return id
}

func (h *hello) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	host := sdk.HostFrom(ctx)
	inst := req.Instance.ID
	path := filePath(inst)
	tgt := req.Config.String("target")
	old := req.Instance.Config.String("target")
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	d := planData{Path: path, Target: tgt}

	if req.Action == sdk.ActionRemove {
		_, exists, err := read(ctx, host, inst, old)
		if err != nil {
			return pl, err
		}
		d.Target = old
		if exists {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Удалить " + path, Detail: "на " + h.targetName(ctx, host, inst, old), Risk: sdk.RiskChange})
		} else {
			pl.Warnings = append(pl.Warnings, "Файла "+path+" уже нет — удалится только экземпляр")
		}
		pl.Data, _ = json.Marshal(d)
		return pl, nil
	}

	if req.Action == sdk.ActionUpdate && old != "" && old != tgt {
		d.OldTarget = old
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Удалить " + path + " со старой цели", Detail: h.targetName(ctx, host, inst, old), Risk: sdk.RiskChange})
	}
	cur, exists, err := read(ctx, host, inst, tgt)
	if err != nil {
		return pl, err
	}
	want := content(req.Config.String("message"))
	switch {
	case exists && cur == want:
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Без изменений: " + path + " уже содержит приветствие", Risk: sdk.RiskInfo})
	case exists:
		d.Write = true
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Перезаписать " + path, Detail: fmt.Sprintf("«%s» → «%s»", strings.TrimSpace(cur), strings.TrimSpace(want)), Risk: sdk.RiskChange})
	default:
		d.Write = true
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Записать приветствие в " + path, Detail: "на " + h.targetName(ctx, host, inst, tgt), Risk: sdk.RiskChange})
	}
	pl.Data, _ = json.Marshal(d)
	return pl, nil
}

func (h *hello) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	host := job.Host()
	inst := req.Instance.ID
	var d planData
	if err := json.Unmarshal(req.Plan.Data, &d); err != nil {
		return errors.New("план без данных: составьте его заново")
	}
	if req.Action == sdk.ActionRemove || d.OldTarget != "" {
		tgt := d.Target
		if d.OldTarget != "" {
			tgt = d.OldTarget
		}
		err := job.Run("Удаление файла", func(ctx context.Context) error {
			res, err := host.Exec(ctx, sdk.ExecRequest{Instance: inst, Target: tgt, Cmd: "rm -f " + d.Path})
			if err != nil {
				return err
			}
			if res.Code != 0 {
				return fmt.Errorf("rm: код %d: %s", res.Code, strings.TrimSpace(res.Stderr))
			}
			job.Logf("Удалён %s", d.Path)
			return nil
		})
		if err != nil || req.Action == sdk.ActionRemove {
			return err
		}
	}
	if !d.Write {
		job.Logf("Файл уже в нужном состоянии")
		return nil
	}
	want := content(req.Config.String("message"))
	if err := job.Run("Запись приветствия", func(ctx context.Context) error {
		return host.PutFile(ctx, inst, d.Target, d.Path, []byte(want), 0o644)
	}); err != nil {
		return err
	}
	return job.Run("Проверка", func(ctx context.Context) error {
		got, ok, err := read(ctx, host, inst, d.Target)
		if err != nil {
			return err
		}
		if !ok || got != want {
			return errors.New("после записи в файле не то приветствие")
		}
		job.Logf("%s: %s", d.Path, strings.TrimSpace(got))
		return nil
	})
}

func (h *hello) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	host := sdk.HostFrom(ctx)
	tgt := inst.Config.String("target")
	got, ok, err := read(ctx, host, inst.ID, tgt)
	switch {
	case err != nil:
		return sdk.Status{State: sdk.StateUnknown, Detail: err.Error()}, nil
	case !ok:
		return sdk.Status{State: sdk.StateDown, Detail: "файла " + filePath(inst.ID) + " нет"}, nil
	case got != content(inst.Config.String("message")):
		return sdk.Status{State: sdk.StateDegraded, Detail: "в файле другое приветствие: " + strings.TrimSpace(got)}, nil
	}
	return sdk.Status{State: sdk.StateOK, Detail: strings.TrimSpace(got)}, nil
}
