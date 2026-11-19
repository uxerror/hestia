package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/sdk"
)

// project is the compose project of every instance (Hestia makes it
// hestia-<instance>-whoami in /opt/hestia/<instance>-whoami/).
const project = "whoami"

// Image of the demo service.
const image = "traefik/whoami:v1.10"

// Timeouts of the HTTP check.
var (
	checkTimeout  = 20 * time.Second // apply: wait for 200
	statusTimeout = 5 * time.Second
	checkInterval = time.Second
)

type hello struct {
	// HTTP is used for the checks (tests replace it).
	HTTP *http.Client
}

func (h *hello) client() *http.Client {
	if h.HTTP != nil {
		return h.HTTP
	}
	return &http.Client{Timeout: statusTimeout}
}

// planData travels from Plan to Apply unchanged (Hestia stores it).
type planData struct {
	Target    string `json:"target"`
	OldTarget string `json:"old_target,omitempty"`
	URL       string `json:"url,omitempty"`
}

// compose is the compose file of the instance (JSON: Hestia accepts compose
// as a JSON object).
func compose(port int64, msg string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"services": map[string]any{
			"whoami": map[string]any{
				"image":   image,
				"command": []string{"--name", msg},
				"ports":   []string{fmt.Sprintf("%d:80", port)},
				"restart": "unless-stopped",
			},
		},
	})
	return b
}

func port(cfg sdk.Config) int64 {
	if p := cfg.Int("port"); p > 0 {
		return p
	}
	return 8080
}

func (h *hello) Validate(ctx context.Context, cfg sdk.Config) []sdk.FieldError {
	var errs []sdk.FieldError
	if strings.TrimSpace(cfg.String("message")) == "" {
		errs = append(errs, sdk.FieldError{Field: "message", Msg: "приветствие не может быть пустым"})
	}
	if cfg.String("target") == "" {
		errs = append(errs, sdk.FieldError{Field: "target", Msg: "выберите, где запустить whoami"})
	}
	if p := cfg.Int("port"); p < 1 || p > 65535 {
		errs = append(errs, sdk.FieldError{Field: "port", Msg: "порт от 1 до 65535"})
	}
	return errs
}

// target returns the granted target with this id.
func target(ctx context.Context, host *sdk.Host, inst int64, id string) (sdk.TargetInfo, error) {
	ts, err := host.Targets(ctx, inst)
	if err != nil {
		return sdk.TargetInfo{}, err
	}
	for _, t := range ts {
		if t.ID == id {
			return t, nil
		}
	}
	return sdk.TargetInfo{ID: id, Name: id}, nil
}

// serviceURL is where whoami answers ("" if the target has no address).
func serviceURL(t sdk.TargetInfo, port int64) string {
	if t.Address == "" {
		return ""
	}
	return "http://" + net.JoinHostPort(t.Address, strconv.FormatInt(port, 10)) + "/"
}

func (h *hello) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	host := sdk.HostFrom(ctx)
	inst := req.Instance.ID
	old := req.Instance.Config.String("target")
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}

	if req.Action == sdk.ActionRemove {
		t, err := target(ctx, host, inst, old)
		if err != nil {
			return pl, err
		}
		st, err := host.DeployStatus(ctx, sdk.DeployStatusRequest{Instance: inst, Target: old, Project: project})
		if err != nil {
			return pl, err
		}
		if st.Exists || len(st.Containers) > 0 {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Остановить и удалить whoami", Detail: "на " + t.Name + ": контейнер, его тома и каталог проекта", Risk: sdk.RiskChange})
		} else {
			pl.Warnings = append(pl.Warnings, "На "+t.Name+" whoami уже нет — удалится только экземпляр")
		}
		pl.Data, _ = json.Marshal(planData{Target: old})
		return pl, nil
	}

	tgt := req.Config.String("target")
	d := planData{Target: tgt}
	if req.Action == sdk.ActionUpdate && old != "" && old != tgt {
		d.OldTarget = old
		ot, err := target(ctx, host, inst, old)
		if err != nil {
			return pl, err
		}
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Остановить и удалить whoami на старой цели", Detail: ot.Name, Risk: sdk.RiskChange})
	}
	t, err := target(ctx, host, inst, tgt)
	if err != nil {
		return pl, err
	}
	dp, err := host.DeployPlan(ctx, sdk.DeployRequest{Instance: inst, Target: tgt, Project: project, Compose: compose(port(req.Config), req.Config.String("message"))})
	if err != nil {
		return pl, err
	}
	pl.Actions = append(pl.Actions, dp.Actions...)
	pl.Warnings = append(pl.Warnings, dp.Warnings...)
	d.URL = serviceURL(t, port(req.Config))
	if d.URL != "" {
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Проверить " + d.URL, Detail: "ждать ответа 200 до 20 секунд", Risk: sdk.RiskInfo})
	} else {
		pl.Warnings = append(pl.Warnings, "У цели "+t.Name+" нет известного адреса — проверку по HTTP Hestia пропустит")
	}
	pl.Data, _ = json.Marshal(d)
	return pl, nil
}

func (h *hello) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	host := job.Host()
	inst := req.Instance.ID
	var d planData
	if err := json.Unmarshal(req.Plan.Data, &d); err != nil || d.Target == "" {
		return errors.New("план без данных: составьте его заново")
	}
	// deploy.up/down add their own job steps.
	if req.Action == sdk.ActionRemove || d.OldTarget != "" {
		tgt := d.Target
		if d.OldTarget != "" {
			tgt = d.OldTarget
		}
		if err := host.DeployDown(ctx, sdk.DeployDownRequest{JobID: job.ID, Instance: inst, Target: tgt, Project: project, Volumes: true}); err != nil {
			return err
		}
		if req.Action == sdk.ActionRemove {
			return nil
		}
	}
	st, err := host.DeployUp(ctx, sdk.DeployRequest{JobID: job.ID, Instance: inst, Target: d.Target, Project: project,
		Compose: compose(port(req.Config), req.Config.String("message"))})
	if err != nil {
		return err
	}
	for _, c := range st.Containers {
		job.Logf("%s: %s", c.Name, c.Status)
	}
	if d.URL == "" {
		job.Log("warn", "У цели нет адреса: проверка по HTTP пропущена")
		return nil
	}
	return job.Run("Проверка "+d.URL, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, checkTimeout)
		defer cancel()
		var last error
		for {
			code, body, err := h.get(ctx, d.URL)
			if err == nil && code == http.StatusOK {
				job.Logf("Ответ 200: %s", firstLine(body))
				return nil
			}
			last = err
			if err == nil {
				last = fmt.Errorf("ответ %d", code)
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("whoami не ответил 200 за %s: %v", checkTimeout, last)
			case <-time.After(checkInterval):
			}
		}
	})
}

// get fetches url (at most 64 KB of the body).
func (h *hello) get(ctx context.Context, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b), nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}

func (h *hello) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	host := sdk.HostFrom(ctx)
	t, err := target(ctx, host, inst.ID, inst.Config.String("target"))
	if err != nil {
		return sdk.Status{State: sdk.StateUnknown, Detail: err.Error()}, nil
	}
	u := serviceURL(t, port(inst.Config))
	if u == "" {
		return sdk.Status{State: sdk.StateUnknown, Detail: "у цели нет известного адреса"}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	ep := []sdk.Endpoint{{Name: "whoami", URL: u}}
	code, body, err := h.get(ctx, u)
	switch {
	case err != nil:
		return sdk.Status{State: sdk.StateDown, Detail: "не отвечает: " + err.Error(), Endpoints: ep}, nil
	case code != http.StatusOK:
		return sdk.Status{State: sdk.StateDegraded, Detail: fmt.Sprintf("ответ %d", code), Endpoints: ep}, nil
	}
	return sdk.Status{State: sdk.StateOK, Detail: firstLine(body), Endpoints: ep}, nil
}
