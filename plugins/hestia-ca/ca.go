package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/caserver"
	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
	"github.com/uxerror/hestia/sdk"
)

// project is the compose project of the CA (hestia-<instance>-ca).
const project = "ca"

// imageName is the image of the package with ca-server.
const imageName = "ca-server"

// Secrets of an instance.
const (
	secretToken = "api_token"
	secretPin   = "api_pin"
)

// Timeouts.
var (
	apiTimeout  = 15 * time.Second
	healthWait  = 30 * time.Second
	healthPoll  = time.Second
	execTimeout = 30
)

var reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type caPlugin struct {
	// Version is the plugin version (image tag).
	Version string
	// TestAddr replaces the address of the CA API (HESTIA_CA_TEST_ADDR,
	// read only in dev mode).
	TestAddr string
	// StateDir keeps what the plugin remembers (date of the last backup,
	// roots installed on devices): $STATE_DIRECTORY.
	StateDir string
	Now      func() time.Time
}

func (p *caPlugin) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// planData travels from Plan to Apply.
type planData struct {
	Target string `json:"target"`
}

func cfgInt(cfg sdk.Config, name string, def int64) int64 {
	if v := cfg.Int(name); v > 0 {
		return v
	}
	return def
}

func port(cfg sdk.Config) int64 { return cfgInt(cfg, "port", 9443) }

func zonesOf(cfg sdk.Config) string {
	if z := strings.TrimSpace(cfg.String("zones")); z != "" {
		return z
	}
	return "home,home.arpa"
}

func rangesOf(cfg sdk.Config) string {
	if _, ok := cfg["ip_ranges"]; ok {
		return cfg.String("ip_ranges")
	}
	return pki.DefaultIPRanges
}

func initMode(cfg sdk.Config) string {
	if cfg.String("init") == "restore" {
		return "restore"
	}
	return "new"
}

// leafLifetime is the lifetime of new certificates.
func leafLifetime(cfg sdk.Config) time.Duration {
	if m := cfg.Int("test_lifetime_min"); m > 0 {
		return time.Duration(m) * time.Minute
	}
	return time.Duration(cfgInt(cfg, "leaf_days", 90)) * 24 * time.Hour
}

// leafMax is HESTIA_CA_LEAF_MAX (the server refuses longer lifetimes).
func leafMax(cfg sdk.Config) string {
	if m := cfg.Int("test_lifetime_min"); m > 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh", cfgInt(cfg, "leaf_days", 90)*24)
}

func containerName(inst int64) string { return fmt.Sprintf("hestia-%d-%s-ca-1", inst, project) }

// compose is the compose file of the CA; tokenSHA is the sha256 of the API
// token (the token itself never leaves Hestia's secrets).
func (p *caPlugin) compose(cfg sdk.Config, tokenSHA string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"services": map[string]any{
			"ca": map[string]any{
				"image":       sdk.ImageRef("hestia-ca", imageName, p.Version),
				"pull_policy": "never",
				"command":     []string{"serve", "--listen", ":9443", "--data", "/data"},
				"environment": map[string]string{"HESTIA_CA_TOKEN_SHA256": tokenSHA, "HESTIA_CA_LEAF_MAX": leafMax(cfg)},
				"ports":       []string{fmt.Sprintf("%d:9443", port(cfg))},
				"volumes":     []string{"ca-data:/data"},
				"tmpfs":       []string{"/tmp"},
				"read_only":   true,
				"cap_drop":    []string{"ALL"},
				"restart":     "unless-stopped",
				"healthcheck": map[string]any{"test": []string{"CMD", "/" + imageName, "health"}, "interval": "30s", "timeout": "10s", "retries": 3},
			},
		},
		"volumes": map[string]any{"ca-data": map[string]any{}},
	})
	return b
}

// placeholderSHA stands for the token in plans (the real one is made in
// apply; the size of the file is the same).
var placeholderSHA = strings.Repeat("0", 64)

// immutable are the fields baked into the root or the place of the key.
var immutable = map[string]string{
	"target":     "Перенос CA на другой сервер — через резервную копию",
	"zones":      "Зашито в корневой сертификат — для другой зоны нужен новый CA",
	"ip_ranges":  "Зашито в корневой сертификат — для других адресов нужен новый CA",
	"root_years": "Зашито в корневой сертификат — для другого срока нужен новый CA",
	"init":       "Ключ CA уже создан или восстанавливается — способ не меняется",
}

func (p *caPlugin) Validate(ctx context.Context, cfg sdk.Config) []sdk.FieldError {
	var errs []sdk.FieldError
	if cfg.String("target") == "" {
		errs = append(errs, sdk.FieldError{Field: "target", Msg: "выберите, где запустить CA"})
	}
	if _, _, err := pki.ParseZones(zonesOf(cfg)); err != nil {
		errs = append(errs, sdk.FieldError{Field: "zones", Msg: err.Error()})
	}
	if _, err := pki.ParseIPRanges(rangesOf(cfg)); err != nil {
		errs = append(errs, sdk.FieldError{Field: "ip_ranges", Msg: err.Error()})
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

func (p *caPlugin) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	host := sdk.HostFrom(ctx)
	inst := req.Instance.ID
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	switch req.Action {
	case sdk.ActionRemove:
		tgt := req.Instance.Config.String("target")
		t, err := target(ctx, host, inst, tgt)
		if err != nil {
			return pl, err
		}
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Удалить ключ CA (том ca-data) безвозвратно",
			Detail: "на " + t.Name + ": контейнер ca-server, том с ключом и корнем, каталог проекта", Risk: sdk.RiskDanger})
		if d := p.lastBackup(inst); d != "" {
			pl.Warnings = append(pl.Warnings, "Последняя резервная копия: "+d)
		} else {
			pl.Warnings = append(pl.Warnings, "Резервная копия не делалась: без неё этот корень восстановить нельзя, устройства придётся перенастроить")
		}
		pl.Data, _ = json.Marshal(planData{Target: tgt})
		return pl, nil
	case sdk.ActionUpdate:
		for f, why := range immutable {
			if fmt.Sprint(req.Config[f]) != fmt.Sprint(req.Instance.Config[f]) {
				return pl, fmt.Errorf("поле %s не меняется после создания: %s", f, why)
			}
		}
	}
	zones, zw, err := pki.ParseZones(zonesOf(req.Config))
	if err != nil {
		return pl, err
	}
	ranges, err := pki.ParseIPRanges(rangesOf(req.Config))
	if err != nil {
		return pl, err
	}
	tgt := req.Config.String("target")
	dp, err := host.DeployPlan(ctx, sdk.DeployRequest{Instance: inst, Target: tgt, Project: project,
		Compose: p.compose(req.Config, placeholderSHA), Images: []string{imageName}})
	if err != nil {
		return pl, err
	}
	pl.Actions = append(pl.Actions, dp.Actions...)
	pl.Warnings = append(pl.Warnings, dp.Warnings...)
	if req.Action == sdk.ActionCreate {
		if initMode(req.Config) == "restore" {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Ждать восстановления из резервной копии",
				Detail: "После создания нажмите «Восстановить из резервной копии…»: зоны и диапазоны берутся из корня в файле, поля формы не используются",
				Risk:   sdk.RiskInfo})
		} else {
			var rs []string
			for _, n := range ranges {
				rs = append(rs, n.String())
			}
			ipText := strings.Join(rs, ", ")
			if ipText == "" {
				ipText = "нет (только DNS-имена)"
			}
			pl.Actions = append(pl.Actions, sdk.Action{
				Title: fmt.Sprintf("Создать корневой CA (ECDSA P-256, %d лет, зоны: %s; IP: %s)", cfgInt(req.Config, "root_years", 10),
					strings.Join(zones, ", "), ipText),
				Detail: "Ключ CA создаётся внутри ca-server и хранится только в томе ca-data на цели (0600). Компрометация root на цели CA = компрометация CA; NameConstraints ограничивают ущерб частной сетью.",
				Risk:   sdk.RiskChange,
			})
			pl.Warnings = append(pl.Warnings, "Зоны нельзя будет изменить: "+strings.Join(zones, ", "))
			pl.Warnings = append(pl.Warnings, zw...)
		}
	} else {
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Новый токен API CA и перезапуск ca-server (ключ CA и корень не меняются)", Risk: sdk.RiskChange})
	}
	if req.Config.Int("test_lifetime_min") > 0 {
		pl.Warnings = append(pl.Warnings, fmt.Sprintf("Тестовый режим: все сертификаты будут жить %d минут", req.Config.Int("test_lifetime_min")))
	}
	pl.Data, _ = json.Marshal(planData{Target: tgt})
	return pl, nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// dockerExec runs ca-server inside the container through Hestia's root
// transport (the trusted channel to the target).
func dockerExec(ctx context.Context, host *sdk.Host, inst int64, tgt string, args ...string) (string, error) {
	cmd := "docker exec " + containerName(inst) + " /" + imageName + " " + strings.Join(args, " ")
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: inst, Target: tgt, Cmd: cmd, TimeoutS: execTimeout})
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("%s: код %d: %s", args[0], res.Code, strings.TrimSpace(res.Stderr))
	}
	return strings.TrimSpace(res.Stdout), nil
}

// addr is host:port of the CA API.
func (p *caPlugin) addr(ctx context.Context, host *sdk.Host, inst sdk.Instance) (string, error) {
	if p.TestAddr != "" {
		return p.TestAddr, nil
	}
	t, err := target(ctx, host, inst.ID, inst.Config.String("target"))
	if err != nil {
		return "", err
	}
	if t.Address == "" {
		return "", fmt.Errorf("у цели %s нет известного адреса", t.Name)
	}
	return net.JoinHostPort(t.Address, strconv.FormatInt(port(inst.Config), 10)), nil
}

// client is the API client with the instance's token and pin.
func (p *caPlugin) client(ctx context.Context, host *sdk.Host, inst sdk.Instance) (*caserver.APIClient, error) {
	tok, ok, err := host.SecretGet(ctx, inst.ID, secretToken)
	if err != nil {
		return nil, err
	}
	pin, ok2, err := host.SecretGet(ctx, inst.ID, secretPin)
	if err != nil {
		return nil, err
	}
	if !ok || !ok2 {
		return nil, errors.New("у экземпляра нет токена или пина API CA — пересоздайте экземпляр")
	}
	a, err := p.addr(ctx, host, inst)
	if err != nil {
		return nil, err
	}
	return caserver.Client(a, pin, tok, apiTimeout), nil
}

type health struct {
	Version    string `json:"version"`
	State      string `json:"state"`
	RootSHA256 string `json:"root_sha256"`
}

// waitHealth polls /v1/health until the CA answers (with the pinned key).
func waitHealth(ctx context.Context, cl *caserver.APIClient) (health, error) {
	ctx, cancel := context.WithTimeout(ctx, healthWait)
	defer cancel()
	for {
		var h health
		err := cl.Do("GET", "/v1/health", nil, &h)
		if err == nil || errors.Is(err, caserver.ErrPin) {
			return h, err
		}
		select {
		case <-ctx.Done():
			return h, fmt.Errorf("CA не ответил за %s: %v", healthWait, err)
		case <-time.After(healthPoll):
		}
	}
}

func (p *caPlugin) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	host := job.Host()
	inst := req.Instance
	inst.Config = req.Config
	var d planData
	if err := json.Unmarshal(req.Plan.Data, &d); err != nil || d.Target == "" {
		return errors.New("план без данных: составьте его заново")
	}
	if req.Action == sdk.ActionRemove {
		if err := host.DeployDown(ctx, sdk.DeployDownRequest{JobID: job.ID, Instance: inst.ID, Target: d.Target, Project: project, Volumes: true}); err != nil {
			return err
		}
		_ = host.SecretDelete(ctx, inst.ID, secretToken)
		_ = host.SecretDelete(ctx, inst.ID, secretPin)
		_ = os.Remove(p.backupFile(inst.ID))
		return nil
	}
	tok, err := newToken()
	if err != nil {
		return err
	}
	if err := host.SecretPut(ctx, inst.ID, secretToken, tok); err != nil {
		return err
	}
	created := req.Action == sdk.ActionCreate
	undo := func(cause error) error {
		if !created {
			return cause
		}
		job.Log("warn", "Откат: ca-server и том ca-data удаляются (ключ только что создан и нигде не использован)")
		if err := host.DeployDown(context.WithoutCancel(ctx), sdk.DeployDownRequest{JobID: job.ID, Instance: inst.ID, Target: d.Target, Project: project, Volumes: true}); err != nil {
			job.Log("error", "Откат не удался: "+err.Error())
		}
		_ = host.SecretDelete(ctx, inst.ID, secretToken)
		_ = host.SecretDelete(ctx, inst.ID, secretPin)
		return cause
	}
	if _, err := host.DeployUp(ctx, sdk.DeployRequest{JobID: job.ID, Instance: inst.ID, Target: d.Target, Project: project,
		Compose: p.compose(req.Config, caserver.HashToken(tok)), Images: []string{imageName}}); err != nil {
		return undo(err)
	}
	if created {
		err := job.Run("Закрепление ключа API CA (docker exec, доверенный канал Hestia)", func(ctx context.Context) error {
			pin, err := dockerExec(ctx, host, inst.ID, d.Target, "api-pin")
			if err != nil {
				return err
			}
			if !reHex64.MatchString(pin) {
				return errors.New("ca-server вернул неверный пин")
			}
			return host.SecretPut(ctx, inst.ID, secretPin, pin)
		})
		if err != nil {
			return undo(err)
		}
	}
	cl, err := p.client(ctx, host, inst)
	if err != nil {
		return undo(err)
	}
	var h health
	if err := job.Run("Проверка API CA (TLS с закреплённым ключом)", func(ctx context.Context) error {
		h, err = waitHealth(ctx, cl)
		return err
	}); err != nil {
		return undo(err)
	}
	if !created {
		return nil
	}
	if initMode(req.Config) == "restore" {
		job.Log("info", "Ключ CA ожидает восстановления: нажмите «Восстановить из резервной копии…»")
		return nil
	}
	if h.State == caserver.StateReady {
		return undo(errors.New("в томе ca-data уже есть ключ CA: удалите старый экземпляр полностью или восстановите его резервную копию"))
	}
	return job.Run("Создание корневого CA", func(ctx context.Context) error {
		var out struct {
			RootPEM    string `json:"root_pem"`
			RootSHA256 string `json:"root_sha256"`
		}
		if err := cl.Do("POST", "/v1/init", caserver.InitRequest{Mode: "generate", OU: inst.Name, Zones: zonesOf(req.Config),
			IPRanges: rangesOf(req.Config), RootYears: int(cfgInt(req.Config, "root_years", 10))}, &out); err != nil {
			return undo(err)
		}
		fp, err := dockerExec(ctx, host, inst.ID, d.Target, "root-sha256")
		if err != nil {
			return undo(err)
		}
		if fp != out.RootSHA256 {
			return undo(errors.New("отпечаток корня по API не совпал с отпечатком в контейнере"))
		}
		job.Logf("Корень создан: SHA-256 %s", pki.FingerprintColon(fp))
		return nil
	})
}

func (p *caPlugin) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	host := sdk.HostFrom(ctx)
	st := sdk.Status{Endpoints: []sdk.Endpoint{}, ActionsEnabled: []string{}}
	cl, err := p.client(ctx, host, inst)
	if err != nil {
		st.State, st.Detail = sdk.StateUnknown, err.Error()
		return st, nil
	}
	var h health
	if err := cl.Do("GET", "/v1/health", nil, &h); err != nil {
		if errors.Is(err, caserver.ErrPin) {
			st.State, st.Detail = sdk.StateDegraded, "Ключ API CA изменился — переустановите экземпляр или проверьте сервер"
			return st, nil
		}
		st.State, st.Detail = sdk.StateDown, "CA не отвечает: "+err.Error()
		return st, nil
	}
	if h.State != caserver.StateReady {
		st.State, st.Detail = sdk.StateDegraded, "Ожидает восстановления из резервной копии"
		st.ActionsEnabled = []string{"restore"}
		return st, nil
	}
	st.ActionsEnabled = []string{"root", "backup"}
	var root caserver.RootInfo
	if err := cl.Do("GET", "/v1/root", nil, &root); err != nil {
		st.State, st.Detail = sdk.StateDegraded, "Корень не читается: "+err.Error()
		return st, nil
	}
	var active []caserver.Record
	if err := cl.Do("GET", "/v1/issued?active=1", nil, &active); err != nil {
		st.State, st.Detail = sdk.StateDegraded, "Журнал выпусков не читается: "+err.Error()
		return st, nil
	}
	st.State = sdk.StateOK
	st.Detail = fmt.Sprintf("Корень до %s, активных сертификатов: %d", root.NotAfter.Format("2006-01-02"), len(active))
	if root.NotAfter.Sub(p.now()) < 365*24*time.Hour {
		st.State = sdk.StateDegraded
		st.Detail += " — корню меньше года"
	}
	return st, nil
}

// backupFile remembers the date of the last backup of an instance.
func (p *caPlugin) backupFile(inst int64) string {
	return filepath.Join(p.StateDir, fmt.Sprintf("backup-%d", inst))
}

func (p *caPlugin) lastBackup(inst int64) string {
	if p.StateDir == "" {
		return ""
	}
	b, err := os.ReadFile(p.backupFile(inst))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
