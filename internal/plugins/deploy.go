package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// Docker compose deployment for plugins (deploy.*): a project lives in
// /opt/hestia/<instance>-<project>/ on a granted target and runs as the
// compose project hestia-<instance>-<project>.

// Limits and names of deploy.
const (
	DeployBase     = "/opt/hestia"
	composeFile    = "compose.yaml"
	filesList      = ".hestia-files"
	prevDir        = ".hestia-prev"
	maxCompose     = 256 << 10
	maxDeployFile  = 1 << 20
	maxDeployFiles = 32
)

// Default timeouts of deploy (Manager fields override them).
const (
	DeployWaitRunning = 60 * time.Second
	deployProbeT      = 20 * time.Second
	deployInstallT    = 15 * time.Minute
	deployUpT         = 15 * time.Minute
	deployDownT       = 5 * time.Minute
	deployFileT       = 2 * time.Minute
	deployCTT         = 3 * time.Minute
)

var (
	reProject    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	reDeployFile = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// NodeExec runs a script as root on the Proxmox node of an "lxc:" grant
// (used to change container features); SSHTargets implements it.
type NodeExec interface {
	ExecNode(ctx context.Context, ref, script string) (sshx.Result, error)
}

// LXCConfigAPI reads the configuration of a container (Proxmox API).
type LXCConfigAPI interface {
	LXCConfig(ctx context.Context, node string, vmid int) (map[string]string, error)
}

// defaultPVE builds an API client from the stored Proxmox target.
func (m *Manager) defaultPVE(ctx context.Context, t store.Target) (LXCConfigAPI, error) {
	if t.TokenSecretRef == 0 || t.APICertFP == "" {
		return nil, errors.New("у цели Proxmox нет токена API")
	}
	raw, err := m.Secrets.Get(ctx, t.TokenSecretRef)
	if err != nil {
		return nil, fmt.Errorf("токен API: %w", err)
	}
	return proxmox.NewClient(proxmox.ClientConfig{Host: t.Host, Port: m.PVEPort, TokenID: t.TokenID, Secret: string(raw), PinFP: t.APICertFP}), nil
}

// deploySpec is a validated deploy request.
type deploySpec struct {
	pluginID string
	instance int64
	ref      Ref
	refStr   string
	project  string // compose project name
	dir      string
	compose  *preparedCompose
	files    map[string][]byte // compose.yaml included
	names    []string          // sorted
}

func projectName(instance int64, project string) string {
	return fmt.Sprintf("hestia-%d-%s", instance, project)
}

func projectDir(instance int64, project string) string {
	return fmt.Sprintf("%s/%d-%s", DeployBase, instance, project)
}

func (m *Manager) newSpec(pid string, instance int64, refStr, project string) (*deploySpec, error) {
	if !reProject.MatchString(project) {
		return nil, badParams("project: строчные латинские буквы, цифры, _ и -, до 40 символов")
	}
	ref, err := ParseRef(refStr)
	if err != nil {
		return nil, badParams("%v", err)
	}
	return &deploySpec{pluginID: pid, instance: instance, ref: ref, refStr: refStr,
		project: projectName(instance, project), dir: projectDir(instance, project)}, nil
}

// withContent checks the compose file and the extra files.
func (sp *deploySpec) withContent(compose json.RawMessage, files []sdk.DeployFile) error {
	pc, err := prepareCompose(compose, sp.dir, sp.pluginID, sp.instance)
	if err != nil {
		return err
	}
	if len(files) > maxDeployFiles {
		return badParams("files: не больше %d файлов", maxDeployFiles)
	}
	sp.compose = pc
	sp.files = map[string][]byte{composeFile: pc.data}
	total := len(pc.data)
	for _, f := range files {
		switch {
		case !reDeployFile.MatchString(f.Name) || f.Name == "." || f.Name == "..":
			return badParams("files: неверное имя %q (латиница, цифры, . _ -, без /)", f.Name)
		case f.Name == composeFile || strings.HasPrefix(f.Name, ".hestia"):
			return badParams("files: имя %q зарезервировано", f.Name)
		case len(f.Data) > maxDeployFile:
			return badParams("files: %s больше 1 МБ", f.Name)
		}
		if _, dup := sp.files[f.Name]; dup {
			return badParams("files: %s указан дважды", f.Name)
		}
		sp.files[f.Name] = f.Data
		total += len(f.Data)
	}
	if total > 4<<20 {
		return badParams("files: всего больше 4 МБ")
	}
	for n := range sp.files {
		sp.names = append(sp.names, n)
	}
	sort.Strings(sp.names)
	return nil
}

// ---- RPC entry ----

func (m *Manager) deployCall(ctx context.Context, s *session, method string, params json.RawMessage) (any, error) {
	pid := s.id()
	switch method {
	case sdk.MethodDeployPlan, sdk.MethodDeployUp:
		var p sdk.DeployRequest
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры %s", method)
		}
		if err := m.checkGrant(ctx, s, sdk.PermDeployDocker, p.Instance, p.Target); err != nil {
			return nil, err
		}
		var a *applyJob
		if method == sdk.MethodDeployUp {
			var err error
			if a, err = m.applyFor(pid, p.JobID, p.Instance); err != nil {
				return nil, err
			}
		}
		sp, err := m.newSpec(pid, p.Instance, p.Target, p.Project)
		if err != nil {
			return nil, err
		}
		if err := sp.withContent(p.Compose, p.Files); err != nil {
			return nil, err
		}
		if a == nil {
			pl, _, err := m.deployPlan(ctx, sp)
			return pl, err
		}
		return m.deployUp(ctx, a, sp)
	case sdk.MethodDeployDown:
		var p sdk.DeployDownRequest
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры %s", method)
		}
		if err := m.checkGrant(ctx, s, sdk.PermDeployDocker, p.Instance, p.Target); err != nil {
			return nil, err
		}
		a, err := m.applyFor(pid, p.JobID, p.Instance)
		if err != nil {
			return nil, err
		}
		sp, err := m.newSpec(pid, p.Instance, p.Target, p.Project)
		if err != nil {
			return nil, err
		}
		return struct{}{}, m.deployDown(ctx, a, sp, p.Volumes)
	case sdk.MethodDeployStatus:
		var p sdk.DeployStatusRequest
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, badParams("неверные параметры %s", method)
		}
		if err := m.checkGrant(ctx, s, sdk.PermDeployDocker, p.Instance, p.Target); err != nil {
			return nil, err
		}
		sp, err := m.newSpec(pid, p.Instance, p.Target, p.Project)
		if err != nil {
			return nil, err
		}
		return m.deployStatus(ctx, sp)
	}
	return nil, badParams("метод %s не поддерживается", method)
}

// applyFor finds the running apply job of this plugin and instance.
func (m *Manager) applyFor(pid, jobID string, iid int64) (*applyJob, error) {
	m.mu.Lock()
	a := m.applying[jobID]
	m.mu.Unlock()
	if a == nil || a.pluginID != pid || a.instanceID != iid {
		return nil, denied(fmt.Sprintf("задача %q не выполняется для экземпляра %d", jobID, iid),
			map[string]any{"job_id": jobID, "instance": iid})
	}
	return a, nil
}

// ---- running commands ----

// texec runs a script on the target with its own timeout. A non-zero exit
// code is an error carrying the tail of the output.
func (m *Manager) texec(ctx context.Context, ref, script string, stdin []byte, timeout time.Duration) (sshx.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := m.Targets.Exec(ctx, ref, script, stdin)
	var ee *sshx.ExitError
	if errors.As(err, &ee) {
		out := strings.TrimSpace(ee.Result.Stderr)
		if out == "" {
			out = strings.TrimSpace(ee.Result.Stdout)
		}
		return ee.Result, fmt.Errorf("код %d: %s", ee.Result.ExitCode, tailLines(out, 8))
	}
	if err != nil && ctx.Err() != nil {
		return res, fmt.Errorf("цель не ответила за %s", timeout)
	}
	return res, err
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return truncate(strings.Join(lines, "\n"), 2000)
}

// ---- probe ----

type fileState struct {
	size int64
	sha  string
}

// probe is what deploy needs to know about the target.
type probe struct {
	osID, osLike, osName string
	apt                  bool
	docker               bool
	compose              string // version of `docker compose` v2 ("" if missing)
	dirExists            bool
	managed              bool // the list of Hestia's files is there
	files                map[string]fileState
	listen               map[int]bool
	ps                   []sdk.DeployContainer
	lxc                  *lxcState
}

type lxcState struct {
	vmid         int
	unprivileged bool
	features     string // current value
	want         string // value with nesting/keyctl ("" if nothing to change)
}

func (p *probe) debianLike() bool {
	return p.apt && (p.osID == "debian" || p.osID == "ubuntu" || strings.Contains(p.osLike, "debian") || strings.Contains(p.osLike, "ubuntu"))
}

func (p *probe) ubuntu() bool { return p.osID == "ubuntu" || strings.Contains(p.osLike, "ubuntu") }

func (p *probe) composePkg() string {
	if p.ubuntu() {
		return "docker-compose-v2"
	}
	return "docker-compose"
}

func (p *probe) installPkgs() string {
	if p.docker {
		return p.composePkg()
	}
	return "docker.io " + p.composePkg()
}

// safeName is a shell snippet for loops over names read from the target
// (.hestia-files may be changed by a container that mounts the project):
// anything but a plain file name is skipped. Globbing is off (set -f).
const safeName = `case "$f" in ""|.|..|*/*|*[!A-Za-z0-9._-]*) continue;; esac;`

func probeScript(dir, project string) string {
	return fmt.Sprintf(`set -f; P=%s; N=%s; v=
if [ -r /etc/os-release ]; then . /etc/os-release; fi
echo "os_id=${ID:-}"; echo "os_like=${ID_LIKE:-}"; echo "os_name=${PRETTY_NAME:-}"
command -v apt-get >/dev/null 2>&1 && echo apt=1
if command -v docker >/dev/null 2>&1; then echo docker=1; v=$(docker compose version --short 2>/dev/null) && echo "compose=$v"; fi
if [ -d "$P" ]; then echo dir=1; fi
if [ -f "$P/%s" ]; then echo managed=1; for f in $(cat "$P/%s"); do `+safeName+` if [ -f "$P/$f" ] && [ ! -L "$P/$f" ]; then echo "file $f $(wc -c < "$P/$f") $(sha256sum < "$P/$f" | cut -c1-64)"; fi; done; fi
echo ---ss
ss -ltnH 2>/dev/null || true
echo ---ps
if [ -n "$v" ]; then docker compose -p "$N" ps -a --format json 2>/dev/null || true; fi
`, target.Quote(dir), target.Quote(project), filesList, filesList)
}

func (m *Manager) probe(ctx context.Context, sp *deploySpec) (*probe, error) {
	res, err := m.texec(ctx, sp.refStr, probeScript(sp.dir, sp.project), nil, m.DeployProbeTimeout)
	if err != nil {
		return nil, fmt.Errorf("проверка цели: %w", err)
	}
	p := parseProbe(res.Stdout)
	if sp.ref.Kind == "lxc" {
		if p.lxc, err = m.lxcFeatures(ctx, sp.ref); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func parseProbe(out string) *probe {
	p := &probe{files: map[string]fileState{}, listen: map[int]bool{}}
	section := ""
	var ps strings.Builder
	for _, line := range strings.Split(out, "\n") {
		switch line {
		case "---ss", "---ps":
			section = line
			continue
		}
		switch section {
		case "---ss":
			if port := listenPort(line); port > 0 {
				p.listen[port] = true
			}
			continue
		case "---ps":
			ps.WriteString(line + "\n")
			continue
		}
		if rest, ok := strings.CutPrefix(line, "file "); ok {
			f := strings.Fields(rest)
			if len(f) == 3 && reDeployFile.MatchString(f[0]) && f[0] != "." && f[0] != ".." {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				p.files[f[0]] = fileState{size: n, sha: f[2]}
			}
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "os_id":
			p.osID = strings.ToLower(v)
		case "os_like":
			p.osLike = strings.ToLower(v)
		case "os_name":
			p.osName = v
		case "apt":
			p.apt = true
		case "docker":
			p.docker = true
		case "compose":
			if strings.HasPrefix(strings.TrimPrefix(v, "v"), "2.") || strings.HasPrefix(strings.TrimPrefix(v, "v"), "5.") {
				p.compose = v
			} else if major, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), "."); major != "" && major != "1" {
				p.compose = v
			}
		case "dir":
			p.dirExists = true
		case "managed":
			p.managed = true
		}
	}
	p.ps = parsePS(ps.String())
	return p
}

// listenPort takes the port of the local address of a `ss -ltnH` line
// ("LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*").
func listenPort(line string) int {
	f := strings.Fields(line)
	if len(f) < 4 {
		return 0
	}
	addr := f[3]
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return 0
	}
	return n
}

// parsePS reads `docker compose ps --format json`: a JSON array (older
// compose) or one object per line.
func parsePS(out string) []sdk.DeployContainer {
	type pub struct {
		URL           string `json:"URL"`
		TargetPort    int    `json:"TargetPort"`
		PublishedPort int    `json:"PublishedPort"`
		Protocol      string `json:"Protocol"`
	}
	type row struct {
		Name       string `json:"Name"`
		Service    string `json:"Service"`
		State      string `json:"State"`
		Status     string `json:"Status"`
		Health     string `json:"Health"`
		ExitCode   int    `json:"ExitCode"`
		Publishers []pub  `json:"Publishers"`
	}
	var rows []row
	out = strings.TrimSpace(out)
	if strings.HasPrefix(out, "[") {
		_ = json.Unmarshal([]byte(out), &rows)
	} else {
		for _, l := range strings.Split(out, "\n") {
			var r row
			if json.Unmarshal([]byte(strings.TrimSpace(l)), &r) == nil && r.Name != "" {
				rows = append(rows, r)
			}
		}
	}
	cs := []sdk.DeployContainer{}
	for _, r := range rows {
		c := sdk.DeployContainer{Name: r.Name, Service: r.Service, State: r.State, Status: r.Status, Health: r.Health,
			ExitCode: r.ExitCode, Ports: []sdk.DeployPort{}}
		for _, p := range r.Publishers {
			if p.PublishedPort == 0 {
				continue
			}
			c.Ports = append(c.Ports, sdk.DeployPort{URL: p.URL, TargetPort: p.TargetPort, PublishedPort: p.PublishedPort, Protocol: p.Protocol})
		}
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	return cs
}

// ---- LXC features ----

// lxcFeatures reads the container's config through the Proxmox API and
// says whether nesting (and keyctl for an unprivileged one) must be
// switched on.
func (m *Manager) lxcFeatures(ctx context.Context, ref Ref) (*lxcState, error) {
	t, err := m.Store.GetTarget(ctx, ref.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("цель больше не подключена к Hestia")
	}
	if err != nil {
		return nil, err
	}
	api, err := m.PVE(ctx, t)
	if err != nil {
		return nil, err
	}
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cfg, err := api.LXCConfig(actx, ref.Node, ref.VMID)
	if err != nil {
		return nil, fmt.Errorf("конфигурация CT %d через API Proxmox: %w", ref.VMID, err)
	}
	st := &lxcState{vmid: ref.VMID, unprivileged: cfg["unprivileged"] == "1", features: cfg["features"]}
	need := map[string]string{"nesting": "1"}
	if st.unprivileged {
		need["keyctl"] = "1"
	}
	st.want = mergeFeatures(st.features, need)
	if st.want == st.features {
		st.want = ""
	}
	return st, nil
}

// mergeFeatures sets keys of a Proxmox "features" value ("nesting=1,fuse=1")
// keeping the others in order; it returns cur unchanged if nothing differs.
func mergeFeatures(cur string, set map[string]string) string {
	var parts []string
	seen := map[string]bool{}
	changed := false
	for _, kv := range strings.Split(cur, ",") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		if want, ok := set[k]; ok {
			seen[k] = true
			if v != want {
				changed = true
				kv = k + "=" + want
			}
		}
		parts = append(parts, kv)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !seen[k] {
			parts = append(parts, k+"="+set[k])
			changed = true
		}
	}
	if !changed {
		return cur
	}
	return strings.Join(parts, ",")
}

// ---- plan ----

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sizeText(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d Б", n)
	}
	return fmt.Sprintf("%.1f КБ", float64(n)/1024)
}

// deployPlan probes the target and describes what deploy.up would do.
func (m *Manager) deployPlan(ctx context.Context, sp *deploySpec) (sdk.DeployPlan, *probe, error) {
	p, err := m.probe(ctx, sp)
	if err != nil {
		return sdk.DeployPlan{}, nil, err
	}
	pl, err := planFrom(sp, p)
	return pl, p, err
}

func planFrom(sp *deploySpec, p *probe) (sdk.DeployPlan, error) {
	pl := sdk.DeployPlan{Project: sp.project, Dir: sp.dir, Exists: p.dirExists, Files: []sdk.DeployFileChange{},
		Actions: []sdk.Action{}, Warnings: []string{}}
	if p.lxc != nil && p.lxc.want != "" {
		pl.EnableFeatures = true
		what := "nesting"
		if p.lxc.unprivileged {
			what = "nesting и keyctl"
		}
		pl.Actions = append(pl.Actions, sdk.Action{
			Title:  fmt.Sprintf("Включить %s для CT %d (Proxmox, нужен перезапуск контейнера)", what, p.lxc.vmid),
			Detail: fmt.Sprintf("features: «%s» → «%s»; без этого Docker в контейнере не работает. Контейнер перезапустится, его сервисы ненадолго остановятся.", p.lxc.features, p.lxc.want),
			Risk:   sdk.RiskDanger,
		})
	}
	if !p.docker || p.compose == "" {
		if !p.debianLike() {
			osName := p.osName
			if osName == "" {
				osName = "неизвестна"
			}
			return pl, badParams("На цели нет Docker с docker compose v2, а ОС цели (%s) — не Debian/Ubuntu. Поставьте Docker вручную, например: curl -fsSL https://get.docker.com | sh — и составьте план ещё раз.", osName)
		}
		pl.InstallDocker = true
		title := "Установить Docker: apt-get install -y " + p.installPkgs()
		if p.docker {
			title = "Установить docker compose v2: apt-get install -y " + p.installPkgs()
		}
		pl.Actions = append(pl.Actions, sdk.Action{Title: title, Detail: "Debian/Ubuntu, пакеты дистрибутива", Risk: sdk.RiskChange})
	}

	var details []string
	for _, n := range sp.names {
		data := sp.files[n]
		fc := sdk.DeployFileChange{Name: n, Size: int64(len(data))}
		old, ok := p.files[n]
		switch {
		case !ok:
			fc.Action = sdk.FileCreate
			details = append(details, fmt.Sprintf("%s: новый, %s", n, sizeText(fc.Size)))
		case old.sha != sha(data):
			fc.Action, fc.OldSize = sdk.FileUpdate, old.size
			details = append(details, fmt.Sprintf("%s: изменится, %s → %s", n, sizeText(old.size), sizeText(fc.Size)))
		default:
			fc.Action, fc.OldSize = sdk.FileUnchanged, old.size
		}
		pl.Files = append(pl.Files, fc)
	}
	var stale []string
	for n, st := range p.files {
		if _, ok := sp.files[n]; !ok {
			stale = append(stale, n)
			pl.Files = append(pl.Files, sdk.DeployFileChange{Name: n, Action: sdk.FileRemove, OldSize: st.size})
		}
	}
	sort.Strings(stale)
	for _, n := range stale {
		details = append(details, n+": будет удалён")
	}
	sort.Slice(pl.Files, func(i, j int) bool { return pl.Files[i].Name < pl.Files[j].Name })
	pl.Changed = len(details) > 0
	switch {
	case !p.managed:
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Создать проект %s в %s", sp.project, sp.dir),
			Detail: strings.Join(details, "; "), Risk: sdk.RiskChange})
	case pl.Changed:
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Изменить файлы проекта %s", sp.project),
			Detail: strings.Join(details, "; "), Risk: sdk.RiskChange})
	default:
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Файлы проекта %s без изменений", sp.project), Risk: sdk.RiskInfo})
	}
	pl.Actions = append(pl.Actions, sdk.Action{
		Title:  fmt.Sprintf("Запустить: docker compose -p %s up -d --remove-orphans", sp.project),
		Detail: "сервисы: " + strings.Join(sp.compose.services, ", "),
		Risk:   sdk.RiskChange,
	})

	own := map[int]bool{}
	for _, c := range p.ps {
		for _, port := range c.Ports {
			own[port.PublishedPort] = true
		}
	}
	for _, port := range sp.compose.ports {
		if p.listen[port] && !own[port] {
			pl.Warnings = append(pl.Warnings, fmt.Sprintf("Порт %d на цели уже занят другой программой: контейнер не сможет его опубликовать.", port))
		}
	}
	return pl, nil
}

// ---- up ----

func (m *Manager) logJob(a *applyJob, level, line string) {
	a.run.Log(level, truncate(a.mask(line), maxLogLine))
}

func (m *Manager) logOutput(a *applyJob, out string) {
	for _, l := range strings.Split(tailLines(out, 30), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			m.logJob(a, "info", l)
		}
	}
}

// jobStep runs fn as a step of the apply job.
func (m *Manager) jobStep(a *applyJob, title string, fn func() error) error {
	a.step(title)
	err := fn()
	if err != nil {
		err = errors.New(truncate(a.mask(err.Error()), 2000))
	}
	a.stepDone(err)
	return err
}

func (m *Manager) composeCmd(sp *deploySpec, args string) string {
	return fmt.Sprintf("cd %s && docker compose -p %s -f %s %s", target.Quote(sp.dir), target.Quote(sp.project), composeFile, args)
}

func (m *Manager) deployUp(ctx context.Context, a *applyJob, sp *deploySpec) (sdk.DeployStatus, error) {
	var (
		p   *probe
		pl  sdk.DeployPlan
		err error
	)
	if err = m.jobStep(a, "Проверка цели "+sp.refStr, func() error {
		pl, p, err = m.deployPlan(ctx, sp)
		return err
	}); err != nil {
		return sdk.DeployStatus{}, err
	}
	if pl.EnableFeatures {
		if !a.confirmed {
			err := errors.New("включение nesting/keyctl контейнера не подтверждено: это действие должно быть в плане экземпляра и подтверждено галкой")
			_ = m.jobStep(a, "Включение nesting/keyctl", func() error { return err })
			return sdk.DeployStatus{}, err
		}
		if err := m.jobStep(a, fmt.Sprintf("Включение %s для CT %d и перезапуск", p.lxc.want, p.lxc.vmid), func() error {
			return m.enableFeatures(ctx, a, sp, p.lxc)
		}); err != nil {
			return sdk.DeployStatus{}, err
		}
	}
	if pl.InstallDocker {
		if err := m.jobStep(a, "Установка Docker ("+p.installPkgs()+")", func() error {
			return m.installDocker(ctx, a, sp, p)
		}); err != nil {
			if pl.EnableFeatures {
				m.logJob(a, "warn", "nesting/keyctl контейнера остаются включёнными")
			}
			return sdk.DeployStatus{}, err
		}
	}

	backedUp := p.managed
	touched := false
	fail := func(err error) (sdk.DeployStatus, error) {
		if touched {
			rb := m.jobStep(a, "Откат проекта "+sp.project, func() error { return m.rollback(ctx, a, sp, backedUp) })
			if rb != nil {
				m.logJob(a, "error", "Откат не удался: "+rb.Error())
			}
		}
		var left []string
		if pl.InstallDocker {
			left = append(left, "Docker")
		}
		if pl.EnableFeatures {
			left = append(left, "nesting/keyctl контейнера")
		}
		if len(left) > 0 {
			m.logJob(a, "warn", "Остаются на цели: "+strings.Join(left, ", "))
		}
		return sdk.DeployStatus{}, err
	}

	if err := m.jobStep(a, "Запись файлов в "+sp.dir, func() error {
		touched = true
		return m.writeFiles(ctx, a, sp, p)
	}); err != nil {
		return fail(err)
	}
	if err := m.jobStep(a, "docker compose up -d", func() error {
		res, err := m.texec(ctx, sp.refStr, m.composeCmd(sp, "up -d --remove-orphans 2>&1"), nil, m.DeployUpTimeout)
		m.logOutput(a, res.Stdout)
		return err
	}); err != nil {
		return fail(err)
	}
	var st sdk.DeployStatus
	if err := m.jobStep(a, "Ожидание запуска контейнеров", func() error {
		st, err = m.waitRunning(ctx, a, sp)
		return err
	}); err != nil {
		return fail(err)
	}
	if backedUp {
		_, _ = m.texec(ctx, sp.refStr, "rm -rf "+target.Quote(sp.dir+"/"+prevDir), nil, deployFileT)
	}
	return st, nil
}

func (m *Manager) enableFeatures(ctx context.Context, a *applyJob, sp *deploySpec, l *lxcState) error {
	ne, ok := m.Targets.(NodeExec)
	if !ok {
		return errors.New("изменение features контейнера недоступно")
	}
	v := strconv.Itoa(l.vmid)
	script := fmt.Sprintf("pct set %s --features %s && pct reboot %s", v, target.Quote(l.want), v)
	m.logJob(a, "info", "узел: "+script)
	cctx, cancel := context.WithTimeout(ctx, m.DeployCTTimeout)
	defer cancel()
	if res, err := ne.ExecNode(cctx, sp.refStr, script); err != nil {
		var ee *sshx.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("pct: код %d: %s", ee.Result.ExitCode, tailLines(ee.Result.Stderr, 8))
		}
		return err
	} else {
		m.logOutput(a, res.Stdout)
	}
	m.logJob(a, "info", "Ждём, пока контейнер ответит")
	for {
		ectx, ecancel := context.WithTimeout(cctx, 15*time.Second)
		_, err := m.Targets.Exec(ectx, sp.refStr, "true", nil)
		ecancel()
		if err == nil {
			return nil
		}
		select {
		case <-cctx.Done():
			return fmt.Errorf("CT %d не ответил после перезапуска за %s", l.vmid, m.DeployCTTimeout)
		case <-time.After(m.DeployPoll):
		}
	}
}

func (m *Manager) installDocker(ctx context.Context, a *applyJob, sp *deploySpec, p *probe) error {
	script := fmt.Sprintf(`export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -y -q %s || exit 1
systemctl enable --now docker.service >/dev/null 2>&1 || true
docker compose version --short`, p.installPkgs())
	res, err := m.texec(ctx, sp.refStr, script, nil, m.DeployInstallTimeout)
	m.logOutput(a, res.Stdout)
	if err != nil {
		return fmt.Errorf("установка Docker: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	ver := strings.TrimSpace(lines[len(lines)-1])
	if ver == "" || strings.HasPrefix(strings.TrimPrefix(ver, "v"), "1.") {
		return errors.New("после установки нет docker compose v2 (в Debian 12 пакет docker-compose — версии 1). Поставьте Docker по инструкции https://docs.docker.com/engine/install/ и повторите")
	}
	m.logJob(a, "info", "docker compose "+ver)
	return nil
}

// writeFiles backs up the current files of the project (if Hestia manages
// it), writes the new ones, removes stale ones and records the list.
func (m *Manager) writeFiles(ctx context.Context, a *applyJob, sp *deploySpec, p *probe) error {
	d := target.Quote(sp.dir)
	if p.managed {
		backup := fmt.Sprintf(`set -f; cd %s && rm -rf %s && mkdir -m 0700 %s && cp -p %s %s/ && for f in $(cat %s); do `+safeName+` if [ -f "$f" ] && [ ! -L "$f" ]; then cp -p "$f" %s/; fi; done`,
			d, prevDir, prevDir, filesList, prevDir, filesList, prevDir)
		if _, err := m.texec(ctx, sp.refStr, backup, nil, deployFileT); err != nil {
			return fmt.Errorf("резервная копия файлов: %w", err)
		}
	}
	for _, n := range sp.names {
		data := sp.files[n]
		if old, ok := p.files[n]; ok && old.sha == sha(data) {
			continue
		}
		tmp := target.Quote(sp.dir + "/." + n + ".hestia-new")
		dst := target.Quote(sp.dir + "/" + n)
		// noclobber: the temporary file is created anew (never through a
		// link a container could have planted); mv replaces a link itself.
		script := fmt.Sprintf("umask 027 && mkdir -p %s && chmod 0750 %s && rm -f %s && (set -C; cat > %s) && chmod 0640 %s && mv -f %s %s", d, d, tmp, tmp, tmp, tmp, dst)
		if _, err := m.texec(ctx, sp.refStr, script, data, deployFileT); err != nil {
			return fmt.Errorf("запись %s: %w", n, err)
		}
		m.logJob(a, "info", fmt.Sprintf("%s/%s (%s)", sp.dir, n, sizeText(int64(len(data)))))
	}
	var stale []string
	for n := range p.files {
		if _, ok := sp.files[n]; !ok {
			stale = append(stale, target.Quote(sp.dir+"/"+n))
		}
	}
	sort.Strings(stale)
	script := ""
	if len(stale) > 0 {
		script = "rm -f " + strings.Join(stale, " ") + " && "
	}
	list := strings.Join(sp.names, "\n") + "\n"
	lt := target.Quote(sp.dir + "/" + filesList + ".hestia-new")
	script += fmt.Sprintf("umask 027 && mkdir -p %s && rm -f %s && (set -C; cat > %s) && mv -f %s %s/%s", d, lt, lt, lt, d, filesList)
	if _, err := m.texec(ctx, sp.refStr, script, []byte(list), deployFileT); err != nil {
		return fmt.Errorf("список файлов проекта: %w", err)
	}
	return nil
}

// rollback returns the previous files and restarts the project, or removes
// a new project. It runs even when the job is cancelled.
func (m *Manager) rollback(ctx context.Context, a *applyJob, sp *deploySpec, backedUp bool) error {
	ctx = context.WithoutCancel(ctx)
	d := target.Quote(sp.dir)
	if !backedUp {
		m.logJob(a, "info", "Проект новый: docker compose down и удаление "+sp.dir)
		res, err := m.texec(ctx, sp.refStr, m.composeCmd(sp, "down -v --remove-orphans 2>&1"), nil, m.DeployDownTimeout)
		m.logOutput(a, res.Stdout)
		if _, rerr := m.texec(ctx, sp.refStr, "rm -rf "+d, nil, deployFileT); err == nil {
			err = rerr
		}
		return err
	}
	m.logJob(a, "info", "Возвращаем прежние файлы и запускаем прежнюю версию")
	restore := fmt.Sprintf(`set -f; cd %s && for f in $(cat %s); do `+safeName+` rm -f "$f"; done && for f in $(cat %s/%s); do `+safeName+` if [ -f %s/"$f" ]; then cp -p %s/"$f" "$f"; fi; done && cp -p %s/%s %s && rm -rf %s`,
		d, filesList, prevDir, filesList, prevDir, prevDir, prevDir, filesList, filesList, prevDir)
	if _, err := m.texec(ctx, sp.refStr, restore, nil, deployFileT); err != nil {
		return fmt.Errorf("возврат файлов: %w", err)
	}
	res, err := m.texec(ctx, sp.refStr, m.composeCmd(sp, "up -d --remove-orphans 2>&1"), nil, m.DeployUpTimeout)
	m.logOutput(a, res.Stdout)
	return err
}

// psCmd lists the containers of the project (by name: it works without the
// directory too).
func psCmd(sp *deploySpec) string {
	return fmt.Sprintf("docker compose -p %s ps -a --format json", target.Quote(sp.project))
}

// waitRunning polls `docker compose ps` until every service runs.
func (m *Manager) waitRunning(ctx context.Context, a *applyJob, sp *deploySpec) (sdk.DeployStatus, error) {
	wctx, cancel := context.WithTimeout(ctx, m.DeployWaitRunning)
	defer cancel()
	st := sdk.DeployStatus{Project: sp.project, Docker: true, Exists: true}
	for {
		res, err := m.texec(wctx, sp.refStr, psCmd(sp), nil, deployProbeT)
		if err == nil {
			st.Containers = parsePS(res.Stdout)
			if allRunning(st.Containers, sp.compose.services) {
				for _, c := range st.Containers {
					m.logJob(a, "info", fmt.Sprintf("%s: %s", c.Name, c.Status))
				}
				return st, nil
			}
		}
		select {
		case <-wctx.Done():
			var states []string
			for _, c := range st.Containers {
				states = append(states, fmt.Sprintf("%s: %s %s", c.Service, c.State, c.Status))
			}
			if len(states) == 0 {
				states = []string{"контейнеров нет"}
			}
			return st, fmt.Errorf("контейнеры не запустились за %s (%s)", m.DeployWaitRunning, strings.Join(states, "; "))
		case <-time.After(m.DeployPoll):
		}
	}
}

func allRunning(cs []sdk.DeployContainer, services []string) bool {
	if !(sdk.DeployStatus{Containers: cs}).Running() {
		return false
	}
	for _, s := range services {
		found := false
		for _, c := range cs {
			if c.Service == s {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ---- down and status ----

func (m *Manager) deployDown(ctx context.Context, a *applyJob, sp *deploySpec, volumes bool) error {
	flags := "--remove-orphans"
	if volumes {
		flags = "-v " + flags
	}
	d := target.Quote(sp.dir)
	if err := m.jobStep(a, "docker compose down ("+sp.project+")", func() error {
		script := fmt.Sprintf(`if ! command -v docker >/dev/null 2>&1; then echo "Docker на цели нет — останавливать нечего"; exit 0; fi
if [ -f %s/%s ]; then cd %s && docker compose -p %s -f %s down %s 2>&1; else docker compose -p %s down %s 2>&1; fi`,
			d, composeFile, d, target.Quote(sp.project), composeFile, flags, target.Quote(sp.project), flags)
		res, err := m.texec(ctx, sp.refStr, script, nil, m.DeployDownTimeout)
		m.logOutput(a, res.Stdout)
		return err
	}); err != nil {
		return err
	}
	return m.jobStep(a, "Удаление "+sp.dir, func() error {
		_, err := m.texec(ctx, sp.refStr, "rm -rf "+d, nil, deployFileT)
		return err
	})
}

func (m *Manager) deployStatus(ctx context.Context, sp *deploySpec) (sdk.DeployStatus, error) {
	script := fmt.Sprintf(`if [ -d %s ]; then echo dir=1; fi
if command -v docker >/dev/null 2>&1; then echo docker=1; echo ---ps; %s 2>/dev/null || true; fi`, target.Quote(sp.dir), psCmd(sp))
	res, err := m.texec(ctx, sp.refStr, script, nil, deployProbeT)
	if err != nil {
		return sdk.DeployStatus{}, rpc.Errorf(rpc.CodeInternal, "цель %s: %v", sp.refStr, err)
	}
	st := sdk.DeployStatus{Project: sp.project, Containers: []sdk.DeployContainer{}}
	head, ps, _ := strings.Cut(res.Stdout, "---ps\n")
	st.Exists = strings.Contains(head, "dir=1")
	st.Docker = strings.Contains(head, "docker=1")
	st.Containers = parsePS(ps)
	return st, nil
}
