package onboard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
)

// ProbeRequest is the body of POST /targets/probe. Password, PrivateKey and
// Passphrase are used for the probe session only.
type ProbeRequest struct {
	Kind       string `json:"kind"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Auth       string `json:"auth"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase"`
}

// PlanItem is one change the plan will make.
type PlanItem struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// ProbeResult is the answer of a probe.
type ProbeResult struct {
	ProbeID       string        `json:"probe_id"`
	Kind          string        `json:"kind"`
	Host          string        `json:"host"`
	Port          int           `json:"port"`
	Username      string        `json:"username"`
	HostKeyFP     string        `json:"host_key_fp"`
	APICertFP     string        `json:"api_cert_fp"`
	Version       string        `json:"version"`
	Cluster       string        `json:"cluster"`
	Nodes         []store.Node  `json:"nodes"`
	Facts         *target.Facts `json:"facts"`
	Warnings      []string      `json:"warnings"`
	Plan          []PlanItem    `json:"plan"`
	SuggestedName string        `json:"suggested_name"`
	ExpiresAt     time.Time     `json:"expires_at"`
}

var (
	hostRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
	userRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
)

// validate normalizes the request and builds the SSH config.
func (r *ProbeRequest) validate() (sshx.Config, *Error) {
	bad := func(m string) (sshx.Config, *Error) { return sshx.Config{}, newErr(400, m, nil) }
	r.Host = strings.TrimSpace(strings.Trim(strings.TrimSpace(r.Host), "[]"))
	if r.Kind != store.KindProxmox && r.Kind != store.KindSSH {
		return bad("неизвестный тип цели")
	}
	if r.Host == "" {
		return bad("укажите адрес сервера")
	}
	if !hostRe.MatchString(r.Host) {
		return bad("адрес сервера содержит недопустимые символы")
	}
	if r.Port == 0 {
		r.Port = 22
	}
	if r.Port < 1 || r.Port > 65535 {
		return bad("порт должен быть от 1 до 65535")
	}
	r.Username = strings.TrimSpace(r.Username)
	if r.Username == "" {
		r.Username = "root"
	}
	if !userRe.MatchString(r.Username) {
		return bad("недопустимое имя пользователя")
	}
	if r.Kind == store.KindProxmox && r.Username != "root" {
		return bad("для Proxmox нужен пользователь root")
	}
	cfg := sshx.Config{Host: r.Host, Port: r.Port, User: r.Username}
	switch r.Auth {
	case "password":
		if r.Password == "" {
			return bad("введите пароль")
		}
		cfg.Password = r.Password
	case "key":
		if strings.TrimSpace(r.PrivateKey) == "" {
			return bad("вставьте приватный ключ")
		}
		sg, err := sshx.ParseKey([]byte(r.PrivateKey), r.Passphrase)
		if err != nil {
			return bad(err.Error())
		}
		cfg.Signer = sg
	default:
		return bad("способ входа: пароль или ключ")
	}
	return cfg, nil
}

// Probe checks access and gathers facts without changing anything on the
// target. On success it opens a probe session holding the credentials.
func (s *Service) Probe(ctx context.Context, req ProbeRequest) (*ProbeResult, error) {
	cfg, verr := req.validate()
	if verr != nil {
		return nil, verr
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cl, err := s.Dial(ctx, cfg)
	if err != nil {
		return nil, probeErr(err)
	}
	defer cl.Close()
	tg := target.NewSSH(cl)

	res := &ProbeResult{
		Kind: req.Kind, Host: req.Host, Port: req.Port, Username: req.Username,
		HostKeyFP: cl.HostKeyFP(), Nodes: []store.Node{}, Warnings: []string{}, Plan: []PlanItem{},
	}
	keyPath, keyPresent := s.keyState(ctx, tg)

	switch req.Kind {
	case store.KindProxmox:
		st, err := proxmox.Inspect(ctx, tg)
		if err != nil {
			return nil, probeErr(err)
		}
		fp, err := s.FetchCertFP(ctx, req.Host, s.APIPort)
		if err != nil {
			return nil, newErr(422, err.Error(), err)
		}
		res.APICertFP = fp
		res.Version, res.Cluster = st.Version, st.Cluster
		for _, n := range st.Nodes {
			res.Nodes = append(res.Nodes, store.Node{Name: n.Name, IP: n.IP, Online: n.Online, HostKeyFP: n.HostKeyFP, HostKeyType: n.HostKeyType})
			if !n.Online {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Узел %s не в сети — Hestia проверит только узлы в сети.", n.Name))
			}
		}
		res.Warnings = append(res.Warnings, s.nodeKeyWarnings(ctx, cfg, cl.HostKeyFP(), st)...)
		res.SuggestedName = res.Cluster
		if res.SuggestedName == "" {
			res.SuggestedName = st.LocalNode
		}
		res.Plan = proxmoxPlan(st, keyPath, keyPresent)
	case store.KindSSH:
		facts, err := tg.Facts(ctx)
		if err != nil {
			return nil, probeErr(err)
		}
		res.Facts = &facts
		res.SuggestedName = facts.Hostname
		if res.SuggestedName == "" {
			res.SuggestedName = req.Host
		}
		if !facts.IsRoot() && !facts.Sudo {
			res.Warnings = append(res.Warnings, "Вход не от root и нет sudo без пароля — часть функций (установка, управление службами) будет недоступна.")
		}
		res.Plan = sshPlan(keyPath, keyPresent)
	}
	s.putSession(res, cfg)
	return res, nil
}

// nodeKeyWarnings reports problems with the cluster's SSH host keys: online
// nodes without a key in the cluster files (Hestia will refuse to log in to
// them) and a primary node whose cluster key does not match what it showed.
func (s *Service) nodeKeyWarnings(ctx context.Context, cfg sshx.Config, presentedFP string, st proxmox.State) []string {
	var w []string
	if len(st.Nodes) < 2 {
		return w
	}
	for _, n := range st.Nodes {
		switch {
		case n.Name == st.LocalNode && n.HostKeyFP != "":
			if n.HostKeyFP != presentedFP && !s.primaryKeyMatches(ctx, cfg, n) {
				w = append(w, fmt.Sprintf("SSH-ключ узла %s в файлах кластера не совпадает с ключом, который показал сервер, — проверьте, что подключаетесь к нужному серверу.", n.Name))
			}
		case n.HostKeyFP == "" && n.Online:
			w = append(w, fmt.Sprintf("Для узла %s нет SSH-ключа в файлах кластера (/etc/pve/nodes/%s/ssh_known_hosts) — Hestia не сможет безопасно войти на него, подключение остановится на проверке доступа.", n.Name, n.Name))
		}
	}
	return w
}

// primaryKeyMatches asks the primary node for the key type the cluster
// recorded (the default one may be another type) and compares fingerprints.
func (s *Service) primaryKeyMatches(ctx context.Context, cfg sshx.Config, n proxmox.Node) bool {
	cfg.ExpectedFP = n.HostKeyFP
	cfg.HostKeyAlgorithms = sshx.AlgorithmsForKeyType(n.HostKeyType)
	cl, err := s.Dial(ctx, cfg)
	if err != nil {
		return false
	}
	_ = cl.Close()
	return true
}

// keyState finds authorized_keys and whether Hestia's key is already in it.
func (s *Service) keyState(ctx context.Context, tg target.Target) (path string, present bool) {
	path, err := target.AuthorizedKeysPath(ctx, tg)
	if err != nil {
		return "", false
	}
	b, err := tg.Get(ctx, path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return path, false
	}
	return path, target.HasAuthorizedKey(string(b), s.Identity.AuthorizedKey)
}

func probeErr(err error) *Error {
	var hk *sshx.HostKeyChangedError
	switch {
	case errors.As(err, &hk), errors.Is(err, sshx.ErrAuth), errors.Is(err, sshx.ErrTimeout),
		errors.Is(err, sshx.ErrResolve), errors.Is(err, sshx.ErrConnect), errors.Is(err, proxmox.ErrNotProxmox):
		return newErr(422, err.Error(), err)
	case errors.Is(err, context.DeadlineExceeded):
		return newErr(422, sshx.ErrTimeout.Error(), err)
	}
	return newErr(422, "проверка не удалась: "+err.Error(), err)
}

func proxmoxPlan(st proxmox.State, keyPath string, keyPresent bool) []PlanItem {
	var plan []PlanItem
	switch {
	case !st.RoleExists:
		plan = append(plan, PlanItem{"role", "Создать роль " + proxmox.RoleName,
			"Минимальные права: " + strings.Join(proxmox.PrivilegesFor(st.Version), ", ")})
	case len(st.MissingPrivs()) > 0:
		plan = append(plan, PlanItem{"role", "Дополнить роль " + proxmox.RoleName,
			"Роль уже есть, добавим недостающие права: " + strings.Join(st.MissingPrivs(), ", ")})
	default:
		plan = append(plan, PlanItem{"role", "Роль " + proxmox.RoleName + " уже настроена", "Изменений не требуется."})
	}
	if st.UserExists {
		plan = append(plan, PlanItem{"user", "Пользователь " + proxmox.UserID + " уже есть", "Будет использован существующий, без изменений."})
	} else {
		plan = append(plan, PlanItem{"user", "Создать пользователя " + proxmox.UserID, "Realm pve, без пароля, комментарий «" + proxmox.Comment + "»."})
	}
	if st.ACLExists {
		plan = append(plan, PlanItem{"acl", "Права на / уже выданы", "Роль " + proxmox.RoleName + " для " + proxmox.UserID + " уже назначена."})
	} else {
		plan = append(plan, PlanItem{"acl", "Выдать роль на /", "Роль " + proxmox.RoleName + " для " + proxmox.UserID + " на путь / (с наследованием)."})
	}
	if st.TokenExist {
		plan = append(plan, PlanItem{"token", "Пересоздать API-токен " + proxmox.TokenID, "Токен с таким именем уже есть: он будет удалён и создан заново (старое значение перестанет работать)."})
	} else {
		plan = append(plan, PlanItem{"token", "Создать API-токен " + proxmox.TokenID, "Без раздельных привилегий (privsep 0); значение хранится зашифрованным."})
	}
	plan = append(plan, keyPlanItem(keyPath, keyPresent, len(st.Nodes) > 1))
	plan = append(plan, PlanItem{"verify", "Проверить доступ", "API с токеном (/version, /nodes) и вход ключом Hestia на каждый узел в сети."})
	return plan
}

func keyPlanItem(path string, present, cluster bool) PlanItem {
	if present {
		return PlanItem{"ssh_key", "Ключ Hestia уже в authorized_keys", "Изменений не требуется."}
	}
	if path == "" {
		path = "~/.ssh/authorized_keys"
	}
	d := "Добавить публичный ключ Hestia в " + path + "."
	if cluster {
		d += " В кластере файл общий — добавим один раз."
	}
	return PlanItem{"ssh_key", "Добавить SSH-ключ Hestia", d}
}

func sshPlan(keyPath string, keyPresent bool) []PlanItem {
	return []PlanItem{
		keyPlanItem(keyPath, keyPresent, false),
		{"verify", "Проверить вход ключом", "Подключение ключом Hestia и проверка отпечатка."},
	}
}
