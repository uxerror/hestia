package onboard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/target"
)

// CreateRequest is the body of POST /targets.
type CreateRequest struct {
	ProbeID string `json:"probe_id"`
	Name    string `json:"name"`
	Accept  struct {
		HostKeyFP string `json:"host_key_fp"`
		APICertFP string `json:"api_cert_fp"`
	} `json:"accept"`
}

// Connect confirms a probe and starts the job that applies its plan. The
// fingerprints must equal the ones the probe reported.
func (s *Service) Connect(ctx context.Context, req CreateRequest) (store.Job, error) {
	sess, err := s.acquire(req.ProbeID)
	if err != nil {
		return store.Job{}, err
	}
	started := false
	defer func() {
		if !started {
			s.release(req.ProbeID)
		}
	}()
	res := sess.result

	if req.Accept.HostKeyFP != res.HostKeyFP {
		return store.Job{}, newErr(409, "отпечаток SSH-ключа не совпадает с найденным при проверке — проверьте подключение заново", nil)
	}
	if res.Kind == store.KindProxmox {
		if req.Accept.APICertFP == "" {
			return store.Job{}, newErr(400, "подтвердите отпечаток TLS-сертификата Proxmox", nil)
		}
		if req.Accept.APICertFP != res.APICertFP {
			return store.Job{}, newErr(409, "отпечаток TLS-сертификата не совпадает с найденным при проверке — проверьте подключение заново", nil)
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = res.SuggestedName
	}
	if name == "" {
		name = res.Host
	}
	if len([]rune(name)) > 64 {
		return store.Job{}, newErr(400, "имя не длиннее 64 символов", nil)
	}
	if _, err := s.Store.FindTargetByAddr(ctx, res.Host, res.Port); err == nil {
		return store.Job{}, newErr(409, "эта цель уже подключена", nil)
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Job{}, err
	}

	// The user's credentials only travel in this closure.
	cfg := sess.cfg
	cfg.ExpectedFP = res.HostKeyFP
	title := "Подключение: " + name
	job, err := s.Runner.Start("target.connect", title, func(jctx context.Context, run *jobs.Run) error {
		a := &applier{s: s, run: run, cfg: cfg, res: res, name: name}
		defer a.closeConn()
		err := a.execute(jctx)
		if err != nil {
			s.release(req.ProbeID)
			return err
		}
		s.drop(req.ProbeID)
		return nil
	})
	if err != nil {
		return store.Job{}, err
	}
	started = true
	return job, nil
}

// applier executes a plan and keeps the undo stack.
type applier struct {
	s    *Service
	run  *jobs.Run
	cfg  sshx.Config
	res  ProbeResult
	name string

	tg    *target.SSH
	undo  []undoItem
	token string // never logged
}

type undoItem struct {
	title string
	fn    func(ctx context.Context) error
}

func (a *applier) push(title string, fn func(ctx context.Context) error) {
	a.undo = append(a.undo, undoItem{title, fn})
}

// conn returns a live connection, redialing if it dropped.
func (a *applier) conn(ctx context.Context) (*target.SSH, error) {
	if a.tg != nil && a.tg.Client().Alive() {
		return a.tg, nil
	}
	cl, err := a.s.Dial(ctx, a.cfg)
	if err != nil {
		return nil, err
	}
	a.tg = target.NewSSH(cl)
	return a.tg, nil
}

func (a *applier) closeConn() {
	if a.tg != nil {
		_ = a.tg.Close()
	}
}

// sh runs a command, logging it (commands never contain secrets).
func (a *applier) sh(ctx context.Context, cmd string) error {
	tg, err := a.conn(ctx)
	if err != nil {
		return err
	}
	a.run.Log("info", "$ "+cmd)
	_, err = tg.Exec(ctx, cmd)
	return a.mask(err)
}

func (a *applier) mask(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(secrets.Mask(err.Error(), a.token, a.cfg.Password))
}

// rollback undoes completed changes in reverse order with a fresh context.
func (a *applier) rollback() string {
	if len(a.undo) == 0 {
		return "Изменения на цели не вносились."
	}
	a.run.Log("warn", "Ошибка — откатываем уже внесённые изменения")
	failed := 0
	for i := len(a.undo) - 1; i >= 0; i-- {
		u := a.undo[i]
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := u.fn(ctx)
		cancel()
		if err != nil {
			failed++
			a.run.Log("error", "откат: "+u.title+": "+a.mask(err).Error())
		} else {
			a.run.Log("info", "откат: "+u.title)
		}
	}
	a.undo = nil
	if failed > 0 {
		return fmt.Sprintf("Откат выполнен не полностью (ошибок: %d) — проверьте журнал и состояние цели.", failed)
	}
	return "Внесённые изменения откатаны."
}

func (a *applier) execute(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w. %s", err, a.rollback())
		}
	}()
	if a.res.Kind == store.KindProxmox {
		return a.proxmox(ctx)
	}
	return a.ssh(ctx)
}

// connect is the first step shared by both kinds: dial with the pinned host key.
func (a *applier) connect(ctx context.Context) error {
	return a.run.Step("Подключение по SSH", func(ctx context.Context) error {
		tg, err := a.conn(ctx)
		if err != nil {
			return err
		}
		a.run.Log("info", fmt.Sprintf("Подключено к %s, отпечаток SSH совпадает: %s", a.cfg.Addr(), tg.Client().HostKeyFP()))
		return nil
	})
}

func (a *applier) addKey(ctx context.Context, title string) (path string, err error) {
	err = a.run.Step(title, func(ctx context.Context) error {
		tg, err := a.conn(ctx)
		if err != nil {
			return err
		}
		path, err = target.AuthorizedKeysPath(ctx, tg)
		if err != nil {
			return err
		}
		added, err := target.AddAuthorizedKey(ctx, tg, path, a.s.Identity.AuthorizedKey)
		if err != nil {
			return err
		}
		if !added {
			a.run.Log("info", "Ключ Hestia уже есть в "+path)
			return nil
		}
		a.run.Log("info", "Ключ Hestia добавлен в "+path)
		a.push("удалить ключ Hestia из "+path, func(ctx context.Context) error {
			tg, err := a.conn(ctx)
			if err != nil {
				return err
			}
			return target.RemoveAuthorizedKey(ctx, tg, path, a.s.Identity.AuthorizedKey)
		})
		return nil
	})
	return path, err
}

// hestiaCfg is a login with Hestia's own key.
func (a *applier) hestiaCfg(host string, port int, pin string) sshx.Config {
	return sshx.Config{Host: host, Port: port, User: a.cfg.User, Signer: a.s.Identity.Signer, ExpectedFP: pin}
}

func (a *applier) ssh(ctx context.Context) error {
	if err := a.connect(ctx); err != nil {
		return err
	}
	if _, err := a.addKey(ctx, "Ключ Hestia в authorized_keys"); err != nil {
		return err
	}
	if err := a.run.Step("Проверка входа ключом", func(ctx context.Context) error {
		return a.verifyKeyLogin(ctx, a.hestiaCfg(a.cfg.Host, a.cfg.Port, a.res.HostKeyFP))
	}); err != nil {
		return err
	}
	return a.run.Step("Сохранение", func(ctx context.Context) error {
		t := store.Target{
			Kind: store.KindSSH, Name: a.name, Host: a.res.Host, Port: a.res.Port, SSHUser: a.res.Username,
			HostKeyFP: a.res.HostKeyFP, Nodes: []store.Node{},
		}
		return a.save(ctx, &t)
	})
}

func (a *applier) verifyKeyLogin(ctx context.Context, cfg sshx.Config) error {
	cl, err := a.s.Dial(ctx, cfg)
	if err != nil {
		return fmt.Errorf("вход ключом Hestia на %s не удался: %w", cfg.Addr(), err)
	}
	defer cl.Close()
	if _, err := cl.Exec(ctx, "true", nil); err != nil {
		return fmt.Errorf("команда по ключу Hestia на %s: %w", cfg.Addr(), err)
	}
	a.run.Log("info", "Вход ключом Hestia на "+cfg.Addr()+" работает")
	return nil
}

func (a *applier) save(ctx context.Context, t *store.Target) error {
	if a.token != "" {
		ref, err := a.s.Secrets.Put(ctx, secrets.PurposeAPIToken, []byte(a.token))
		if err != nil {
			return err
		}
		a.push("удалить сохранённый секрет токена", func(ctx context.Context) error { return a.s.Secrets.Delete(ctx, ref) })
		t.TokenSecretRef = ref
		t.TokenID = proxmox.TokenID
	}
	if err := a.s.Store.CreateTarget(ctx, t); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return errors.New("цель с таким именем или адресом уже есть")
		}
		return err
	}
	a.run.Log("info", "Цель сохранена")
	if a.s.AfterChange != nil {
		a.s.AfterChange(t.ID)
	}
	return nil
}

func (a *applier) proxmox(ctx context.Context) error {
	if err := a.connect(ctx); err != nil {
		return err
	}
	var st proxmox.State
	if err := a.run.Step("Проверка Proxmox", func(ctx context.Context) error {
		tg, err := a.conn(ctx)
		if err != nil {
			return err
		}
		if st, err = proxmox.Inspect(ctx, tg); err != nil {
			return err
		}
		// TOFU: the API certificate must still be the one the user confirmed.
		fp, err := a.s.FetchCertFP(ctx, a.cfg.Host, a.s.APIPort)
		if err != nil {
			return err
		}
		if fp != a.res.APICertFP {
			return proxmox.ErrCertChanged
		}
		if err := a.checkNodeKeys(st); err != nil {
			return err
		}
		a.run.Log("info", fmt.Sprintf("Proxmox VE %s, узлов: %d", st.Version, len(st.Nodes)))
		return nil
	}); err != nil {
		return err
	}

	if err := a.run.Step("Роль "+proxmox.RoleName, func(ctx context.Context) error {
		switch {
		case !st.RoleExists:
			if err := a.sh(ctx, proxmox.CmdRoleCreate(st.Version)); err != nil {
				return err
			}
			a.push("удалить роль "+proxmox.RoleName, func(ctx context.Context) error { return a.sh(ctx, proxmox.CmdRoleDel) })
		case len(st.MissingPrivs()) > 0:
			if err := a.sh(ctx, proxmox.CmdRoleModify(st.Version, st.RolePrivs)); err != nil {
				return err
			}
			old := st.RolePrivs
			a.push("вернуть права роли "+proxmox.RoleName, func(ctx context.Context) error { return a.sh(ctx, proxmox.CmdRoleRestore(old)) })
		default:
			a.run.Log("info", "Роль уже настроена")
		}
		return nil
	}); err != nil {
		return err
	}

	if err := a.run.Step("Пользователь "+proxmox.UserID, func(ctx context.Context) error {
		if st.UserExists {
			a.run.Log("info", "Пользователь уже есть")
			return nil
		}
		if err := a.sh(ctx, proxmox.CmdUserAdd); err != nil {
			return err
		}
		a.push("удалить пользователя "+proxmox.UserID, func(ctx context.Context) error { return a.sh(ctx, proxmox.CmdUserDel) })
		return nil
	}); err != nil {
		return err
	}

	if err := a.run.Step("Права на /", func(ctx context.Context) error {
		if st.ACLExists {
			a.run.Log("info", "Права уже выданы")
			return nil
		}
		if err := a.sh(ctx, proxmox.CmdACLAdd); err != nil {
			return err
		}
		a.push("убрать права на /", func(ctx context.Context) error { return a.sh(ctx, proxmox.CmdACLDel) })
		return nil
	}); err != nil {
		return err
	}

	if err := a.run.Step("API-токен "+proxmox.TokenID, func(ctx context.Context) error {
		if st.TokenExist {
			a.run.Log("warn", "Токен уже есть — удаляем и создаём заново")
			if err := a.sh(ctx, proxmox.CmdTokenDel); err != nil {
				return err
			}
		}
		tg, err := a.conn(ctx)
		if err != nil {
			return err
		}
		a.run.Log("info", "$ pveum user token add "+proxmox.UserID+" "+proxmox.TokenName+" --privsep 0 (вывод не журналируется)")
		tok, err := proxmox.AddToken(ctx, tg)
		if err != nil {
			return a.mask(err)
		}
		a.token = tok
		a.push("удалить API-токен "+proxmox.TokenID, func(ctx context.Context) error { return a.sh(ctx, proxmox.CmdTokenDel) })
		return nil
	}); err != nil {
		return err
	}

	if _, err := a.addKey(ctx, "SSH-ключ Hestia для узлов"); err != nil {
		return err
	}

	if err := a.run.Step("Проверка доступа", func(ctx context.Context) error { return a.verifyProxmox(ctx, st) }); err != nil {
		return err
	}

	return a.run.Step("Сохранение", func(ctx context.Context) error {
		t := store.Target{
			Kind: store.KindProxmox, Name: a.name, Host: a.res.Host, Port: a.res.Port, SSHUser: a.res.Username,
			HostKeyFP: a.res.HostKeyFP, APICertFP: a.res.APICertFP, Cluster: st.Cluster, Nodes: []store.Node{},
		}
		for _, n := range st.Nodes {
			t.Nodes = append(t.Nodes, store.Node{Name: n.Name, IP: n.IP, Online: n.Online, HostKeyFP: n.HostKeyFP, HostKeyType: n.HostKeyType})
		}
		return a.save(ctx, &t)
	})
}

func (a *applier) verifyProxmox(ctx context.Context, st proxmox.State) error {
	api := proxmox.NewClient(proxmox.ClientConfig{
		Host: a.cfg.Host, Port: a.s.APIPort, TokenID: proxmox.TokenID, Secret: a.token, PinFP: a.res.APICertFP,
	})
	v, err := api.Version(ctx)
	if err != nil {
		return a.mask(err)
	}
	nodes, err := api.Nodes(ctx)
	if err != nil {
		return a.mask(err)
	}
	a.run.Log("info", fmt.Sprintf("API с токеном работает: версия %s, узлов в ответе: %d", v, len(nodes)))

	for _, n := range st.Nodes {
		if !n.Online {
			a.run.Log("warn", "Узел "+n.Name+" не в сети — пропущен")
			continue
		}
		cfg := a.hestiaCfg(a.cfg.Host, a.cfg.Port, a.res.HostKeyFP)
		if n.Name != st.LocalNode && len(st.Nodes) > 1 {
			var err error
			if cfg, err = a.nodeCfg(n); err != nil {
				return err
			}
		}
		if err := a.verifyKeyLogin(ctx, cfg); err != nil {
			return fmt.Errorf("узел %s: %w", n.Name, err)
		}
	}
	return nil
}

// nodeCfg is a Hestia-key login to another cluster node, pinned to the host
// key the cluster records for it. Without such a key there is no login: a
// node is never trusted on first use.
func (a *applier) nodeCfg(n proxmox.Node) (sshx.Config, error) {
	if n.IP == "" {
		return sshx.Config{}, fmt.Errorf("у узла %s нет адреса в кластере", n.Name)
	}
	return nodeLoginCfg(a.hestiaCfg(n.IP, a.cfg.Port, ""), n.Name, n.HostKeyType, n.HostKeyFP)
}

// nodeLoginCfg pins cfg to a node's host key and restricts the accepted key
// algorithms to that key's type.
func nodeLoginCfg(cfg sshx.Config, node, keyType, fp string) (sshx.Config, error) {
	if fp == "" || keyType == "" {
		return sshx.Config{}, fmt.Errorf("у узла %s нет SSH-ключа в файлах кластера (/etc/pve/nodes/%s/ssh_known_hosts) — без него вход на узел не проверить: ключ не принимается вслепую", node, node)
	}
	cfg.ExpectedFP = fp
	cfg.HostKeyAlgorithms = sshx.AlgorithmsForKeyType(keyType)
	return cfg, nil
}

// checkNodeKeys makes sure the cluster's node keys are still the ones shown
// to the user at probe time.
func (a *applier) checkNodeKeys(st proxmox.State) error {
	seen := map[string]store.Node{}
	for _, n := range a.res.Nodes {
		seen[n.Name] = n
	}
	for _, n := range st.Nodes {
		if old, ok := seen[n.Name]; ok && (old.HostKeyFP != n.HostKeyFP || old.HostKeyType != n.HostKeyType) {
			return fmt.Errorf("SSH-ключ узла %s в кластере изменился с момента проверки — проверьте подключение заново", n.Name)
		}
	}
	return nil
}
