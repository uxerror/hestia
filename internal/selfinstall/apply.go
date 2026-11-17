package selfinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/secrets"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/target"
)

// Result is what a finished installation reports to the UI. It is kept in
// memory only: HandoffURL carries a one-time login token.
type Result struct {
	URL        string `json:"url"`
	HandoffURL string `json:"handoff_url"`
	IP         string `json:"ip"`
	MAC        string `json:"mac,omitempty"`
	VMID       int    `json:"vmid,omitempty"`
	Node       string `json:"node,omitempty"`
	Kind       string `json:"kind"`
	Hint       string `json:"hint,omitempty"`
}

// Start confirms a probe and starts the installation job.
func (s *Service) Start(ctx context.Context, probeID string, userID int64) (store.Job, error) {
	if err := s.requireLocal(ctx); err != nil {
		return store.Job{}, err
	}
	res, err := s.acquire(probeID)
	if err != nil {
		return store.Job{}, err
	}
	started := false
	defer func() {
		if !started {
			s.release(probeID)
		}
	}()
	t, err := s.Store.GetTarget(ctx, res.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Job{}, newErr(404, "цель больше не подключена", nil)
	}
	if err != nil {
		return store.Job{}, err
	}
	bin, err := s.loadBinary()
	if err != nil {
		return store.Job{}, newErr(422, err.Error(), err)
	}
	title := "Установка Hestia на сервер: " + t.Name
	job, err := s.Runner.Start(JobKind, title, func(jctx context.Context, run *jobs.Run) error {
		in := &installer{s: s, run: run, res: res, t: t, userID: userID, bin: bin}
		err := in.execute(jctx)
		if err != nil {
			s.release(probeID)
			return err
		}
		s.drop(probeID)
		return nil
	})
	if err != nil {
		return store.Job{}, err
	}
	started = true
	return job, nil
}

type undoItem struct {
	title string
	fn    func(ctx context.Context) error
}

// shellFn runs a shell script on the machine that will host Hestia.
type shellFn func(ctx context.Context, script string, stdin []byte) (sshx.Result, error)

// installer executes one installation and keeps the undo stack.
type installer struct {
	s      *Service
	run    *jobs.Run
	res    ProbeResult
	t      store.Target
	userID int64
	bin    []byte

	api    API
	secret string // API token, only for masking
	cl     *sshx.Client
	root   bool // server kind: logged in as root
	sh     shellFn
	node   string // lxc: node name
	vmid   int
	ip     string // address of the new controller
	mac    string
	port   int
	undo   []undoItem
	commit bool // step 9 reached: nothing is rolled back any more
	bundle *bundle
}

func (in *installer) lxc() bool { return in.res.Kind == KindLXC }

func (in *installer) push(title string, fn func(ctx context.Context) error) {
	in.undo = append(in.undo, undoItem{title, fn})
}

// pushHost registers an undo that only matters on a standalone server (in a
// container it vanishes with the container).
func (in *installer) pushHost(title, script string) {
	if in.lxc() {
		return
	}
	in.push(title, func(ctx context.Context) error {
		_, err := in.sh(ctx, script, nil)
		return err
	})
}

func (in *installer) mask(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(secrets.Mask(err.Error(), in.secret))
}

func (in *installer) rollback() string {
	if len(in.undo) == 0 {
		return "Изменения на цели не вносились."
	}
	in.run.Log("warn", "Ошибка — откатываем созданное этой установкой")
	failed := 0
	for i := len(in.undo) - 1; i >= 0; i-- {
		u := in.undo[i]
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := u.fn(ctx)
		cancel()
		if err != nil {
			failed++
			in.run.Log("error", "откат: "+u.title+": "+in.mask(err).Error())
		} else {
			in.run.Log("info", "откат: "+u.title)
		}
	}
	in.undo = nil
	if failed > 0 {
		return fmt.Sprintf("Откат выполнен не полностью (ошибок: %d) — проверьте журнал и состояние цели.", failed)
	}
	return "Созданное этой установкой удалено; Hestia на этом ПК не изменилась."
}

func (in *installer) execute(ctx context.Context) (err error) {
	defer func() {
		if in.cl != nil {
			_ = in.cl.Close()
		}
	}()
	defer func() {
		if err == nil || in.commit {
			return
		}
		in.s.Gate.SetTransferring(false)
		err = fmt.Errorf("%w. %s", in.mask(err), in.rollback())
	}()
	if in.lxc() {
		err = in.executeLXC(ctx)
	} else {
		err = in.executeServer(ctx)
	}
	return err
}

// ---- running commands ----

// logSh runs a script, logging it (scripts never carry secrets).
func (in *installer) logSh(ctx context.Context, script string) (sshx.Result, error) {
	in.run.Log("info", "$ "+script)
	return in.sh(ctx, script, nil)
}

// putFile writes data through stdin, then fixes mode/owner and verifies the
// sha256 of the stored file.
func (in *installer) putFile(ctx context.Context, path string, data []byte, mode, owner string) error {
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	in.run.Log("info", fmt.Sprintf("→ %s (%d байт, sha256 %s…)", path, len(data), want[:12]))
	q := target.Quote(path)
	script := "cat > " + q + " && chmod " + mode + " " + q
	if owner != "" {
		script += " && chown " + owner + " " + q
	}
	uctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := in.sh(uctx, script, data); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	r, err := in.sh(ctx, "sha256sum "+q, nil)
	if err != nil {
		return fmt.Errorf("проверка %s: %w", path, err)
	}
	if f := strings.Fields(r.Stdout); len(f) == 0 || f[0] != want {
		return fmt.Errorf("контрольная сумма %s не совпала после записи", path)
	}
	return nil
}

// ---- Proxmox (LXC) ----

func (in *installer) nodeLogin(ctx context.Context) error {
	node, _ := findNode(in.t, in.res.Params.Node)
	cfg, ok := in.s.nodeCfg(in.t, node)
	if !ok {
		return fmt.Errorf("у узла %s нет закреплённого SSH-ключа", in.res.Params.Node)
	}
	cl, err := in.s.Dial(ctx, cfg)
	if err != nil {
		return fmt.Errorf("вход на узел %s: %w", in.res.Params.Node, err)
	}
	in.cl = cl
	return nil
}

func (in *installer) nodeExec(ctx context.Context, cmd string) (sshx.Result, error) {
	if in.cl == nil || !in.cl.Alive() {
		if in.cl != nil {
			_ = in.cl.Close()
		}
		if err := in.nodeLogin(ctx); err != nil {
			return sshx.Result{}, err
		}
	}
	return in.cl.Exec(ctx, cmd, nil)
}

func (in *installer) ctShell() shellFn {
	pfx := "pct exec " + strconv.Itoa(in.vmid) + " -- sh -c "
	return func(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
		if in.cl == nil || !in.cl.Alive() {
			if in.cl != nil {
				_ = in.cl.Close()
			}
			if err := in.nodeLogin(ctx); err != nil {
				return sshx.Result{}, err
			}
		}
		return in.cl.Exec(ctx, pfx+target.Quote(script), stdin)
	}
}

// wait waits for a Proxmox task, relaying its log into the job log.
func (in *installer) wait(ctx context.Context, upid string) error {
	if upid == "" {
		return nil
	}
	return in.api.WaitTask(ctx, in.res.Params.Node, upid, in.s.PollInterval, func(l string) {
		if l = strings.TrimSpace(l); l != "" {
			in.run.Log("info", "proxmox: "+secrets.Mask(l, in.secret))
		}
	})
}

func (in *installer) executeLXC(ctx context.Context) error {
	p := in.res.Params
	in.node, in.vmid, in.port = p.Node, p.VMID, DefaultPort
	var err error
	if in.api, in.secret, err = in.s.newAPI(ctx, in.t); err != nil {
		return err
	}
	if err := in.stepTemplate(ctx); err != nil {
		return err
	}
	if err := in.stepCreate(ctx); err != nil {
		return err
	}
	if err := in.stepStart(ctx); err != nil {
		return err
	}
	in.sh = in.ctShell()
	if err := in.run.Step("Уникальность контейнера", in.stepUnique); err != nil {
		return err
	}
	return in.finish(ctx)
}

func (in *installer) stepTemplate(ctx context.Context) error {
	p := in.res.Params
	return in.run.Step("Шаблон Debian 13", func(ctx context.Context) error {
		vols, err := in.api.StorageContent(ctx, p.Node, p.TemplateStorage, "vztmpl")
		if err != nil {
			return err
		}
		vol := templateVolID(p.TemplateStorage, p.Template)
		for _, v := range vols {
			if v.VolID == vol {
				in.run.Log("info", "Шаблон уже скачан: "+vol)
				return nil
			}
		}
		in.run.Log("info", "Скачиваем шаблон "+p.Template)
		upid, err := in.api.DownloadTemplate(ctx, p.Node, p.TemplateStorage, p.Template)
		if err != nil {
			return err
		}
		// Registered before waiting: a failed download may leave a partial file.
		in.push("удалить скачанный шаблон "+vol, func(ctx context.Context) error {
			up, err := in.api.DeleteVolume(ctx, p.Node, p.TemplateStorage, vol)
			if err != nil {
				var ae *proxmox.APIError
				if errors.As(err, &ae) && ae.Status == 500 && strings.Contains(ae.Detail, "does not exist") {
					return nil
				}
				return err
			}
			return in.wait(ctx, up)
		})
		dctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		defer cancel()
		return in.wait(dctx, upid)
	})
}

func (in *installer) net0() string {
	p := in.res.Params
	n := "name=eth0,bridge=" + p.Bridge + ",ip=" + p.IP + ",firewall=0"
	if p.IP != "dhcp" && p.Gateway != "" {
		n = "name=eth0,bridge=" + p.Bridge + ",ip=" + p.IP + ",gw=" + p.Gateway + ",firewall=0"
	}
	return n
}

func (in *installer) stepCreate(ctx context.Context) error {
	p := in.res.Params
	return in.run.Step("Создание контейнера", func(ctx context.Context) error {
		resources, err := in.api.ClusterResources(ctx)
		if err != nil {
			return err
		}
		if VMIDUsed(resources, p.VMID) {
			return fmt.Errorf("VMID %d уже занят — повторите проверку", p.VMID)
		}
		form := url.Values{
			"vmid":         {strconv.Itoa(p.VMID)},
			"hostname":     {p.Hostname},
			"ostemplate":   {templateVolID(p.TemplateStorage, p.Template)},
			"rootfs":       {p.Storage + ":" + strconv.Itoa(p.DiskGB)},
			"cores":        {strconv.Itoa(p.Cores)},
			"memory":       {strconv.Itoa(p.MemoryMB)},
			"swap":         {strconv.Itoa(p.SwapMB)},
			"net0":         {in.net0()},
			"unprivileged": {"1"},
			"features":     {"nesting=1"},
			"onboot":       {"1"},
			"start":        {"0"},
			"description":  {"Hestia controller"},
			"tags":         {"hestia"},
		}
		in.run.Log("info", fmt.Sprintf("Создаём контейнер %d (%s) на узле %s", p.VMID, p.Hostname, p.Node))
		upid, err := in.api.CreateLXC(ctx, p.Node, form)
		if err != nil {
			return err
		}
		in.push(fmt.Sprintf("удалить контейнер %d", p.VMID), in.destroyCT)
		cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		return in.wait(cctx, upid)
	})
}

// destroyCT stops the container if it runs and destroys it with its disks.
func (in *installer) destroyCT(ctx context.Context) error {
	p := in.res.Params
	st, err := in.api.LXCStatus(ctx, p.Node, p.VMID)
	if err != nil {
		var ae *proxmox.APIError
		if errors.As(err, &ae) && (ae.Status == 500 || ae.Status == 404) {
			return nil // never created (or already gone)
		}
		return err
	}
	if st == "running" {
		up, err := in.api.StopLXC(ctx, p.Node, p.VMID)
		if err != nil {
			return err
		}
		if err := in.wait(ctx, up); err != nil {
			return err
		}
	}
	up, err := in.api.DeleteLXC(ctx, p.Node, p.VMID)
	if err != nil {
		return err
	}
	return in.wait(ctx, up)
}

func (in *installer) stepStart(ctx context.Context) error {
	p := in.res.Params
	return in.run.Step("Запуск контейнера", func(ctx context.Context) error {
		up, err := in.api.StartLXC(ctx, p.Node, p.VMID)
		if err != nil {
			return err
		}
		if err := in.wait(ctx, up); err != nil {
			return err
		}
		if cfg, err := in.api.LXCConfig(ctx, p.Node, p.VMID); err == nil {
			in.mac = proxmox.NetHWAddr(cfg["net0"])
		}
		in.run.Log("info", "Ждём адрес контейнера")
		deadline := time.Now().Add(in.s.IPTimeout)
		for {
			ifs, err := in.api.LXCInterfaces(ctx, p.Node, p.VMID)
			if err == nil {
				if ip := proxmox.IfaceIPv4(ifs, "eth0"); ip != "" {
					in.ip = ip
					break
				}
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("контейнер не получил IPv4-адрес за %d с (DHCP не отвечает?)", int(in.s.IPTimeout.Seconds()))
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(in.s.PollInterval):
			}
		}
		in.run.Log("info", fmt.Sprintf("Адрес контейнера: %s, MAC: %s", in.ip, in.mac))
		return in.waitCT(ctx)
	})
}

// waitCT waits until commands run inside the container and systemd is up.
func (in *installer) waitCT(ctx context.Context) error {
	sh := in.ctShell()
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, err := sh(ctx, "true", nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("команды в контейнере не выполняются: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(in.s.PollInterval):
		}
	}
	// "degraded" is fine; we only want the boot to be over.
	wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, _ = sh(wctx, "systemctl is-system-running --wait", nil)
	return nil
}

// stepUnique makes sure the container does not share its identity with the
// node (a template can ship a machine-id or SSH host keys) and has host keys.
func (in *installer) stepUnique(ctx context.Context) error {
	node, err := in.nodeExec(ctx, "cat /etc/machine-id")
	nodeID := ""
	if err == nil {
		nodeID = strings.TrimSpace(node.Stdout)
	}
	ct, _ := in.sh(ctx, "cat /etc/machine-id", nil)
	id := strings.TrimSpace(ct.Stdout)
	if !validMachineID(id) || (nodeID != "" && id == nodeID) {
		in.run.Log("info", "machine-id контейнера пуст или совпадает с узлом — создаём новый")
		if _, err := in.logSh(ctx, "rm -f /etc/machine-id && systemd-machine-id-setup"); err != nil {
			return fmt.Errorf("machine-id: %w", err)
		}
		r, err := in.sh(ctx, "cat /etc/machine-id", nil)
		if err != nil {
			return err
		}
		if id = strings.TrimSpace(r.Stdout); !validMachineID(id) || id == nodeID {
			return errors.New("не удалось получить уникальный machine-id контейнера")
		}
	}
	const key = "/etc/ssh/ssh_host_ed25519_key.pub"
	if _, err := in.sh(ctx, "test -s "+key, nil); err != nil {
		in.run.Log("info", "SSH host keys контейнера нет — создаём")
		if _, err := in.logSh(ctx, "ssh-keygen -A"); err != nil {
			return fmt.Errorf("ssh-keygen: %w", err)
		}
	}
	r, err := in.sh(ctx, "ssh-keygen -lf "+key, nil)
	if err != nil {
		return fmt.Errorf("SSH host key контейнера: %w", err)
	}
	in.run.Log("info", "Отпечаток SSH host key (ed25519) контейнера: "+strings.TrimSpace(r.Stdout))
	return nil
}

func validMachineID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ---- standalone server ----

func (in *installer) executeServer(ctx context.Context) error {
	in.port = in.res.Params.Port
	if in.port == 0 {
		in.port = DefaultPort
	}
	in.ip = in.t.Host
	if err := in.run.Step("Подключение по SSH", func(ctx context.Context) error {
		cl, err := in.s.Dial(ctx, sshx.Config{Host: in.t.Host, Port: in.t.Port, User: in.t.SSHUser,
			Signer: in.s.Identity.Signer, ExpectedFP: in.t.HostKeyFP})
		if err != nil {
			return err
		}
		in.cl = cl
		facts, err := target.NewSSH(cl).Facts(ctx)
		if err != nil {
			return err
		}
		if !facts.IsRoot() && !facts.Sudo {
			return errors.New("нужен root или sudo без пароля")
		}
		in.root = facts.IsRoot()
		in.sh = serverShell(cl, in.root)
		if r, err := in.sh(ctx, fmt.Sprintf("test -e %s -o -e %s -o -e %s && echo yes", binPath, unitPath, dataPath), nil); err == nil && strings.TrimSpace(r.Stdout) == "yes" {
			return errors.New("Hestia уже установлена на этом сервере — ничего не перезаписываем")
		}
		return nil
	}); err != nil {
		return err
	}
	return in.finish(ctx)
}

// ---- common steps (on the machine that will host Hestia) ----

func (in *installer) finish(ctx context.Context) error {
	if err := in.run.Step("Пользователь и бинарник", in.stepBinary); err != nil {
		return err
	}
	if err := in.run.Step("Служба systemd", in.stepUnit); err != nil {
		return err
	}
	if err := in.run.Step("Перенос состояния", in.stepState); err != nil {
		return err
	}
	var res Result
	if err := in.run.Step("Запуск и проверка", func(ctx context.Context) error {
		var err error
		res, err = in.stepVerify(ctx)
		return err
	}); err != nil {
		return err
	}
	// Past this point the new controller works: nothing is rolled back.
	in.commit = true
	return in.run.Step("Переключение", func(ctx context.Context) error {
		if err := in.switchOver(ctx, &res); err != nil {
			return fmt.Errorf("Hestia установлена и работает на %s, но переключить этот ПК не удалось: %w. Откройте %s вручную; созданное на цели не удаляется", res.URL, err, res.URL)
		}
		in.run.SetResult(res)
		return nil
	})
}

func (in *installer) stepBinary(ctx context.Context) error {
	if _, err := in.sh(ctx, "id -u "+svcUser, nil); err != nil {
		if _, err := in.logSh(ctx, "useradd --system --home-dir "+dataPath+" --shell /usr/sbin/nologin "+svcUser); err != nil {
			return fmt.Errorf("создание пользователя %s: %w", svcUser, err)
		}
		in.pushHost("удалить пользователя "+svcUser, "userdel "+svcUser)
	} else {
		in.run.Log("info", "Пользователь "+svcUser+" уже есть")
	}
	if _, err := in.logSh(ctx, "install -d -m 0700 -o "+svcUser+" -g "+svcUser+" "+dataPath); err != nil {
		return fmt.Errorf("каталог %s: %w", dataPath, err)
	}
	in.pushHost("удалить "+dataPath, "rm -rf "+dataPath)
	in.pushHost("удалить "+binPath, "rm -f "+binPath)
	if err := in.putFile(ctx, binPath, in.bin, "0755", "root:root"); err != nil {
		return err
	}
	r, err := in.sh(ctx, binPath+" version", nil)
	if err != nil {
		return fmt.Errorf("запуск hestia на цели: %w", err)
	}
	got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Stdout), "hestia"))
	if got != in.s.Version {
		return fmt.Errorf("версия hestia на цели (%s) не совпала с версией контроллера (%s)", got, in.s.Version)
	}
	in.run.Log("info", "Версия hestia на цели: "+got)
	return nil
}

func (in *installer) stepUnit(ctx context.Context) error {
	in.pushHost("отключить службу и удалить юнит", "systemctl disable --now hestia; rm -f "+unitPath+"; systemctl daemon-reload")
	if err := in.putFile(ctx, unitPath, []byte(unitText(in.port)), "0644", "root:root"); err != nil {
		return err
	}
	if _, err := in.logSh(ctx, "systemctl daemon-reload && systemctl enable hestia"); err != nil {
		return fmt.Errorf("systemctl enable: %w", err)
	}
	return nil
}

func (in *installer) stepState(ctx context.Context) error {
	b, err := in.s.buildBundle(ctx, in.run.ID(), in.userID, in.location())
	if err != nil {
		return err
	}
	in.bundle = b
	in.s.Gate.SetTransferring(true)
	in.run.Log("info", "Перенос начался: изменения в Hestia на этом ПК временно заблокированы")
	for _, f := range []struct {
		name string
		data []byte
	}{{"hestia.db", b.DB}, {"master.key", b.Key}} {
		if err := in.putFile(ctx, dataPath+"/"+f.name, f.data, "0600", svcUser+":"+svcUser); err != nil {
			return err
		}
	}
	return nil
}

func (in *installer) location() Location {
	l := Location{IP: in.ip, MAC: in.mac, TargetID: in.t.ID, MovedAt: in.s.Now().UTC()}
	if in.lxc() {
		l.Kind, l.Node, l.VMID = "lxc", in.node, in.vmid
	} else {
		l.Kind, l.Host = "ssh", in.t.Host
	}
	return l
}

func (in *installer) baseURL() string { return hostURL(in.ip, in.port) }

func (in *installer) stepVerify(ctx context.Context) (Result, error) {
	if _, err := in.logSh(ctx, "systemctl start hestia"); err != nil {
		return Result{}, fmt.Errorf("запуск службы hestia: %w", err)
	}
	base := in.s.HealthBase(in.ip, in.port)
	in.run.Log("info", "Проверяем "+base+"/api/v1/health")
	want, err := in.s.Store.EnsureInstanceID(ctx)
	if err != nil {
		return Result{}, err
	}
	deadline := time.Now().Add(in.s.HealthTimeout)
	for {
		id, ok := fetchHealth(ctx, in.s.HTTP, base)
		if ok {
			if id != want {
				return Result{}, errors.New("на новом месте отвечает Hestia с другим идентификатором экземпляра — перенесённая база не поднялась")
			}
			break
		}
		if time.Now().After(deadline) {
			return Result{}, fmt.Errorf("Hestia запущена на цели, но адрес %s не отвечает с этого компьютера (маршрут или фаервол?)", in.baseURL())
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	in.run.Log("info", "Новый контроллер отвечает, идентификатор экземпляра совпал")
	res := Result{URL: in.baseURL(), IP: in.ip, MAC: in.mac, VMID: in.vmid, Node: in.node, Kind: in.res.Kind,
		HandoffURL: in.baseURL() + "/#/handoff/" + in.bundle.Token}
	if in.lxc() && in.res.Params.IP == "dhcp" {
		res.Hint = "Закрепите адрес в DHCP роутера (MikroTik: IP → DHCP Server → Leases → Make Static), MAC " + in.mac + "."
	}
	return res, nil
}
