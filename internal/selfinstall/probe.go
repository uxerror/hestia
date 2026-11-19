package selfinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"os"

	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
)

// ProbeRequest is the body of POST /selfinstall/probe. Zero fields take the
// default values.
type ProbeRequest struct {
	TargetID        int64  `json:"target_id"`
	Node            string `json:"node"`
	VMID            int    `json:"vmid"`
	Hostname        string `json:"hostname"`
	Storage         string `json:"storage"`
	TemplateStorage string `json:"template_storage"`
	Bridge          string `json:"bridge"`
	IP              string `json:"ip"` // "dhcp" or "a.b.c.d/nn"
	Gateway         string `json:"gateway"`
	Cores           int    `json:"cores"`
	MemoryMB        int    `json:"memory_mb"`
	DiskGB          int    `json:"disk_gb"`
	Port            int    `json:"port"`
}

// Params are the final values of an installation.
type Params struct {
	Node            string `json:"node,omitempty"`
	VMID            int    `json:"vmid,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	Storage         string `json:"storage,omitempty"`
	TemplateStorage string `json:"template_storage,omitempty"`
	Bridge          string `json:"bridge,omitempty"`
	IP              string `json:"ip,omitempty"`
	Gateway         string `json:"gateway,omitempty"`
	Cores           int    `json:"cores,omitempty"`
	MemoryMB        int    `json:"memory_mb,omitempty"`
	SwapMB          int    `json:"swap_mb,omitempty"`
	DiskGB          int    `json:"disk_gb,omitempty"`
	Template        string `json:"template,omitempty"`
	TemplatePresent bool   `json:"template_present"`
	Port            int    `json:"port,omitempty"`
}

// PlanItem is one change the installation will make.
type PlanItem struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// StorageChoice is a storage offered in the form.
type StorageChoice struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Avail int64  `json:"avail"`
}

// Choices are the values the form can offer for the chosen node.
type Choices struct {
	Nodes            []string        `json:"nodes"`
	Storages         []StorageChoice `json:"storages"`
	TemplateStorages []string        `json:"template_storages"`
	Bridges          []string        `json:"bridges"`
}

// ProbeResult is the answer of a probe.
type ProbeResult struct {
	ProbeID    string     `json:"probe_id"`
	Kind       string     `json:"kind"` // lxc | ssh
	TargetID   int64      `json:"target_id"`
	TargetName string     `json:"target_name"`
	Params     Params     `json:"params"`
	Defaults   Params     `json:"defaults"`
	Choices    Choices    `json:"choices"`
	Warnings   []string   `json:"warnings"`
	Plan       []PlanItem `json:"plan"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Probe checks everything the installation needs without changing anything
// and returns the values, the plan and a session to confirm.
func (s *Service) Probe(ctx context.Context, req ProbeRequest) (*ProbeResult, error) {
	if err := s.requireLocal(ctx); err != nil {
		return nil, err
	}
	t, err := s.Store.GetTarget(ctx, req.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, newErr(404, "цель не найдена", nil)
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.loadBinary(); err != nil {
		return nil, newErr(422, err.Error(), err)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var res *ProbeResult
	if t.Kind == store.KindProxmox {
		res, err = s.probeLXC(ctx, req, t)
	} else {
		res, err = s.probeServer(ctx, req, t)
	}
	if err != nil {
		return nil, err
	}
	s.putSession(res)
	return res, nil
}

// ---- binary ----

// loadBinary returns the server binary (and caches it).
func (s *Service) loadBinary() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bin != nil {
		return s.bin, nil
	}
	b, err := s.readBinary()
	if err != nil {
		return nil, err
	}
	s.bin = b
	return b, nil
}

var errNoBinary = errors.New("эта сборка не содержит серверного бинарника: соберите её через make desktop или запустите установку из серверной сборки (hestia serve)")

func (s *Service) readBinary() ([]byte, error) {
	if s.Binary != nil {
		return s.Binary()
	}
	if b, ok := embeddedBinary(); ok {
		return b, nil
	}
	if desktopBuild {
		return nil, errNoBinary
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("серверный бинарник для linux/amd64 недоступен: Hestia запущена на %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("серверный бинарник: %w", err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return nil, fmt.Errorf("серверный бинарник: %w", err)
	}
	if err := ValidateServerBinary(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---- Proxmox ----

func (s *Service) newAPI(ctx context.Context, t store.Target) (API, string, error) {
	raw, err := s.Secrets.Get(ctx, t.TokenSecretRef)
	if err != nil {
		return nil, "", fmt.Errorf("токен API: %w", err)
	}
	secret := string(raw)
	return s.NewAPI(proxmox.ClientConfig{Host: t.Host, Port: s.APIPort, TokenID: t.TokenID, Secret: secret, PinFP: t.APICertFP}), secret, nil
}

// nodeCfg is a Hestia-key login to a node, pinned to the host key recorded
// in the cluster. Without such a key the node is never used.
func (s *Service) nodeCfg(t store.Target, n store.Node) (sshx.Config, bool) {
	if n.IP == "" || n.HostKeyFP == "" || n.HostKeyType == "" {
		return sshx.Config{}, false
	}
	return sshx.Config{
		Host: n.IP, Port: t.Port, User: t.SSHUser, Signer: s.Identity.Signer,
		ExpectedFP: n.HostKeyFP, HostKeyAlgorithms: sshx.AlgorithmsForKeyType(n.HostKeyType),
	}, true
}

func findNode(t store.Target, name string) (store.Node, bool) {
	for _, n := range t.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return store.Node{}, false
}

func apiErr(err error, secret string) error {
	if err == nil {
		return nil
	}
	return newErr(422, "Proxmox: "+secrets.Mask(err.Error(), secret), err)
}

func (s *Service) probeLXC(ctx context.Context, req ProbeRequest, t store.Target) (*ProbeResult, error) {
	api, secret, err := s.newAPI(ctx, t)
	if err != nil {
		return nil, err
	}
	res := &ProbeResult{Kind: KindLXC, TargetID: t.ID, TargetName: t.Name, Warnings: []string{}, Plan: []PlanItem{}}

	resources, err := api.ClusterResources(ctx)
	if err != nil {
		return nil, apiErr(err, secret)
	}
	// Nodes that are online and that Hestia can log in to with a pinned key.
	var cands []string
	for _, n := range t.Nodes {
		if _, ok := s.nodeCfg(t, n); !ok {
			if n.Online {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Узел %s не предлагается: для него нет закреплённого SSH-ключа.", n.Name))
			}
			continue
		}
		cands = append(cands, n.Name)
	}
	var online []string
	for _, r := range resources {
		if r.Type == "node" && r.Status == "online" {
			for _, c := range cands {
				if c == r.Node {
					online = append(online, c)
				}
			}
		}
	}
	sort.Strings(online)
	res.Choices = Choices{Nodes: online, Storages: []StorageChoice{}, TemplateStorages: []string{}, Bridges: []string{}}
	if len(online) == 0 {
		return nil, newErr(422, "нет узла в сети, на котором Hestia может создать контейнер", nil)
	}
	def := Params{
		Hostname: DefaultHostname, Cores: DefaultCores, MemoryMB: DefaultMemoryMB, SwapMB: DefaultSwapMB,
		DiskGB: DefaultDiskGB, IP: "dhcp", Node: PickNode(resources, online),
		VMID: FirstFreeVMID(resources, DefaultVMIDFrom),
	}
	if def.Node == "" {
		def.Node = online[0]
	}
	p := def
	bad := func(msg string) (*ProbeResult, error) { return nil, newErr(422, msg, nil) }
	if req.Node != "" {
		if !contains(online, req.Node) {
			return bad(fmt.Sprintf("узел %s не в сети или недоступен для Hestia", req.Node))
		}
		p.Node = req.Node
	}
	if req.Hostname != "" {
		p.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
		if !hostnameRe.MatchString(p.Hostname) {
			return bad("имя контейнера: латиница в нижнем регистре, цифры и дефис")
		}
	}
	if req.Cores != 0 {
		if req.Cores < 1 || req.Cores > 64 {
			return bad("число ядер: от 1 до 64")
		}
		p.Cores = req.Cores
	}
	if req.MemoryMB != 0 {
		if req.MemoryMB < 256 || req.MemoryMB > 1<<20 {
			return bad("память: не меньше 256 МБ")
		}
		p.MemoryMB = req.MemoryMB
	}
	if req.DiskGB != 0 {
		if req.DiskGB < 2 || req.DiskGB > 4096 {
			return bad("диск: от 2 до 4096 ГБ")
		}
		p.DiskGB = req.DiskGB
	}
	if req.VMID != 0 {
		if req.VMID < 100 || req.VMID > 999999999 {
			return bad("VMID: от 100 до 999999999")
		}
		p.VMID = req.VMID
	}
	if VMIDUsed(resources, p.VMID) {
		return bad(fmt.Sprintf("VMID %d уже занят в кластере", p.VMID))
	}

	// The node must be x86_64 (the embedded binary is linux/amd64).
	node, _ := findNode(t, p.Node)
	cfg, _ := s.nodeCfg(t, node)
	cl, err := s.Dial(ctx, cfg)
	if err != nil {
		return nil, newErr(422, fmt.Sprintf("не удалось войти на узел %s: %v", p.Node, err), err)
	}
	defer cl.Close()
	tg := target.NewSSH(cl)
	r, err := tg.Exec(ctx, "uname -m")
	if err != nil {
		return nil, newErr(422, "не удалось определить архитектуру узла: "+err.Error(), err)
	}
	if arch := strings.TrimSpace(r.Stdout); arch != "x86_64" {
		return bad(fmt.Sprintf("архитектура узла %s — %s: поддерживается только x86_64", p.Node, arch))
	}

	stor, err := api.NodeStorage(ctx, p.Node)
	if err != nil {
		return nil, apiErr(err, secret)
	}
	for _, e := range RootStorages(stor) {
		res.Choices.Storages = append(res.Choices.Storages, StorageChoice{Name: e.Storage, Type: e.Type, Avail: e.Avail})
	}
	for _, e := range stor {
		if usable(e) && hasContent(e.Content, "vztmpl") {
			res.Choices.TemplateStorages = append(res.Choices.TemplateStorages, e.Storage)
		}
	}
	sort.Strings(res.Choices.TemplateStorages)
	def.Storage = PickRootStorage(stor, p.DiskGB)
	def.TemplateStorage = PickTemplateStorage(stor)
	p.Storage, p.TemplateStorage = def.Storage, def.TemplateStorage
	if req.Storage != "" {
		e, ok := findStorage(stor, req.Storage)
		switch {
		case !ok || !hasContent(e.Content, "rootdir"):
			return bad(fmt.Sprintf("хранилище %s не поддерживает диски контейнеров (rootdir)", req.Storage))
		case !usable(e):
			return bad(fmt.Sprintf("хранилище %s не активно", req.Storage))
		}
		p.Storage = req.Storage
	}
	if p.Storage == "" {
		return bad("нет хранилища с rootdir и достаточным свободным местом")
	}
	if e, _ := findStorage(stor, p.Storage); e.Avail < int64(p.DiskGB)<<30 {
		return bad(fmt.Sprintf("в хранилище %s свободно меньше %d ГБ", p.Storage, p.DiskGB))
	}
	if req.TemplateStorage != "" {
		e, ok := findStorage(stor, req.TemplateStorage)
		if !ok || !hasContent(e.Content, "vztmpl") || !usable(e) {
			return bad(fmt.Sprintf("хранилище %s не подходит для шаблонов (vztmpl)", req.TemplateStorage))
		}
		p.TemplateStorage = req.TemplateStorage
	}
	if p.TemplateStorage == "" {
		return bad("нет хранилища для шаблонов контейнеров (vztmpl)")
	}

	nets, err := api.Network(ctx, p.Node)
	if err != nil {
		return nil, apiErr(err, secret)
	}
	var defBridge string
	res.Choices.Bridges, defBridge = Bridges(nets)
	def.Bridge, p.Bridge = defBridge, defBridge
	if req.Bridge != "" {
		if !contains(res.Choices.Bridges, req.Bridge) {
			return bad(fmt.Sprintf("моста %s нет на узле %s", req.Bridge, p.Node))
		}
		p.Bridge = req.Bridge
	}
	if p.Bridge == "" {
		return bad(fmt.Sprintf("на узле %s нет сетевого моста", p.Node))
	}

	apl, err := api.AplInfo(ctx, p.Node)
	if err != nil {
		return nil, apiErr(err, secret)
	}
	tpl, ok := PickTemplate(apl)
	if !ok {
		return bad("в каталоге шаблонов Proxmox нет debian-13-standard (amd64)")
	}
	def.Template, p.Template = tpl.Template, tpl.Template
	vols, err := api.StorageContent(ctx, p.Node, p.TemplateStorage, "vztmpl")
	if err != nil {
		return nil, apiErr(err, secret)
	}
	for _, v := range vols {
		if v.VolID == templateVolID(p.TemplateStorage, tpl.Template) {
			p.TemplatePresent = true
		}
	}
	def.TemplatePresent = p.TemplatePresent

	if err := s.checkIP(ctx, &p, req, nets, t.ID, tg, res); err != nil {
		return nil, err
	}
	if p.Port = DefaultPort; req.Port != 0 && req.Port != DefaultPort {
		res.Warnings = append(res.Warnings, "Порт задаётся только для отдельного сервера: в контейнере Hestia слушает порт 80.")
	}
	def.Port = DefaultPort
	if p.IP == "dhcp" {
		res.Warnings = append(res.Warnings, "Адрес выдаст DHCP. После установки закрепите его в роутере (MikroTik: IP → DHCP Server → Leases → Make Static), чтобы адрес Hestia не менялся.")
	}
	res.Params, res.Defaults = p, def
	res.Plan = lxcPlan(p)
	return res, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func findStorage(l []proxmox.NodeStorageEntry, name string) (proxmox.NodeStorageEntry, bool) {
	for _, e := range l {
		if e.Storage == name {
			return e, true
		}
	}
	return proxmox.NodeStorageEntry{}, false
}

// checkIP validates the address mode. A static address must be well-formed,
// not used by a known guest and must not answer a ping from the node.
func (s *Service) checkIP(ctx context.Context, p *Params, req ProbeRequest, nets []proxmox.NetIface, targetID int64, tg *target.SSH, res *ProbeResult) error {
	ip := strings.TrimSpace(req.IP)
	if ip == "" || strings.EqualFold(ip, "dhcp") {
		p.IP = "dhcp"
		return nil
	}
	pfx, err := netip.ParsePrefix(ip)
	if err != nil || !pfx.Addr().Is4() {
		return newErr(422, "статический адрес: IPv4 с маской, например 192.168.1.20/24", nil)
	}
	addr := pfx.Addr()
	p.IP = pfx.String()
	p.Gateway = strings.TrimSpace(req.Gateway)
	if p.Gateway == "" {
		p.Gateway = BridgeGateway(nets, p.Bridge)
	}
	if p.Gateway != "" {
		gw, err := netip.ParseAddr(p.Gateway)
		if err != nil || !gw.Is4() {
			return newErr(422, "шлюз: IPv4-адрес", nil)
		}
		if !pfx.Masked().Contains(gw) {
			res.Warnings = append(res.Warnings, "Шлюз "+p.Gateway+" не входит в подсеть "+pfx.Masked().String()+".")
		}
	}
	if row, err := s.Store.GetInventory(ctx, targetID); err == nil && len(row.Data) > 0 {
		var snap inventory.Snapshot
		if json.Unmarshal(row.Data, &snap) == nil {
			for _, g := range snap.Guests {
				for _, gip := range g.IPs {
					if a, err := netip.ParseAddr(gip); err == nil && a == addr {
						return newErr(422, fmt.Sprintf("адрес %s уже занят гостем %s (VMID %d)", addr, g.Name, g.VMID), nil)
					}
				}
			}
		}
	}
	if _, err := tg.Exec(ctx, "ping -c1 -W1 "+addr.String()); err == nil {
		return newErr(422, fmt.Sprintf("адрес %s отвечает на ping — он занят", addr), nil)
	}
	return nil
}

func lxcPlan(p Params) []PlanItem {
	tpl := "Шаблон " + p.Template + " уже скачан в " + p.TemplateStorage
	tplDetail := "Скачивание не требуется."
	if !p.TemplatePresent {
		tpl = "Скачать шаблон " + p.Template
		tplDetail = "С серверов Proxmox в хранилище " + p.TemplateStorage + "; при ошибке скачанное удаляется."
	}
	ipMode := "DHCP"
	if p.IP != "dhcp" {
		ipMode = p.IP
		if p.Gateway != "" {
			ipMode += ", шлюз " + p.Gateway
		}
	}
	return append([]PlanItem{
		{"template", tpl, tplDetail},
		{"create", fmt.Sprintf("Создать контейнер %d (%s) на узле %s", p.VMID, p.Hostname, p.Node),
			fmt.Sprintf("Непривилегированный, nesting; %d vCPU, %d МБ RAM, %d МБ swap, диск %d ГБ на %s; сеть: мост %s, %s; автозапуск; метка hestia.",
				p.Cores, p.MemoryMB, p.SwapMB, p.DiskGB, p.Storage, p.Bridge, ipMode)},
		{"start", "Запустить контейнер и получить адрес", "Адрес и MAC покажем в конце; ждём адрес до 90 с."},
		{"unique", "Проверить уникальность контейнера", "machine-id не совпадает с узлом, есть SSH host keys (иначе создаются)."},
	}, commonPlan(p, true)...)
}

// commonPlan is the part of the plan executed on the machine that will run
// Hestia (inside the container or on the server itself).
func commonPlan(p Params, lxc bool) []PlanItem {
	port := p.Port
	if port == 0 {
		port = DefaultPort
	}
	where := "на сервере"
	if lxc {
		where = "в контейнере"
	}
	return []PlanItem{
		{"binary", "Установить Hestia " + where, fmt.Sprintf("Пользователь %s, каталог %s (0700), бинарник %s с проверкой sha256.", svcUser, dataPath, binPath)},
		{"unit", "Создать службу systemd", fmt.Sprintf("%s: порт %d, пользователь %s, автозапуск.", unitPath, port, svcUser)},
		{"state", "Перенести состояние", "Копия базы (цели, секреты, задачи) и мастер-ключ; на время переноса изменения в Hestia на этом ПК блокируются."},
		{"verify", "Запустить и проверить", "Hestia на новом месте должна ответить с тем же идентификатором экземпляра."},
		{"switch", "Переключить этот ПК на сервер", "Локальные база и ключ уходят в архив (каталог данных/archive), окно Hestia открывает сервер."},
	}
}

// ---- standalone server ----

func (s *Service) probeServer(ctx context.Context, req ProbeRequest, t store.Target) (*ProbeResult, error) {
	cl, err := s.Dial(ctx, sshx.Config{Host: t.Host, Port: t.Port, User: t.SSHUser, Signer: s.Identity.Signer, ExpectedFP: t.HostKeyFP})
	if err != nil {
		return nil, newErr(422, "не удалось войти на сервер: "+err.Error(), err)
	}
	defer cl.Close()
	tg := target.NewSSH(cl)
	facts, err := tg.Facts(ctx)
	if err != nil {
		return nil, newErr(422, "не удалось собрать данные сервера: "+err.Error(), err)
	}
	bad := func(msg string) (*ProbeResult, error) { return nil, newErr(422, msg, nil) }
	if !facts.IsRoot() && !facts.Sudo {
		return bad("нужен root или sudo без пароля")
	}
	if facts.Arch != "x86_64" {
		return bad(fmt.Sprintf("архитектура сервера — %s: поддерживается только x86_64", facts.Arch))
	}
	sh := serverShell(cl, facts.IsRoot())
	if _, err := sh(ctx, "systemctl --version", nil); err != nil {
		return bad("на сервере нет systemd")
	}
	res := &ProbeResult{Kind: KindServer, TargetID: t.ID, TargetName: t.Name, Warnings: []string{}, Plan: []PlanItem{},
		Choices: Choices{Nodes: []string{}, Storages: []StorageChoice{}, TemplateStorages: []string{}, Bridges: []string{}}}
	def := Params{Port: DefaultPort}
	busy := func(port int) (bool, error) {
		r, err := sh(ctx, fmt.Sprintf("ss -ltnH 'sport = :%d'", port), nil)
		if err != nil {
			return false, fmt.Errorf("не удалось проверить порт %d: %w", port, err)
		}
		return strings.TrimSpace(r.Stdout) != "", nil
	}
	busy80, err := busy(DefaultPort)
	if err != nil {
		return nil, newErr(422, err.Error(), err)
	}
	if busy80 {
		def.Port = FallbackPort
		res.Warnings = append(res.Warnings, fmt.Sprintf("Порт 80 на сервере занят — предлагаем порт %d.", FallbackPort))
	}
	port := def.Port
	if req.Port != 0 {
		if req.Port < 1 || req.Port > 65535 {
			return bad("порт: от 1 до 65535")
		}
		port = req.Port
	}
	if port != DefaultPort {
		if busy80, err = busy(port); err != nil {
			return nil, newErr(422, err.Error(), err)
		}
	}
	if busy80 {
		return bad(fmt.Sprintf("порт %d на сервере занят — выберите другой (например, %d)", port, FallbackPort))
	}
	if r, err := sh(ctx, fmt.Sprintf("test -e %s -o -e %s -o -e %s && echo yes", binPath, unitPath, dataPath), nil); err == nil && strings.TrimSpace(r.Stdout) == "yes" {
		return bad("Hestia уже установлена на этом сервере (найден " + binPath + ", " + unitPath + " или " + dataPath + ") — Hestia ничего не перезаписывает")
	}
	res.Params = Params{Port: port}
	res.Defaults = def
	res.Plan = commonPlan(res.Params, false)
	if !facts.IsRoot() {
		res.Warnings = append(res.Warnings, "Вход не от root: команды будут выполняться через sudo без пароля.")
	}
	return res, nil
}

// serverShell runs a script on the server (through sudo when not root).
func serverShell(cl *sshx.Client, root bool) func(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
	return func(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
		cmd := "sh -c " + target.Quote(script)
		if !root {
			cmd = "sudo -n " + cmd
		}
		return cl.Exec(ctx, cmd, stdin)
	}
}
