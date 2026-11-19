package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
	"github.com/uxerror/hestia/internal/version"
	"github.com/uxerror/hestia/sdk"
)

// Job kinds.
const (
	JobInstall = "plugin-install"
	JobEnable  = "plugin-enable"
	JobDisable = "plugin-disable"
	JobRemove  = "plugin-remove"
	JobApply   = "plugin-apply"
)

// Trust levels of a package author.
const (
	TrustOfficial = "official"
	TrustPinned   = "pinned"
	TrustNew      = "new"
)

// AuthorView describes the author of a package or plugin.
type AuthorView struct {
	Name        string `json:"name"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	Trust       string `json:"trust,omitempty"`
	Official    bool   `json:"official"`
}

// UpdateDiff is "was → becomes" of an update.
type UpdateDiff struct {
	From           string   `json:"from"`
	To             string   `json:"to"`
	NewPermissions []string `json:"new_permissions"`
}

// Preview is what the user confirms before an install.
type Preview struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Description string      `json:"description"`
	Homepage    string      `json:"homepage"`
	Size        int64       `json:"size"`
	SHA256      string      `json:"sha256"`
	Permissions []string    `json:"permissions"`
	Provides    []sdk.Port  `json:"provides"`
	Requires    []sdk.Port  `json:"requires"`
	Author      AuthorView  `json:"author"`
	Update      *UpdateDiff `json:"update"`
	Readme      string      `json:"readme"`
}

// Uploaded is the answer to a package upload.
type Uploaded struct {
	UploadID string  `json:"upload_id"`
	Preview  Preview `json:"preview"`
}

type upload struct {
	path    string
	sha     string
	source  string
	preview Preview
	expires time.Time
}

// Upload stores a package sent by the user (source "file").
func (m *Manager) Upload(ctx context.Context, r io.Reader) (*Uploaded, error) {
	return m.receive(ctx, r, store.PluginSourceFile)
}

// Fetch downloads a package by an https link (source "url:<link>").
func (m *Manager) Fetch(ctx context.Context, link string) (*Uploaded, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, newErr(http.StatusBadRequest, "нужна ссылка https://…")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, newErr(http.StatusBadRequest, "неверная ссылка")
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, newErr(http.StatusBadGateway, "не удалось скачать пакет: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, newErr(http.StatusBadGateway, "не удалось скачать пакет: HTTP %d", resp.StatusCode)
	}
	return m.receive(ctx, resp.Body, "url:"+u.String())
}

// defaultHTTP follows only https redirects (GitHub release assets redirect
// to their storage) and never uses a proxy from the environment.
func defaultHTTP() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("слишком много перенаправлений")
			}
			if req.URL.Scheme != "https" {
				return errors.New("перенаправление не на https")
			}
			return nil
		},
	}
}

func (m *Manager) receive(ctx context.Context, r io.Reader, source string) (*Uploaded, error) {
	if ok, reason := m.Availability(ctx); !ok {
		return nil, newErr(http.StatusConflict, "%s", reason)
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxPackage+1))
	if err != nil {
		return nil, newErr(http.StatusBadRequest, "не удалось получить пакет: %v", err)
	}
	if int64(len(data)) > MaxPackage {
		return nil, newErr(http.StatusRequestEntityTooLarge, "пакет больше 64 МБ")
	}
	pkg, err := ReadPackage(data, m.Version)
	if err != nil {
		return nil, asUserErr(err)
	}
	pv, err := m.preview(ctx, pkg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.uploadDir(), 0o700); err != nil {
		return nil, err
	}
	id := randID()
	path := filepath.Join(m.uploadDir(), id+".hpkg")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.purgeLocked()
	m.uploads[id] = &upload{path: path, sha: pkg.SHA256, source: source, preview: *pv, expires: m.Now().Add(uploadTTL)}
	m.mu.Unlock()
	return &Uploaded{UploadID: id, Preview: *pv}, nil
}

func asUserErr(err error) error {
	var pe *PackageError
	if errors.As(err, &pe) {
		return newErr(http.StatusUnprocessableEntity, "%s", pe.Msg)
	}
	return err
}

func (m *Manager) purgeLocked() {
	now := m.Now()
	for id, u := range m.uploads {
		if now.After(u.expires) {
			_ = os.Remove(u.path)
			delete(m.uploads, id)
		}
	}
	for id, p := range m.plans {
		if now.After(p.expires) {
			delete(m.plans, id)
			if p.action == sdk.ActionCreate {
				_ = m.Store.DeleteInstance(context.Background(), p.instanceID)
			}
		}
	}
}

// preview checks the package against what is installed: the pinned author
// key, downgrade, new permissions.
func (m *Manager) preview(ctx context.Context, pkg *Package) (*Preview, error) {
	man := pkg.Manifest
	pv := &Preview{
		ID: man.ID, Name: man.Name, Version: man.Version, Description: man.Description, Homepage: man.Homepage,
		Size: pkg.Size, SHA256: pkg.SHA256, Permissions: nonNil(man.Permissions), Provides: nonNilPorts(man.Provides),
		Requires: nonNilPorts(man.Requires), Readme: pkg.Readme,
		Author: AuthorView{Name: man.Author.Name, Key: man.Author.Key, Fingerprint: Fingerprint(man.Author.Key), Official: pkg.Official},
	}
	switch _, err := m.Store.GetAuthor(ctx, man.Author.Key); {
	case pkg.Official:
		pv.Author.Trust = TrustOfficial
	case err == nil:
		pv.Author.Trust = TrustPinned
	case errors.Is(err, store.ErrNotFound):
		pv.Author.Trust = TrustNew
	default:
		return nil, err
	}
	cur, err := m.Store.GetPlugin(ctx, man.ID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cur.Source == store.PluginSourceDev) {
		return pv, nil
	}
	if err != nil {
		return nil, err
	}
	if cur.AuthorKey != man.Author.Key {
		return nil, newErr(http.StatusConflict, "Ключ автора изменился: плагин %s подписан другим ключом (%s). Обновление невозможно — удалите плагин и поставьте заново, если доверяете новому ключу.", man.ID, Fingerprint(man.Author.Key))
	}
	a, _ := version.Parse(cur.Version)
	b, _ := version.Parse(man.Version)
	switch c := version.Compare(a, b); {
	case c > 0:
		return nil, newErr(http.StatusConflict, "Установлена более новая версия %s (пакет — %s): понижение версии запрещено.", cur.Version, man.Version)
	case c == 0:
		return nil, newErr(http.StatusConflict, "Версия %s уже установлена.", cur.Version)
	}
	old, _ := ParseManifest([]byte(cur.Manifest))
	diff := &UpdateDiff{From: cur.Version, To: man.Version, NewPermissions: []string{}}
	for _, p := range man.Permissions {
		if !slices.Contains(old.Permissions, p) {
			diff.NewPermissions = append(diff.NewPermissions, p)
		}
	}
	pv.Update = diff
	return pv, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilPorts(s []sdk.Port) []sdk.Port {
	if s == nil {
		return []sdk.Port{}
	}
	return s
}

// InstallRequest confirms an upload.
type InstallRequest struct {
	UploadID    string `json:"upload_id"`
	TrustAuthor bool   `json:"trust_author"`
}

// Install starts the plugin-install job.
func (m *Manager) Install(ctx context.Context, req InstallRequest) (store.Job, error) {
	loc, err := m.location(ctx)
	if err != nil {
		return store.Job{}, err
	}
	if loc == nil {
		_, reason := m.Availability(ctx)
		return store.Job{}, newErr(http.StatusConflict, "%s", reason)
	}
	m.mu.Lock()
	m.purgeLocked()
	up := m.uploads[req.UploadID]
	m.mu.Unlock()
	if up == nil {
		return store.Job{}, newErr(http.StatusGone, "загруженный пакет не найден или устарел — загрузите его заново")
	}
	if up.preview.Author.Trust == TrustNew && !req.TrustAuthor {
		return store.Job{}, newErr(http.StatusBadRequest, "Подтвердите доверие автору")
	}
	id := up.preview.ID
	if err := m.lockPlugin(id); err != nil {
		return store.Job{}, err
	}
	title := "Установка плагина " + up.preview.Name + " " + up.preview.Version
	if up.preview.Update != nil {
		title = fmt.Sprintf("Обновление плагина %s: %s → %s", up.preview.Name, up.preview.Update.From, up.preview.Update.To)
	}
	in := &installer{m: m, up: up, loc: *loc, trust: req.TrustAuthor}
	job, err := m.Runner.Start(JobInstall, title, func(ctx context.Context, run *jobs.Run) error {
		defer m.unlockPlugin(id)
		defer m.dropUpload(req.UploadID)
		return in.run(ctx, run)
	})
	if err != nil {
		m.unlockPlugin(id)
	}
	return job, err
}

func (m *Manager) dropUpload(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u := m.uploads[id]; u != nil {
		_ = os.Remove(u.path)
		delete(m.uploads, id)
	}
}

func (m *Manager) lockPlugin(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.busy[id] {
		return newErr(http.StatusConflict, "с плагином %s уже выполняется задача", id)
	}
	m.busy[id] = true
	return nil
}

func (m *Manager) unlockPlugin(id string) {
	m.mu.Lock()
	delete(m.busy, id)
	m.mu.Unlock()
}

func (m *Manager) pendingPerms(id string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.pending[id]; p != nil {
		return p.perms
	}
	return nil
}

// installer is one plugin-install job.
type installer struct {
	m     *Manager
	up    *upload
	loc   selfinstall.Location
	trust bool

	run_        *jobs.Run
	pkg         *Package
	prev        *store.Plugin // installed version (update)
	sh          Shell
	sd          systemd
	token       string
	placed      bool // files of the new version are on the machine
	switched    bool // current points at the new version
	needRestart bool // the controller must restart to open the socket
}

func (in *installer) log(line string) { in.run_.Log("info", line) }

func (in *installer) run(ctx context.Context, run *jobs.Run) (err error) {
	in.run_ = run
	m := in.m
	if err := run.Step("Проверка пакета", in.verify); err != nil {
		return err
	}
	man := in.pkg.Manifest
	sh, err := m.Open(ctx, in.loc)
	if err != nil {
		return fmt.Errorf("root-доступ к машине контроллера: %w", err)
	}
	defer sh.Close()
	in.sh, in.sd = sh, systemd{sh: sh, l: layout{root: m.Root}}
	in.token = newToken()

	defer func() {
		m.mu.Lock()
		delete(m.pending, man.ID)
		m.mu.Unlock()
		if err != nil {
			in.rollback(context.WithoutCancel(ctx))
		}
		if in.needRestart {
			if rerr := in.sd.restartController(context.WithoutCancel(ctx)); rerr != nil {
				run.Log("error", "перезапуск контроллера: "+rerr.Error())
			} else {
				run.Log("warn", "Контроллер перезапустится через 5 секунд")
			}
		}
	}()
	if err := run.Step("Файлы плагина", in.place); err != nil {
		return err
	}
	if err := run.Step("Запуск", in.start); err != nil {
		return err
	}
	if err := run.Step("Подключение плагина", in.handshake); err != nil {
		return err
	}
	if in.prev != nil {
		if err := run.Step("Проверка экземпляров", in.checkInstances); err != nil {
			return err
		}
	}
	return run.Step("Запись в базу", in.commit)
}

func (in *installer) verify(ctx context.Context) error {
	data, err := os.ReadFile(in.up.path)
	if err != nil {
		return errors.New("загруженный пакет пропал — загрузите его заново")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != in.up.sha {
		return errors.New("пакет изменился после загрузки")
	}
	pkg, err := ReadPackage(data, in.m.Version)
	if err != nil {
		return err
	}
	// The checks of the preview again: the database may have changed.
	pv, err := in.m.preview(ctx, pkg)
	if err != nil {
		return err
	}
	if pv.Author.Trust == TrustNew && !in.trust {
		return errors.New("автор не подтверждён")
	}
	in.pkg = pkg
	if cur, err := in.m.Store.GetPlugin(ctx, pkg.Manifest.ID); err == nil && cur.Source != store.PluginSourceDev {
		in.prev = &cur
	}
	in.log(fmt.Sprintf("%s %s, автор %s (%s), sha256 %s…", pkg.Manifest.ID, pkg.Manifest.Version, pkg.Manifest.Author.Name, pv.Author.Trust, pkg.SHA256[:12]))
	return nil
}

func (in *installer) place(ctx context.Context) error {
	m, man, l := in.m, in.pkg.Manifest, in.sd.l
	vdir := l.versionDir(man.ID, man.Version)
	in.placed = true
	if _, err := in.sd.run(ctx, "mkdir -p "+l.q(vdir)+" && chmod 0755 "+l.q(pluginsDir)+" "+l.q(l.pluginDir(man.ID))+" "+l.q(vdir)); err != nil {
		return err
	}
	if err := in.sh.PutFile(ctx, in.log, l.p(vdir+"/"+FilePlugin), in.pkg.Binary, "0755", "root:root"); err != nil {
		return err
	}
	if err := in.sh.PutFile(ctx, in.log, l.p(vdir+"/"+FileManifest), in.pkg.ManifestRaw, "0644", "root:root"); err != nil {
		return err
	}
	tok := l.pluginDir(man.ID) + "/token"
	if in.prev != nil {
		if _, err := in.sd.run(ctx, "cp -p "+l.q(tok)+" "+l.q(tok+".prev")); err != nil {
			return err
		}
	}
	// The token goes through stdin, never through the command line or the log.
	if err := in.sh.PutFile(ctx, nil, l.p(tok), []byte(in.token), "0600", "root:root"); err != nil {
		return errors.New("запись токена не удалась")
	}
	if err := in.sd.prepare(ctx, in.log); err != nil {
		return err
	}
	if err := in.sd.sandbox(ctx, in.log, man.ID, slices.Contains(man.Permissions, sdk.PermNetOutbound)); err != nil {
		return err
	}
	if err := in.sd.daemonReload(ctx); err != nil {
		return err
	}
	m.ensureListener()
	if !m.Listening() {
		// The running controller was started before /run/hestia was open to
		// it (an installation older than plugins): one restart is needed.
		in.needRestart = true
		return errors.New(msgFirstRestart)
	}
	return nil
}

func (in *installer) start(ctx context.Context) error {
	m, man := in.m, in.pkg.Manifest
	m.mu.Lock()
	m.pending[man.ID] = &pendingInstall{version: man.Version, tokenHash: HashToken(in.token), perms: man.Permissions}
	m.mu.Unlock()
	if err := in.sd.switchCurrent(ctx, man.ID, man.Version); err != nil {
		return err
	}
	in.switched = true
	if in.prev != nil {
		return in.sd.Restart(ctx, man.ID)
	}
	return in.sd.Enable(ctx, man.ID)
}

func (in *installer) handshake(ctx context.Context) error {
	m, man := in.m, in.pkg.Manifest
	wctx, cancel := context.WithTimeout(ctx, m.HelloTimeout)
	defer cancel()
	s, err := m.waitHelloVersion(wctx, man.ID, man.Version)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	cctx, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	if err := s.conn.Call(cctx, sdk.MethodManifest, struct{}{}, &raw); err != nil {
		return fmt.Errorf("манифест от процесса: %w", pluginErr(err))
	}
	if !sameJSON(raw, in.pkg.ManifestRaw) {
		return errors.New("манифест, который сообщил процесс, не совпадает с манифестом пакета")
	}
	in.log("Плагин подключился, манифест совпал")
	return nil
}

// waitHelloVersion waits for a connection of the given version (an update
// first sees the old process go away).
func (m *Manager) waitHelloVersion(ctx context.Context, id, ver string) (*session, error) {
	for {
		s, err := m.waitHello(ctx, id)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		v := s.version
		s.mu.Unlock()
		if v == ver {
			return s, nil
		}
		select {
		case <-s.conn.Done():
		case <-ctx.Done():
			return nil, fmt.Errorf("плагин не подключился за %s", m.HelloTimeout)
		}
	}
}

func (in *installer) checkInstances(ctx context.Context) error {
	list, err := in.m.Store.ListInstances(ctx, in.pkg.Manifest.ID, false)
	if err != nil {
		return err
	}
	for _, inst := range list {
		st, err := in.m.instanceStatus(ctx, in.pkg.Manifest.ID, inst)
		if err != nil {
			return fmt.Errorf("экземпляр «%s»: %w", inst.Name, err)
		}
		in.log(fmt.Sprintf("«%s»: %s %s", inst.Name, st.State, st.Detail))
	}
	return nil
}

func (in *installer) commit(ctx context.Context) error {
	m, pkg, man := in.m, in.pkg, in.pkg.Manifest
	p := store.Plugin{
		ID: man.ID, Version: man.Version, AuthorKey: man.Author.Key, Manifest: string(pkg.ManifestRaw),
		Source: in.up.source, Enabled: true, TokenHash: HashToken(in.token), Readme: pkg.Readme, Icon: string(pkg.Icon),
	}
	if in.prev != nil {
		p.PrevVersion, p.InstalledAt = in.prev.Version, in.prev.InstalledAt
	}
	author := &store.PluginAuthor{Key: man.Author.Key, Name: man.Author.Name, Official: pkg.Official}
	if err := m.Store.SavePlugin(ctx, p, author); err != nil {
		return err
	}
	// Keep one previous version; best effort.
	keep := []string{man.Version}
	if in.prev != nil {
		keep = append(keep, in.prev.Version)
	}
	dir := in.sd.l.pluginDir(man.ID)
	script := "cd " + in.sd.l.q(dir) + " && rm -f token.prev && for d in v*; do case \"$d\" in " +
		strings.Join(keep, "|") + ") ;; *) [ -d \"$d\" ] && rm -rf -- \"$d\" ;; esac; done; true"
	if _, err := in.sd.run(ctx, script); err != nil {
		in.log("не удалось убрать старые версии: " + err.Error())
	}
	return nil
}

// rollback returns the previous version (or removes a new install).
func (in *installer) rollback(ctx context.Context) {
	if in.pkg == nil || in.sh == nil || !in.placed {
		return
	}
	m, man, l := in.m, in.pkg.Manifest, in.sd.l
	in.run_.Log("warn", "Откат установки")
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if in.prev == nil {
		m.dropConn(man.ID)
		if err := in.sd.purge(ctx, man.ID); err != nil {
			in.run_.Log("error", "откат: "+err.Error())
		}
		return
	}
	dir := l.pluginDir(man.ID)
	tok := dir + "/token"
	steps := []string{
		"[ -f " + l.q(tok+".prev") + " ] && mv -f " + l.q(tok+".prev") + " " + l.q(tok) + " || true",
		"ln -sfn " + target.Quote(in.prev.Version) + " " + l.q(dir+"/current.new") + " && mv -Tf " + l.q(dir+"/current.new") + " " + l.q(dir+"/current"),
	}
	if in.prev.Version != man.Version {
		steps = append(steps, "rm -rf "+l.q(l.versionDir(man.ID, man.Version)))
	}
	prevMan, _ := ParseManifest([]byte(in.prev.Manifest))
	if err := in.sd.sandbox(ctx, in.log, man.ID, slices.Contains(prevMan.Permissions, sdk.PermNetOutbound)); err != nil {
		in.run_.Log("error", "откат: "+err.Error())
	}
	steps = append(steps, "systemctl daemon-reload")
	switch {
	case !in.switched:
		// The old process keeps running with the token it has loaded.
	case in.prev.Enabled:
		steps = append(steps, "systemctl restart "+unitName(man.ID))
	default:
		steps = append(steps, "systemctl disable --now "+unitName(man.ID)+" || true")
	}
	if _, err := in.sd.run(ctx, strings.Join(steps, "\n")); err != nil {
		in.run_.Log("error", "откат: "+err.Error())
		return
	}
	in.run_.Log("info", "Возвращена версия "+in.prev.Version)
}

func sameJSON(a, b []byte) bool {
	ca, err1 := canonical(a)
	cb, err2 := canonical(b)
	return err1 == nil && err2 == nil && bytes.Equal(ca, cb)
}

// canonical re-encodes JSON with sorted keys and exact numbers.
func canonical(b []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// ---- enable / disable / remove ----

// SetEnabled starts the enable or disable job.
func (m *Manager) SetEnabled(ctx context.Context, id string, on bool) (store.Job, error) {
	p, err := m.Store.GetPlugin(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Job{}, newErr(http.StatusNotFound, "плагин не найден")
	}
	if err != nil {
		return store.Job{}, err
	}
	if p.Source == store.PluginSourceDev {
		return store.Job{}, newErr(http.StatusConflict, "dev-плагин включается и выключается флагом --plugin-dev")
	}
	loc, err := m.location(ctx)
	if err != nil {
		return store.Job{}, err
	}
	if loc == nil {
		_, reason := m.Availability(ctx)
		return store.Job{}, newErr(http.StatusConflict, "%s", reason)
	}
	if err := m.lockPlugin(id); err != nil {
		return store.Job{}, err
	}
	kind, title := JobEnable, "Включение плагина "+id
	if !on {
		kind, title = JobDisable, "Отключение плагина "+id
	}
	job, err := m.Runner.Start(kind, title, func(ctx context.Context, run *jobs.Run) error {
		defer m.unlockPlugin(id)
		sh, err := m.Open(ctx, *loc)
		if err != nil {
			return fmt.Errorf("root-доступ к машине контроллера: %w", err)
		}
		defer sh.Close()
		sd := systemd{sh: sh, l: layout{root: m.Root}}
		if !on {
			if err := run.Step("Остановка", func(ctx context.Context) error { return sd.Disable(ctx, id) }); err != nil {
				return err
			}
			m.dropConn(id)
			return run.Step("Запись в базу", func(ctx context.Context) error { return m.Store.SetPluginEnabled(ctx, id, false) })
		}
		if err := run.Step("Запись в базу", func(ctx context.Context) error { return m.Store.SetPluginEnabled(ctx, id, true) }); err != nil {
			return err
		}
		if err := run.Step("Запуск", func(ctx context.Context) error { return sd.Enable(ctx, id) }); err != nil {
			_ = m.Store.SetPluginEnabled(context.WithoutCancel(ctx), id, false)
			return err
		}
		return run.Step("Подключение плагина", func(ctx context.Context) error {
			wctx, cancel := context.WithTimeout(ctx, m.HelloTimeout)
			defer cancel()
			_, err := m.waitHello(wctx, id)
			return err
		})
	})
	if err != nil {
		m.unlockPlugin(id)
	}
	return job, err
}

// Remove starts the plugin-remove job; a plugin with instances is refused.
func (m *Manager) Remove(ctx context.Context, id string) (store.Job, error) {
	p, err := m.Store.GetPlugin(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Job{}, newErr(http.StatusNotFound, "плагин не найден")
	}
	if err != nil {
		return store.Job{}, err
	}
	insts, err := m.Store.ListInstances(ctx, id, false)
	if err != nil {
		return store.Job{}, err
	}
	if len(insts) > 0 {
		e := newErr(http.StatusConflict, "Сначала удалите экземпляры плагина")
		for _, in := range insts {
			e.Instances = append(e.Instances, in.Name)
		}
		return store.Job{}, e
	}
	var loc *selfinstall.Location
	if p.Source != store.PluginSourceDev {
		if loc, err = m.location(ctx); err != nil {
			return store.Job{}, err
		}
		if loc == nil {
			_, reason := m.Availability(ctx)
			return store.Job{}, newErr(http.StatusConflict, "%s", reason)
		}
	}
	if err := m.lockPlugin(id); err != nil {
		return store.Job{}, err
	}
	job, err := m.Runner.Start(JobRemove, "Удаление плагина "+id, func(ctx context.Context, run *jobs.Run) error {
		defer m.unlockPlugin(id)
		if loc != nil {
			err := run.Step("Удаление с машины контроллера", func(ctx context.Context) error {
				sh, err := m.Open(ctx, *loc)
				if err != nil {
					return fmt.Errorf("root-доступ к машине контроллера: %w", err)
				}
				defer sh.Close()
				return systemd{sh: sh, l: layout{root: m.Root}}.purge(ctx, id)
			})
			if err != nil {
				return err
			}
		}
		m.dropConn(id)
		return run.Step("Запись в базу", func(ctx context.Context) error {
			if err := m.Store.DeleteSecretsByPrefix(ctx, pluginPrefix(id)); err != nil {
				return err
			}
			if err := m.Store.DeletePlugin(ctx, id); errors.Is(err, store.ErrDuplicate) {
				return errors.New("у плагина появились экземпляры — удаление отменено")
			} else if err != nil {
				return err
			}
			run.Log("info", "Ключ автора остаётся закреплённым (раздел «Авторы»)")
			return nil
		})
	})
	if err != nil {
		m.unlockPlugin(id)
	}
	return job, err
}

// UnitState asks systemd about the plugin's unit (only on request: it
// takes the root path).
func (m *Manager) UnitState(ctx context.Context, id string) (string, error) {
	loc, err := m.location(ctx)
	if err != nil || loc == nil {
		return "", errNoShell
	}
	sh, err := m.Open(ctx, *loc)
	if err != nil {
		return "", err
	}
	defer sh.Close()
	return systemd{sh: sh, l: layout{root: m.Root}}.Active(ctx, id)
}
