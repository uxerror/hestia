package plugins

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/update"
	"github.com/uxerror/hestia/internal/version"
	"github.com/uxerror/hestia/sdk"
)

// The official catalog is the GitHub release with the permanent tag
// "plugins-catalog": index.json, its signature by the official plugin key
// (index.json.sig, base64 ed25519 of the whole file) and the packages.
const (
	CatalogTag      = "plugins-catalog"
	CatalogIndex    = "index.json"
	CatalogSig      = "index.json.sig"
	CatalogInterval = 24 * time.Hour
	catalogFirst    = time.Minute
	maxIndex        = 1 << 20
	catalogTimeout  = time.Minute
)

var (
	reVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	reSHA256  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CatalogEntry is a plugin of the catalog.
type CatalogEntry struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	MinHestia   string     `json:"min_hestia,omitempty"`
	URL         string     `json:"url"`
	SHA256      string     `json:"sha256"`
	Size        int64      `json:"size"`
	Permissions []string   `json:"permissions"`
	Provides    []sdk.Port `json:"provides"`
	Requires    []sdk.Port `json:"requires"`
}

// CatalogIndexFile is index.json.
type CatalogIndexFile struct {
	Generated string         `json:"generated"`
	Plugins   []CatalogEntry `json:"plugins"`
}

// SignIndex signs index.json; the result is the content of index.json.sig.
func SignIndex(priv ed25519.PrivateKey, index []byte) []byte {
	return update.SignSums(priv, index)
}

// VerifyIndex checks the signature of index.json with pub and parses it.
func VerifyIndex(pub ed25519.PublicKey, index, sig []byte) (*CatalogIndexFile, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("в этой сборке Hestia нет ключа официальных плагинов: каталог недоступен")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, index, raw) {
		return nil, errors.New("подпись каталога неверна: каталог не показывается")
	}
	return ParseIndex(index)
}

// ParseIndex decodes index.json and checks every entry.
func ParseIndex(index []byte) (*CatalogIndexFile, error) {
	var f CatalogIndexFile
	if err := json.Unmarshal(index, &f); err != nil {
		return nil, fmt.Errorf("index.json не разбирается: %v", err)
	}
	seen := map[string]bool{}
	for i := range f.Plugins {
		e := &f.Plugins[i]
		if err := checkEntry(*e); err != nil {
			return nil, fmt.Errorf("index.json: %s: %v", e.ID, err)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("index.json: %s указан дважды", e.ID)
		}
		seen[e.ID] = true
		e.Permissions, e.Provides, e.Requires = nonNil(e.Permissions), nonNilPorts(e.Provides), nonNilPorts(e.Requires)
	}
	if f.Plugins == nil {
		f.Plugins = []CatalogEntry{}
	}
	return &f, nil
}

func checkEntry(e CatalogEntry) error {
	u, err := url.Parse(e.URL)
	switch {
	case !reID.MatchString(e.ID):
		return errors.New("неверный id")
	case !reVersion.MatchString(e.Version):
		return errors.New("неверная версия")
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil:
		return errors.New("неверная ссылка на пакет")
	case !reSHA256.MatchString(e.SHA256):
		return errors.New("неверный sha256")
	case e.Size <= 0 || e.Size > MaxPackage:
		return errors.New("неверный размер")
	case e.MinHestia != "" && !reVersion.MatchString(e.MinHestia):
		return errors.New("неверная min_hestia")
	}
	for _, p := range e.Permissions {
		if !slices.Contains(Permissions, p) {
			return fmt.Errorf("неизвестное право %q", p)
		}
	}
	return nil
}

// EntryFromPackage describes a verified package for the catalog.
func EntryFromPackage(pkg *Package, url string) CatalogEntry {
	m := pkg.Manifest
	return CatalogEntry{ID: m.ID, Name: m.Name, Version: m.Version, Description: m.Description, MinHestia: m.MinHestia,
		URL: url, SHA256: pkg.SHA256, Size: pkg.Size, Permissions: nonNil(m.Permissions),
		Provides: nonNilPorts(m.Provides), Requires: nonNilPorts(m.Requires)}
}

// AddToIndex adds or replaces the entry of e.ID (a lower version is
// refused), sorts by id and stamps the time.
func AddToIndex(f *CatalogIndexFile, e CatalogEntry, now time.Time) error {
	for i, old := range f.Plugins {
		if old.ID != e.ID {
			continue
		}
		a, _ := version.Parse(old.Version)
		b, _ := version.Parse(e.Version)
		if version.Compare(b, a) < 0 {
			return fmt.Errorf("в каталоге уже %s %s — новее, чем %s", e.ID, old.Version, e.Version)
		}
		f.Plugins[i] = e
		e.ID = ""
		break
	}
	if e.ID != "" {
		f.Plugins = append(f.Plugins, e)
	}
	sort.Slice(f.Plugins, func(i, j int) bool { return f.Plugins[i].ID < f.Plugins[j].ID })
	f.Generated = now.UTC().Format(time.RFC3339)
	return nil
}

// ---- the controller side ----

// CatalogItem is a catalog entry as GET /plugins/catalog shows it.
type CatalogItem struct {
	CatalogEntry
	Installed  string   `json:"installed"`        // installed version ("" if not)
	Update     bool     `json:"update"`           // the catalog has a newer version
	Compatible bool     `json:"compatible"`       // min_hestia is satisfied
	Reason     string   `json:"reason,omitempty"` // why it cannot be installed
	NewPerms   []string `json:"new_permissions"`  // for an update
}

// CatalogView is GET /plugins/catalog.
type CatalogView struct {
	FetchedAt *time.Time    `json:"fetched_at"`
	Generated string        `json:"generated"`
	Error     string        `json:"error"`
	Plugins   []CatalogItem `json:"plugins"`
}

// officialPub is the key the catalog is checked with (tests replace
// OfficialPub).
func officialPub() ed25519.PublicKey { return officialKey() }

// RefreshCatalog downloads and verifies the catalog now. A failure is
// recorded in the state (and returned): a network error keeps the last good
// catalog, a bad signature drops it.
func (m *Manager) RefreshCatalog(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()
	now := m.Now().UTC()
	idx, keep, err := m.fetchCatalog(ctx)
	prev, gerr := m.Store.GetPluginCatalog(ctx)
	if gerr != nil {
		return gerr
	}
	st := store.PluginCatalog{FetchedAt: &now}
	switch {
	case err == nil:
		st.IndexJSON = string(idx)
	case keep:
		st.IndexJSON, st.FetchedAt = prev.IndexJSON, prev.FetchedAt
		st.Error = "Не удалось обновить каталог: " + err.Error()
	default:
		st.Error = err.Error()
	}
	if serr := m.Store.SetPluginCatalog(context.WithoutCancel(ctx), st); serr != nil {
		return serr
	}
	if err != nil {
		slog.Warn("каталог плагинов", "err", err)
	}
	return err
}

// fetchCatalog returns the verified index.json; keep says the failure is
// transient (the cached catalog stays valid).
func (m *Manager) fetchCatalog(ctx context.Context) ([]byte, bool, error) {
	pub := officialPub()
	if pub == nil {
		return nil, false, errors.New("в этой сборке Hestia нет ключа официальных плагинов: каталог недоступен")
	}
	rel, err := m.GitHub.ReleaseByTag(ctx, CatalogTag)
	if err != nil {
		return nil, true, err
	}
	ia, ok1 := rel.Assets[CatalogIndex]
	sa, ok2 := rel.Assets[CatalogSig]
	if !ok1 || !ok2 {
		return nil, true, fmt.Errorf("в релизе %s нет %s или %s", CatalogTag, CatalogIndex, CatalogSig)
	}
	idx, err := m.GitHub.Download(ctx, ia, maxIndex)
	if err != nil {
		return nil, true, err
	}
	sig, err := m.GitHub.Download(ctx, sa, 4<<10)
	if err != nil {
		return nil, true, err
	}
	if _, err := VerifyIndex(pub, idx, sig); err != nil {
		return nil, false, err
	}
	return idx, false, nil
}

// cachedIndex returns the cached verified catalog (nil if none).
func (m *Manager) cachedIndex(ctx context.Context) (*CatalogIndexFile, store.PluginCatalog, error) {
	c, err := m.Store.GetPluginCatalog(ctx)
	if err != nil || c.IndexJSON == "" {
		return nil, c, err
	}
	idx, err := ParseIndex([]byte(c.IndexJSON))
	if err != nil {
		return nil, c, nil
	}
	return idx, c, nil
}

// Catalog returns the cached catalog with what is installed.
func (m *Manager) Catalog(ctx context.Context) (CatalogView, error) {
	idx, c, err := m.cachedIndex(ctx)
	v := CatalogView{FetchedAt: c.FetchedAt, Error: c.Error, Plugins: []CatalogItem{}}
	if err != nil || idx == nil {
		return v, err
	}
	v.Generated = idx.Generated
	ps, err := m.Store.ListPlugins(ctx)
	if err != nil {
		return v, err
	}
	for _, e := range idx.Plugins {
		it := CatalogItem{CatalogEntry: e, Compatible: true, NewPerms: []string{}}
		if err := CheckMinHestia(sdk.Manifest{MinHestia: e.MinHestia}, m.Version); err != nil {
			it.Compatible, it.Reason = false, err.Error()
		}
		for _, p := range ps {
			if p.ID != e.ID {
				continue
			}
			it.Installed = p.Version
			if u := m.catalogUpdate(p, e); u != nil {
				it.Update, it.NewPerms = true, u.NewPermissions
			}
		}
		v.Plugins = append(v.Plugins, it)
	}
	return v, nil
}

// catalogUpdate is the update an installed official plugin has in the
// catalog (nil if none).
func (m *Manager) catalogUpdate(p store.Plugin, e CatalogEntry) *UpdateDiff {
	if p.Source == store.PluginSourceDev || !IsOfficialKey(p.AuthorKey) {
		return nil
	}
	a, ok1 := version.Parse(p.Version)
	b, ok2 := version.Parse(e.Version)
	if !ok1 || !ok2 || version.Compare(b, a) <= 0 {
		return nil
	}
	if CheckMinHestia(sdk.Manifest{MinHestia: e.MinHestia}, m.Version) != nil {
		return nil
	}
	old, _ := ParseManifest([]byte(p.Manifest))
	d := &UpdateDiff{From: p.Version, To: e.Version, NewPermissions: []string{}}
	for _, perm := range e.Permissions {
		if !slices.Contains(old.Permissions, perm) {
			d.NewPermissions = append(d.NewPermissions, perm)
		}
	}
	return d
}

// catalogUpdates maps plugin id → update for GET /plugins.
func (m *Manager) catalogUpdates(ctx context.Context, ps []store.Plugin) map[string]*UpdateDiff {
	out := map[string]*UpdateDiff{}
	idx, _, err := m.cachedIndex(ctx)
	if err != nil || idx == nil {
		return out
	}
	for _, p := range ps {
		for _, e := range idx.Plugins {
			if e.ID == p.ID {
				if u := m.catalogUpdate(p, e); u != nil {
					out[p.ID] = u
				}
			}
		}
	}
	return out
}

// FetchFromCatalog downloads the package of a catalog entry, checks its
// size and sha256 against the catalog and then as any package.
func (m *Manager) FetchFromCatalog(ctx context.Context, id string) (*Uploaded, error) {
	if ok, reason := m.Availability(ctx); !ok {
		return nil, newErr(http.StatusConflict, "%s", reason)
	}
	idx, _, err := m.cachedIndex(ctx)
	if err != nil {
		return nil, err
	}
	if idx == nil {
		return nil, newErr(http.StatusConflict, "Каталог ещё не загружен — обновите его")
	}
	var e *CatalogEntry
	for i := range idx.Plugins {
		if idx.Plugins[i].ID == id {
			e = &idx.Plugins[i]
		}
	}
	if e == nil {
		return nil, newErr(http.StatusNotFound, "плагина %s нет в каталоге", id)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return nil, newErr(http.StatusBadGateway, "неверная ссылка на пакет в каталоге")
	}
	req.Header.Set("User-Agent", "hestia-controller")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, newErr(http.StatusBadGateway, "не удалось скачать пакет: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, newErr(http.StatusBadGateway, "не удалось скачать пакет: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, e.Size+1))
	if err != nil {
		return nil, newErr(http.StatusBadGateway, "не удалось скачать пакет: %v", err)
	}
	sum := sha256.Sum256(data)
	if int64(len(data)) != e.Size || hex.EncodeToString(sum[:]) != e.SHA256 {
		return nil, newErr(http.StatusUnprocessableEntity, "пакет %s не совпадает с каталогом (размер или sha256): не устанавливается", e.ID)
	}
	up, err := m.receive(ctx, bytes.NewReader(data), store.PluginSourceCatalog)
	if err != nil {
		return nil, err
	}
	if up.Preview.ID != e.ID || up.Preview.Version != e.Version || !up.Preview.Author.Official {
		m.dropUpload(up.UploadID)
		return nil, newErr(http.StatusUnprocessableEntity, "пакет %s из каталога не совпадает с записью каталога или подписан не официальным ключом", e.ID)
	}
	return up, nil
}

// startCatalogChecks refreshes the catalog a minute after start and then
// once a day.
func (m *Manager) startCatalogChecks() {
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		d := catalogFirst
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(d):
			}
			_ = m.RefreshCatalog(m.ctx)
			d = CatalogInterval
		}
	}()
}
