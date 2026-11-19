package plugins

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/update"
	"github.com/uxerror/hestia/sdk"
)

// fakeGitHub serves the release "plugins-catalog" and its assets.
type fakeGitHub struct {
	srv *httptest.Server

	mu     sync.Mutex
	assets map[string][]byte
	down   bool
	hits   []string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	g := &fakeGitHub{assets: map[string][]byte{}}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hits = append(g.hits, r.URL.Path)
	if g.down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == "/repos/uxerror/hestia/releases/tags/plugins-catalog" {
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int    `json:"size"`
		}
		var as []asset
		for n, b := range g.assets {
			as = append(as, asset{Name: n, URL: g.srv.URL + "/download/" + n, Size: len(b)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "plugins-catalog", "html_url": g.srv.URL, "assets": as})
		return
	}
	if n, ok := strings.CutPrefix(r.URL.Path, "/download/"); ok {
		if b, ok := g.assets[n]; ok {
			_, _ = w.Write(b)
			return
		}
	}
	http.NotFound(w, r)
}

func (g *fakeGitHub) set(name string, b []byte) {
	g.mu.Lock()
	g.assets[name] = b
	g.mu.Unlock()
}

// publish builds a signed index of the packages (like catalog-add).
func (g *fakeGitHub) publish(t *testing.T, key ed25519.PrivateKey, pkgs ...[]byte) *CatalogIndexFile {
	t.Helper()
	idx := &CatalogIndexFile{Plugins: []CatalogEntry{}}
	for _, b := range pkgs {
		p, err := ReadPackage(b, "")
		if err != nil {
			t.Fatal(err)
		}
		name := PackName(p.Manifest)
		g.set(name, b)
		if err := AddToIndex(idx, EntryFromPackage(p, g.srv.URL+"/download/"+name), time.Unix(1700000000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	g.setIndex(t, key, idx)
	return idx
}

func (g *fakeGitHub) setIndex(t *testing.T, key ed25519.PrivateKey, idx *CatalogIndexFile) {
	b, _ := json.MarshalIndent(idx, "", "  ")
	g.set(CatalogIndex, b)
	g.set(CatalogSig, SignIndex(key, b))
}

func withOfficial(t *testing.T, key ed25519.PrivateKey) {
	old := OfficialPub
	t.Cleanup(func() { OfficialPub = old })
	OfficialPub = pubOf(key)
}

func TestCatalogLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := newKey(t)
	withOfficial(t, key)
	g := newFakeGitHub(t)
	h.m.GitHub = &update.GitHub{BaseURL: g.srv.URL, HTTP: g.srv.Client()}
	h.m.HTTP = g.srv.Client()

	// Nothing fetched yet.
	v, err := h.m.Catalog(ctx)
	if err != nil || len(v.Plugins) != 0 || v.Error != "" || v.FetchedAt != nil {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := h.m.FetchFromCatalog(ctx, "demo"); err == nil {
		t.Fatal("install from an empty catalog")
	}

	v1 := pkgFor(t, key, "v0.1.0", sdk.PermTargetsRead)
	g.publish(t, key, v1)
	if err := h.m.RefreshCatalog(ctx); err != nil {
		t.Fatal(err)
	}
	v, _ = h.m.Catalog(ctx)
	if len(v.Plugins) != 1 || v.Plugins[0].ID != "demo" || v.Plugins[0].Installed != "" || !v.Plugins[0].Compatible ||
		v.Error != "" || v.FetchedAt == nil || v.Generated == "" {
		t.Fatalf("%+v", v)
	}

	// Install from the catalog.
	up, err := h.m.FetchFromCatalog(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if up.Preview.Author.Trust != TrustOfficial || up.Preview.Version != "v0.1.0" {
		t.Fatalf("%+v", up.Preview)
	}
	job, err := h.m.Install(ctx, InstallRequest{UploadID: up.UploadID})
	if err != nil {
		t.Fatal(err)
	}
	if j := h.wait(job.ID); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if p, _ := h.st.GetPlugin(ctx, "demo"); p.Source != store.PluginSourceCatalog {
		t.Fatalf("source %q", p.Source)
	}
	if _, err := h.m.FetchFromCatalog(ctx, "nope"); err == nil || err.(*Error).Status != 404 {
		t.Fatalf("%v", err)
	}

	// A newer version with a new permission: offered as an update.
	v2 := pkgFor(t, key, "v0.2.0", sdk.PermTargetsRead, sdk.PermDeployDocker)
	g.publish(t, key, v2)
	_ = h.m.RefreshCatalog(ctx)
	l, _ := h.m.List(ctx)
	if len(l.Plugins) != 1 || l.Plugins[0].Update == nil || l.Plugins[0].Update.To != "v0.2.0" ||
		strings.Join(l.Plugins[0].Update.NewPermissions, ",") != sdk.PermDeployDocker {
		t.Fatalf("%+v", l.Plugins)
	}
	v, _ = h.m.Catalog(ctx)
	if it := v.Plugins[0]; it.Installed != "v0.1.0" || !it.Update || len(it.NewPerms) != 1 {
		t.Fatalf("%+v", it)
	}
	if d, _ := h.m.Get(ctx, "demo", false); d.Update == nil {
		t.Fatal("no update on the plugin page")
	}

	// GitHub is down: the last good catalog stays, with an error.
	g.mu.Lock()
	g.down = true
	g.mu.Unlock()
	if err := h.m.RefreshCatalog(ctx); err == nil {
		t.Fatal("no error")
	}
	v, _ = h.m.Catalog(ctx)
	if len(v.Plugins) != 1 || !strings.Contains(v.Error, "Не удалось обновить каталог") {
		t.Fatalf("%+v", v)
	}
	g.mu.Lock()
	g.down = false
	g.mu.Unlock()

	// A wrong signature: the catalog is not shown, nor its updates.
	g.set(CatalogSig, SignIndex(newKey(t), g.assets[CatalogIndex]))
	if err := h.m.RefreshCatalog(ctx); err == nil || !strings.Contains(err.Error(), "подпись") {
		t.Fatalf("%v", err)
	}
	v, _ = h.m.Catalog(ctx)
	if len(v.Plugins) != 0 || !strings.Contains(v.Error, "подпись каталога неверна") {
		t.Fatalf("%+v", v)
	}
	if l, _ := h.m.List(ctx); l.Plugins[0].Update != nil {
		t.Fatal("update from a rejected catalog")
	}
	if _, err := h.m.FetchFromCatalog(ctx, "demo"); err == nil {
		t.Fatal("install from a rejected catalog")
	}
}

func TestCatalogPackageChecks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := newKey(t)
	withOfficial(t, key)
	g := newFakeGitHub(t)
	h.m.GitHub = &update.GitHub{BaseURL: g.srv.URL, HTTP: g.srv.Client()}
	h.m.HTTP = g.srv.Client()

	pkg := pkgFor(t, key, "v0.1.0")
	idx := g.publish(t, key, pkg)
	_ = h.m.RefreshCatalog(ctx)
	// The asset is replaced by another (validly signed) package: sha256 differs.
	g.set(PackName(sdk.Manifest{ID: "demo", Version: "v0.1.0"}), pkgFor(t, key, "v0.1.0", sdk.PermTargetsRead))
	if _, err := h.m.FetchFromCatalog(ctx, "demo"); err == nil || !strings.Contains(err.Error(), "не совпадает с каталогом") {
		t.Fatalf("%v", err)
	}

	// A package of another author listed in the official catalog.
	other := newKey(t)
	third := pkgFor(t, other, "v0.1.0")
	g.publish(t, key, third)
	_ = h.m.RefreshCatalog(ctx)
	if _, err := h.m.FetchFromCatalog(ctx, "demo"); err == nil || !strings.Contains(err.Error(), "не официальным") {
		t.Fatalf("%v", err)
	}

	// min_hestia newer than this Hestia.
	idx.Plugins[0].MinHestia = "v9.0.0"
	g.setIndex(t, key, idx)
	_ = h.m.RefreshCatalog(ctx)
	v, _ := h.m.Catalog(ctx)
	if v.Plugins[0].Compatible || !strings.Contains(v.Plugins[0].Reason, "v9.0.0") {
		t.Fatalf("%+v", v.Plugins[0])
	}

	// No official key in the build: the catalog is unavailable.
	OfficialPub = ""
	if err := h.m.RefreshCatalog(ctx); err == nil || !strings.Contains(err.Error(), "нет ключа") {
		t.Fatalf("%v", err)
	}
}

func TestIndexChecks(t *testing.T) {
	key := newKey(t)
	good := CatalogEntry{ID: "demo", Name: "Demo", Version: "v0.1.0", URL: "https://example.com/demo.hpkg",
		SHA256: strings.Repeat("a", 64), Size: 10, Permissions: []string{"targets.read"}}
	f := &CatalogIndexFile{}
	if err := AddToIndex(f, good, time.Now()); err != nil {
		t.Fatal(err)
	}
	zz := good
	zz.ID = "aaa"
	_ = AddToIndex(f, zz, time.Now())
	if f.Plugins[0].ID != "aaa" || len(f.Plugins) != 2 {
		t.Fatalf("not sorted: %+v", f.Plugins)
	}
	newer := good
	newer.Version = "v0.2.0"
	if err := AddToIndex(f, newer, time.Now()); err != nil || len(f.Plugins) != 2 || f.Plugins[1].Version != "v0.2.0" {
		t.Fatalf("%v %+v", err, f.Plugins)
	}
	if err := AddToIndex(f, good, time.Now()); err == nil {
		t.Fatal("downgrade accepted")
	}
	b, _ := json.Marshal(f)
	if _, err := VerifyIndex(key.Public().(ed25519.PublicKey), b, SignIndex(key, b)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIndex(key.Public().(ed25519.PublicKey), append(b, ' '), SignIndex(key, b)); err == nil {
		t.Fatal("modified index accepted")
	}
	if _, err := VerifyIndex(nil, b, SignIndex(key, b)); err == nil {
		t.Fatal("no key accepted")
	}
	for name, mod := range map[string]func(e *CatalogEntry){
		"id":      func(e *CatalogEntry) { e.ID = "Bad" },
		"version": func(e *CatalogEntry) { e.Version = "1.0" },
		"url":     func(e *CatalogEntry) { e.URL = "file:///etc/passwd" },
		"sha":     func(e *CatalogEntry) { e.SHA256 = "zz" },
		"size":    func(e *CatalogEntry) { e.Size = MaxPackage + 1 },
		"perm":    func(e *CatalogEntry) { e.Permissions = []string{"root"} },
	} {
		e := good
		mod(&e)
		b, _ := json.Marshal(CatalogIndexFile{Plugins: []CatalogEntry{e}})
		if _, err := ParseIndex(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dup, _ := json.Marshal(CatalogIndexFile{Plugins: []CatalogEntry{good, good}})
	if _, err := ParseIndex(dup); err == nil || errors.Is(err, nil) {
		t.Fatal("duplicate accepted")
	}
}
