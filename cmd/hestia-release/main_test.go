package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/testelf"
	"github.com/uxerror/hestia/internal/update"
)

func TestKeygenSignVerify(t *testing.T) {
	tmp := t.TempDir()
	key, pub := filepath.Join(tmp, "k", "release.key"), filepath.Join(tmp, "release.pub")
	if run([]string{"keygen", "--out", key, "--pub", pub}) != 0 {
		t.Fatal("keygen")
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(pub); len(b) < 40 {
		t.Fatalf("public key: %q", b)
	}
	// an existing key is never overwritten
	before, _ := os.ReadFile(key)
	if run([]string{"keygen", "--out", key, "--pub", pub}) == 0 {
		t.Fatal("keygen must refuse to overwrite")
	}
	if after, _ := os.ReadFile(key); string(after) != string(before) {
		t.Fatal("key changed")
	}

	dir := filepath.Join(tmp, "dist")
	_ = os.Mkdir(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "hestia-linux-amd64"), []byte("server"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "hestia-desktop-linux-amd64"), []byte("desktop"), 0o755)
	if run([]string{"sign", "--key", key, dir}) != 0 || run([]string{"verify", "--pub", pub, dir}) != 0 {
		t.Fatal("sign/verify")
	}
	// corruption → verify fails
	_ = os.WriteFile(filepath.Join(dir, "hestia-linux-amd64"), []byte("tampered"), 0o755)
	if run([]string{"verify", "--pub", pub, dir}) == 0 {
		t.Fatal("verify must fail after tampering")
	}
	// an empty public key means "not configured"
	_ = os.WriteFile(pub, nil, 0o644)
	if run([]string{"verify", "--pub", pub, dir}) == 0 {
		t.Fatal("verify with an empty key")
	}
	if run([]string{"nonsense"}) != 2 || run(nil) != 2 {
		t.Fatal("usage")
	}
}

func TestPluginPackVerify(t *testing.T) {
	tmp := t.TempDir()
	key, pub := filepath.Join(tmp, "plugins.key"), filepath.Join(tmp, "official.pub")
	if run([]string{"plugin-keygen", "--out", key, "--pub", pub}) != 0 {
		t.Fatal("plugin-keygen")
	}
	pubKey, _ := os.ReadFile(pub)
	build, src := filepath.Join(tmp, "build", "demo"), filepath.Join(tmp, "src")
	_ = os.MkdirAll(build, 0o755)
	_ = os.MkdirAll(src, 0o755)
	_ = os.WriteFile(filepath.Join(build, "plugin"), testelf.Build(testelf.Opts{}), 0o755)
	manifest := `{"protocol":1,"id":"demo","name":"Demo","version":"v0.1.0","description":"d",
		"author":{"name":"me","key":"` + strings.TrimSpace(string(pubKey)) + `"},"permissions":["targets.read"],
		"schema":{"fields":[]}}`
	_ = os.WriteFile(filepath.Join(src, "manifest.json"), []byte(manifest), 0o644)
	_ = os.WriteFile(filepath.Join(src, "README.md"), []byte("# Demo"), 0o644)
	out := filepath.Join(tmp, "dist")
	if run([]string{"plugin-pack", "--key", key, "--dir", build, "--src", src, "--out", out}) != 0 {
		t.Fatal("plugin-pack")
	}
	pkg := filepath.Join(out, "demo-v0.1.0-linux-amd64.hpkg")
	if run([]string{"plugin-verify", "--pub", pub, pkg}) != 0 {
		t.Fatal("plugin-verify")
	}
	// A tampered package fails.
	b, _ := os.ReadFile(pkg)
	b[len(b)/2] ^= 0xff
	_ = os.WriteFile(pkg, b, 0o644)
	if run([]string{"plugin-verify", "--pub", pub, pkg}) == 0 {
		t.Fatal("tampered package verified")
	}
	// A manifest without the signing key is refused by plugin-pack.
	_ = os.WriteFile(filepath.Join(src, "manifest.json"), []byte(strings.Replace(manifest, strings.TrimSpace(string(pubKey)), "", 1)), 0o644)
	if run([]string{"plugin-pack", "--key", key, "--dir", build, "--src", src, "--out", out}) == 0 {
		t.Fatal("plugin-pack without author.key")
	}
}

func TestCatalogAdd(t *testing.T) {
	tmp := t.TempDir()
	key, pub := filepath.Join(tmp, "plugins.key"), filepath.Join(tmp, "official.pub")
	if run([]string{"plugin-keygen", "--out", key, "--pub", pub}) != 0 {
		t.Fatal("plugin-keygen")
	}
	pubKey, _ := os.ReadFile(pub)
	out := filepath.Join(tmp, "dist")
	pack := func(id, ver, keyPath, author string) string {
		t.Helper()
		build, src := filepath.Join(tmp, "build", id+ver), filepath.Join(tmp, "src", id+ver)
		_ = os.MkdirAll(build, 0o755)
		_ = os.MkdirAll(src, 0o755)
		_ = os.WriteFile(filepath.Join(build, "plugin"), testelf.Build(testelf.Opts{}), 0o755)
		manifest := `{"protocol":1,"id":"` + id + `","name":"N","version":"` + ver + `","description":"d",
			"author":{"name":"me","key":"` + author + `"},"permissions":["targets.read"],"schema":{"fields":[]}}`
		_ = os.WriteFile(filepath.Join(src, "manifest.json"), []byte(manifest), 0o644)
		if run([]string{"plugin-pack", "--key", keyPath, "--dir", build, "--src", src, "--out", out, "--version", ver}) != 0 {
			t.Fatal("plugin-pack")
		}
		return filepath.Join(out, id+"-"+ver+"-linux-amd64.hpkg")
	}
	official := strings.TrimSpace(string(pubKey))
	zeta := pack("zeta", "v0.1.0", key, official)
	alpha := pack("alpha", "v0.1.0", key, official)
	index := filepath.Join(out, "index.json")
	if run([]string{"catalog-add", "--index", index, "--key", key, zeta, alpha}) != 0 {
		t.Fatal("catalog-add")
	}
	read := func() *plugins.CatalogIndexFile {
		t.Helper()
		b, _ := os.ReadFile(index)
		sig, _ := os.ReadFile(index + ".sig")
		k, err := update.ParsePublicKey(official)
		if err != nil {
			t.Fatal(err)
		}
		f, err := plugins.VerifyIndex(k, b, sig)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := read()
	if len(f.Plugins) != 2 || f.Plugins[0].ID != "alpha" || f.Plugins[1].ID != "zeta" || f.Generated == "" ||
		f.Plugins[0].URL != "https://github.com/uxerror/hestia/releases/download/plugins-catalog/alpha-v0.1.0-linux-amd64.hpkg" ||
		len(f.Plugins[0].SHA256) != 64 || f.Plugins[0].Size == 0 {
		t.Fatalf("%+v", f)
	}
	// A new version replaces the entry; the other one stays.
	zeta2 := pack("zeta", "v0.2.0", key, official)
	if run([]string{"catalog-add", "--index", index, "--key", key, "--url-base", "https://example.com/p/", zeta2}) != 0 {
		t.Fatal("catalog-add update")
	}
	f = read()
	if len(f.Plugins) != 2 || f.Plugins[1].Version != "v0.2.0" || f.Plugins[1].URL != "https://example.com/p/zeta-v0.2.0-linux-amd64.hpkg" ||
		f.Plugins[0].Version != "v0.1.0" {
		t.Fatalf("%+v", f.Plugins)
	}
	// A downgrade is refused and the index is left as it was.
	before, _ := os.ReadFile(index)
	if run([]string{"catalog-add", "--index", index, "--key", key, zeta}) == 0 {
		t.Fatal("downgrade accepted")
	}
	if after, _ := os.ReadFile(index); string(after) != string(before) {
		t.Fatal("index changed")
	}
	// A package signed by another key is refused.
	other, otherPub := filepath.Join(tmp, "other.key"), filepath.Join(tmp, "other.pub")
	if run([]string{"plugin-keygen", "--out", other, "--pub", otherPub}) != 0 {
		t.Fatal("keygen")
	}
	op, _ := os.ReadFile(otherPub)
	third := pack("third", "v0.1.0", other, strings.TrimSpace(string(op)))
	if run([]string{"catalog-add", "--index", index, "--key", key, third}) == 0 {
		t.Fatal("foreign package accepted")
	}
	// plugin-pack --version must match the manifest.
	build := filepath.Join(tmp, "build", "alphav0.1.0")
	if run([]string{"plugin-pack", "--key", key, "--dir", build, "--src", filepath.Join(tmp, "src", "alphav0.1.0"), "--out", out, "--version", "v9.9.9"}) == 0 {
		t.Fatal("version mismatch accepted")
	}
	// A tampered index fails verification.
	b, _ := os.ReadFile(index)
	_ = os.WriteFile(index, append(b, ' '), 0o644)
	sig, _ := os.ReadFile(index + ".sig")
	k, _ := update.ParsePublicKey(official)
	if _, err := plugins.VerifyIndex(k, append(b, ' '), sig); err == nil {
		t.Fatal("tampered index verified")
	}
}
