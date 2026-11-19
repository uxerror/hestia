package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/testelf"
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
