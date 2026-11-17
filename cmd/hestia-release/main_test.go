package main

import (
	"os"
	"path/filepath"
	"testing"
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
