package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func releaseDir(t *testing.T) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for n, c := range map[string]string{ServerAsset: "server-binary", DesktopAsset: "desktop-binary"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := SignDir(priv, dir); err != nil {
		t.Fatal(err)
	}
	return dir, pub, priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	dir, pub, _ := releaseDir(t)
	if err := VerifyDir(pub, dir); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(dir, SumsName))
	if !strings.Contains(string(sums), "  "+ServerAsset+"\n") || !strings.Contains(string(sums), "  "+DesktopAsset+"\n") {
		t.Fatalf("sums: %s", sums)
	}
	// another key must not verify
	other, _, _ := GenerateKey()
	if err := VerifyDir(other, dir); err == nil {
		t.Fatal("verified with a foreign key")
	}
}

func TestTamperingIsRefused(t *testing.T) {
	for _, name := range []string{SumsName, SigName, ServerAsset, DesktopAsset} {
		t.Run(name, func(t *testing.T) {
			dir, pub, _ := releaseDir(t)
			p := filepath.Join(dir, name)
			b, _ := os.ReadFile(p)
			// flip one bit of the first byte
			b[0] ^= 1
			if err := os.WriteFile(p, b, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := VerifyDir(pub, dir); err == nil {
				t.Fatalf("tampered %s accepted", name)
			}
		})
	}
	t.Run("missing signature", func(t *testing.T) {
		dir, pub, _ := releaseDir(t)
		_ = os.Remove(filepath.Join(dir, SigName))
		if VerifyDir(pub, dir) == nil {
			t.Fatal("accepted without a signature")
		}
	})
	t.Run("appended line", func(t *testing.T) {
		dir, pub, _ := releaseDir(t)
		p := filepath.Join(dir, SumsName)
		b, _ := os.ReadFile(p)
		_ = os.WriteFile(p, append(b, []byte(strings.Repeat("0", 64)+"  evil\n")...), 0o644)
		if VerifyDir(pub, dir) == nil {
			t.Fatal("accepted modified SUMS")
		}
	})
}

func TestEveryByteOfSigMatters(t *testing.T) {
	_, pub, priv := releaseDir(t)
	sums := SumsFile(map[string][]byte{"a": []byte("x")})
	sig := SignSums(priv, sums)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	for i := range raw {
		c := append([]byte(nil), raw...)
		c[i] ^= 0x80
		if _, err := VerifySums(pub, sums, []byte(base64.StdEncoding.EncodeToString(c))); err == nil {
			t.Fatalf("byte %d of the signature does not matter", i)
		}
	}
}

func TestKeyParsing(t *testing.T) {
	if _, err := ParsePublicKey(" \n"); err != ErrNotConfigured {
		t.Fatalf("empty key: %v", err)
	}
	if _, err := ParsePublicKey("not base64!"); err == nil {
		t.Fatal("garbage accepted")
	}
	pub, priv, _ := GenerateKey()
	got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatal("public key round trip")
	}
	pk, err := ParsePrivateKey(EncodePrivateKey(priv))
	if err != nil || !pk.Equal(priv) {
		t.Fatal("private key round trip")
	}
	if _, err := ParsePrivateKey([]byte("AAAA")); err == nil {
		t.Fatal("short private key accepted")
	}
}

// The repository ships an empty release.pub until the maintainer creates a key.
func TestEmbeddedKeyUnconfigured(t *testing.T) {
	if strings.TrimSpace(ReleasePub) != "" {
		t.Skip("release.pub is set in this checkout")
	}
	if _, err := EmbeddedKey(); err != ErrNotConfigured {
		t.Fatalf("got %v", err)
	}
}

func TestParseSumsRejects(t *testing.T) {
	for _, in := range []string{"abc  file\n", strings.Repeat("g", 64) + "  f\n", strings.Repeat("0", 64) + "  ../f\n", strings.Repeat("0", 64) + " f\n",
		strings.Repeat("0", 64) + "  f\n" + strings.Repeat("1", 64) + "  f\n"} {
		if _, err := ParseSums([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}
