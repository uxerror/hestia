// Package update updates the installed controller: from the desktop app
// (offline, the binary comes from the app's payload) or from a signed GitHub
// release. The root-level work (replace the binary, restart, roll back) is done
// by upgrade.sh on the controller's machine.
package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Release asset names.
const (
	ServerAsset  = "hestia-linux-amd64"
	DesktopAsset = "hestia-desktop-linux-amd64"
	SumsName     = "SHA256SUMS"
	SigName      = "SHA256SUMS.sig"
)

// releaseAssets are the files SHA256SUMS covers.
var releaseAssets = []string{ServerAsset, DesktopAsset}

// ReleasePub is the public release key (base64, 32 bytes); empty until the
// maintainer has run `hestia-release keygen`.
//
//go:embed release.pub
var ReleasePub string

// ErrNotConfigured means the build carries no release key: the GitHub channel
// is switched off.
var ErrNotConfigured = errors.New("канал обновлений GitHub не настроен: в сборке нет публичного ключа релиза")

// ParsePublicKey decodes a base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNotConfigured
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("публичный ключ релиза повреждён")
	}
	return ed25519.PublicKey(b), nil
}

// EmbeddedKey returns the key built into this binary (ErrNotConfigured if none).
func EmbeddedKey() (ed25519.PublicKey, error) { return ParsePublicKey(ReleasePub) }

// GenerateKey creates a release key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePrivateKey / ParsePrivateKey store the private key as base64 text.
func EncodePrivateKey(k ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(k) + "\n")
}

// ParsePrivateKey is the reverse of EncodePrivateKey.
func ParsePrivateKey(b []byte) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("закрытый ключ релиза повреждён")
	}
	return ed25519.PrivateKey(raw), nil
}

// SumsFile renders SHA256SUMS (`<sha256>  <name>` per line, sorted by name).
func SumsFile(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(&sb, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	return []byte(sb.String())
}

// SignSums signs the whole SHA256SUMS file; the result is base64 text.
func SignSums(priv ed25519.PrivateKey, sums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
}

// ParseSums reads SHA256SUMS into name → hex sha256.
func ParseSums(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || name == "" || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("SHA256SUMS: неверная строка %q", line)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("SHA256SUMS: неверная строка %q", line)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("SHA256SUMS: %s указан дважды", name)
		}
		out[name] = strings.ToLower(sum)
	}
	return out, nil
}

// VerifySums checks the signature over the whole SHA256SUMS and returns its
// parsed content.
func VerifySums(pub ed25519.PublicKey, sums, sig []byte) (map[string]string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("подпись релиза повреждена")
	}
	if !ed25519.Verify(pub, sums, raw) {
		return nil, errors.New("подпись релиза не совпала с ключом Hestia")
	}
	return ParseSums(sums)
}

// CheckAsset compares data with the hash listed for name.
func CheckAsset(sums map[string]string, name string, data []byte) error {
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("в SHA256SUMS нет %s", name)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("контрольная сумма %s не совпала с SHA256SUMS", name)
	}
	return nil
}

// SignDir writes SHA256SUMS and SHA256SUMS.sig for the release assets in dir.
func SignDir(priv ed25519.PrivateKey, dir string) error {
	files := map[string][]byte{}
	for _, n := range releaseAssets {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return err
		}
		files[n] = b
	}
	sums := SumsFile(files)
	if err := os.WriteFile(filepath.Join(dir, SumsName), sums, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SigName), SignSums(priv, sums), 0o644)
}

// VerifyDir checks a release directory the way the controller does: the
// signature, then the hash of every asset.
func VerifyDir(pub ed25519.PublicKey, dir string) error {
	read := func(n string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, n)) }
	sums, err := read(SumsName)
	if err != nil {
		return err
	}
	sig, err := read(SigName)
	if err != nil {
		return err
	}
	parsed, err := VerifySums(pub, sums, sig)
	if err != nil {
		return err
	}
	for _, n := range releaseAssets {
		b, err := read(n)
		if err != nil {
			return err
		}
		if err := CheckAsset(parsed, n, b); err != nil {
			return err
		}
	}
	return nil
}

// EncodePublicKey is the base64 text form kept in release.pub.
func EncodePublicKey(k ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(k) }
