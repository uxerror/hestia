package plugins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/update"
	"github.com/uxerror/hestia/sdk"
)

// Files of a package (.hpkg = tar.gz).
const (
	FileManifest = "manifest.json"
	FilePlugin   = "plugin"
	FileIcon     = "icon.svg"
	FileReadme   = "README.md"
	FileSums     = "SHA256SUMS"
	FileSig      = "SHA256SUMS.sig"
)

// Limits of a package.
const (
	MaxPackage  = 64 << 20 // all files together (and the compressed file)
	MaxIcon     = 64 << 10
	MaxReadme   = 256 << 10
	MaxManifest = 1 << 20
)

// contentFiles are covered by SHA256SUMS; required ones must be present.
var contentFiles = map[string]bool{FileManifest: true, FilePlugin: true, FileIcon: false, FileReadme: false}

// OfficialPub is the public key of official plugins (base64); empty until
// the maintainer has run `hestia-release keygen --pub
// internal/plugins/official.pub`. Tests replace it.
//
//go:embed official.pub
var OfficialPub string

// officialKey returns the embedded official key or nil.
func officialKey() ed25519.PublicKey {
	k, err := update.ParsePublicKey(OfficialPub)
	if err != nil {
		return nil
	}
	return k
}

// IsOfficialKey reports whether key (base64) is the official plugin key.
func IsOfficialKey(key string) bool {
	k := officialKey()
	return k != nil && strings.TrimSpace(key) == update.EncodePublicKey(k)
}

// Package is a verified plugin package.
type Package struct {
	Manifest    sdk.Manifest
	ManifestRaw []byte
	Binary      []byte
	Icon        []byte // sanitised, may be nil
	Readme      string
	Size        int64  // size of the .hpkg file
	SHA256      string // of the .hpkg file
	Official    bool
}

// PackageError is a rejected package (the message is for the user).
type PackageError struct{ Msg string }

func (e *PackageError) Error() string { return e.Msg }

func pkgErr(format string, args ...any) error {
	return &PackageError{Msg: fmt.Sprintf(format, args...)}
}

// ReadPackage unpacks and verifies a package: only the listed regular
// files, no paths, no links, at most MaxPackage bytes; SHA256SUMS signed by
// the author key of the manifest; a valid manifest; a static linux/amd64
// binary. Any mismatch rejects the whole package. hestiaVersion is used for
// min_hestia.
func ReadPackage(data []byte, hestiaVersion string) (*Package, error) {
	if int64(len(data)) > MaxPackage {
		return nil, pkgErr("пакет больше 64 МБ")
	}
	files, err := untar(data)
	if err != nil {
		return nil, err
	}
	for name, required := range contentFiles {
		if _, ok := files[name]; required && !ok {
			return nil, pkgErr("в пакете нет %s", name)
		}
	}
	sums, ok := files[FileSums]
	if !ok {
		return nil, pkgErr("пакет не подписан: нет %s", FileSums)
	}
	sig, ok := files[FileSig]
	if !ok {
		return nil, pkgErr("пакет не подписан: нет %s", FileSig)
	}
	if len(files[FileManifest]) > MaxManifest {
		return nil, pkgErr("manifest.json больше 1 МБ")
	}
	m, err := ParseManifest(files[FileManifest])
	if err != nil {
		return nil, err
	}
	pub, err := authorKey(m.Author.Key)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, sums, raw) {
		return nil, pkgErr("подпись пакета неверна: пакет изменён или подписан другим ключом")
	}
	parsed, err := update.ParseSums(sums)
	if err != nil {
		return nil, pkgErr("%v", err)
	}
	// SHA256SUMS lists exactly the content files of the package.
	for name := range files {
		if name == FileSums || name == FileSig {
			continue
		}
		if err := update.CheckAsset(parsed, name, files[name]); err != nil {
			return nil, pkgErr("%v", err)
		}
	}
	for name := range parsed {
		if _, ok := files[name]; !ok || name == FileSums || name == FileSig {
			return nil, pkgErr("SHA256SUMS упоминает %s, которого нет в пакете", name)
		}
	}
	official := IsOfficialKey(m.Author.Key)
	if strings.HasPrefix(m.ID, "hestia-") && !official {
		return nil, pkgErr("идентификатор с префиксом hestia- зарезервирован за официальными плагинами")
	}
	if err := CheckMinHestia(m, hestiaVersion); err != nil {
		return nil, err
	}
	if err := selfinstall.ValidateServerBinary(files[FilePlugin]); err != nil {
		return nil, pkgErr("исполняемый файл плагина: %v", err)
	}
	p := &Package{
		Manifest: m, ManifestRaw: files[FileManifest], Binary: files[FilePlugin],
		Readme: string(files[FileReadme]), Size: int64(len(data)), Official: official,
	}
	if len(p.Readme) > MaxReadme {
		return nil, pkgErr("README.md больше 256 КБ")
	}
	if icon, ok := files[FileIcon]; ok {
		if len(icon) > MaxIcon {
			return nil, pkgErr("icon.svg больше 64 КБ")
		}
		clean, err := SanitizeSVG(icon)
		if err != nil {
			return nil, pkgErr("icon.svg: %v", err)
		}
		p.Icon = clean
	}
	sum := sha256.Sum256(data)
	p.SHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

func authorKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, pkgErr("в манифесте нет ключа автора (author.key, ed25519 в base64)")
	}
	return ed25519.PublicKey(b), nil
}

// untar reads the archive with every restriction of the format.
func untar(data []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, pkgErr("это не пакет плагина (ожидается tar.gz)")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, pkgErr("архив пакета повреждён")
		}
		name := h.Name
		switch {
		case strings.ContainsAny(name, `/\`) || strings.Contains(name, ".."):
			return nil, pkgErr("недопустимый путь в пакете: %q", name)
		case h.Typeflag != tar.TypeReg:
			return nil, pkgErr("в пакете допустимы только обычные файлы: %q", name)
		}
		if _, known := contentFiles[name]; !known && name != FileSums && name != FileSig {
			return nil, pkgErr("лишний файл в пакете: %q", name)
		}
		if _, dup := files[name]; dup {
			return nil, pkgErr("файл %q в пакете дважды", name)
		}
		if h.Size < 0 || total+h.Size > MaxPackage {
			return nil, pkgErr("содержимое пакета больше 64 МБ")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil {
			return nil, pkgErr("архив пакета повреждён")
		}
		if int64(len(b)) != h.Size {
			return nil, pkgErr("архив пакета повреждён")
		}
		total += h.Size
		files[name] = b
	}
	return files, nil
}

// PackName is the file name of a package.
func PackName(m sdk.Manifest) string {
	return m.ID + "-" + m.Version + "-linux-amd64.hpkg"
}

// Pack builds and signs a package from files (name → content): SHA256SUMS
// and its signature are added. The manifest must carry the signing key.
func Pack(priv ed25519.PrivateKey, files map[string][]byte) ([]byte, error) {
	m, err := ParseManifest(files[FileManifest])
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if strings.TrimSpace(m.Author.Key) != update.EncodePublicKey(pub) {
		return nil, fmt.Errorf("author.key в manifest.json не совпадает с ключом подписи (%s): впишите ключ и пересоберите плагин — манифест вшит в бинарник", update.EncodePublicKey(pub))
	}
	content := map[string][]byte{}
	for name, b := range files {
		if _, ok := contentFiles[name]; !ok {
			return nil, fmt.Errorf("лишний файл %q", name)
		}
		content[name] = b
	}
	if _, ok := content[FilePlugin]; !ok {
		return nil, errors.New("нет исполняемого файла plugin")
	}
	sums := update.SumsFile(content)
	all := map[string][]byte{FileSums: sums, FileSig: update.SignSums(priv, sums)}
	for n, b := range content {
		all[n] = b
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{FileManifest, FilePlugin, FileIcon, FileReadme, FileSums, FileSig} {
		b, ok := all[name]
		if !ok {
			continue
		}
		mode := int64(0o644)
		if name == FilePlugin {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PackDir packs a plugin directory: `plugin` from dir; manifest.json,
// icon.svg and README.md from src (default dir).
func PackDir(priv ed25519.PrivateKey, dir, src string) ([]byte, sdk.Manifest, error) {
	if src == "" {
		src = dir
	}
	files := map[string][]byte{}
	read := func(d, name string, required bool) error {
		b, err := os.ReadFile(filepath.Join(d, name))
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil
		}
		if err != nil {
			return err
		}
		files[name] = b
		return nil
	}
	if err := read(dir, FilePlugin, true); err != nil {
		return nil, sdk.Manifest{}, err
	}
	for _, n := range []string{FileManifest, FileIcon, FileReadme} {
		d := src
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			d = dir
		}
		if err := read(d, n, n == FileManifest); err != nil {
			return nil, sdk.Manifest{}, err
		}
	}
	m, err := ParseManifest(files[FileManifest])
	if err != nil {
		return nil, m, err
	}
	b, err := Pack(priv, files)
	return b, m, err
}

// Fingerprint renders the SHA-256 of an author key as hex in groups of four.
func Fingerprint(key string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	h := hex.EncodeToString(sum[:])
	var parts []string
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, " ")
}
