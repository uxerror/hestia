package plugins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/testelf"
	"github.com/uxerror/hestia/internal/update"
	"github.com/uxerror/hestia/sdk"
)

func newKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pubOf(k ed25519.PrivateKey) string {
	return update.EncodePublicKey(k.Public().(ed25519.PublicKey))
}

// testManifest returns a valid manifest signed by key.
func testManifest(key ed25519.PrivateKey, mod func(*sdk.Manifest)) []byte {
	m := sdk.Manifest{
		Protocol: 1, ID: "demo", Name: "Demo", Version: "v0.1.0", Description: "test",
		Author:      sdk.Author{Name: "Tester", Key: pubOf(key)},
		Permissions: []string{sdk.PermTargetsRead, sdk.PermTargetsExec},
		Provides:    []sdk.Port{{Type: "demo.hello"}}, MultiInstance: true,
		Schema: sdk.Schema{Fields: []sdk.Field{
			{Name: "target", Type: sdk.FieldTarget, Label: "Где", Required: true},
			{Name: "message", Type: sdk.FieldString, Label: "Текст", Default: "hi", MaxLen: 20},
		}},
	}
	if mod != nil {
		mod(&m)
	}
	b, _ := json.Marshal(m)
	return b
}

func testPackage(t testing.TB, key ed25519.PrivateKey, mod func(*sdk.Manifest)) []byte {
	t.Helper()
	b, err := Pack(key, map[string][]byte{
		FileManifest: testManifest(key, mod),
		FilePlugin:   testelf.Build(testelf.Opts{Payload: []byte("plugin")}),
		FileReadme:   []byte("# Demo\n"),
		FileIcon:     []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="x()"><script>x()</script><rect width="1" height="1"/></svg>`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type tarFile struct {
	name string
	data []byte
	typ  byte
	link string
}

func rawTar(t testing.TB, files []tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		typ := f.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: typ, Linkname: f.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write(f.data)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// signedFiles returns the files of a valid package (with sums and sig).
func signedFiles(t testing.TB, key ed25519.PrivateKey, extra map[string][]byte) []tarFile {
	content := map[string][]byte{
		FileManifest: testManifest(key, nil),
		FilePlugin:   testelf.Build(testelf.Opts{}),
	}
	for k, v := range extra {
		content[k] = v
	}
	sums := update.SumsFile(content)
	var out []tarFile
	for n, b := range content {
		out = append(out, tarFile{name: n, data: b})
	}
	return append(out, tarFile{name: FileSums, data: sums}, tarFile{name: FileSig, data: update.SignSums(key, sums)})
}

func wantPkgErr(t *testing.T, data []byte, substr string) {
	t.Helper()
	_, err := ReadPackage(data, "v0.2.0")
	var pe *PackageError
	if !errors.As(err, &pe) {
		t.Fatalf("want package error %q, got %v", substr, err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("want %q in %q", substr, err)
	}
}

func TestPackageOK(t *testing.T) {
	key := newKey(t)
	p, err := ReadPackage(testPackage(t, key, nil), "v0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.ID != "demo" || p.Official || p.Readme != "# Demo\n" || len(p.SHA256) != 64 || p.Size == 0 {
		t.Fatalf("%+v", p)
	}
	if bytes.Contains(p.Icon, []byte("script")) || bytes.Contains(p.Icon, []byte("onload")) || !bytes.Contains(p.Icon, []byte("<rect")) {
		t.Fatalf("icon not sanitised: %s", p.Icon)
	}
	if PackName(p.Manifest) != "demo-v0.1.0-linux-amd64.hpkg" {
		t.Fatal(PackName(p.Manifest))
	}
}

func TestPackageSignature(t *testing.T) {
	key, other := newKey(t), newKey(t)

	// Signed by another key than the one in the manifest.
	files := signedFiles(t, key, nil)
	for i := range files {
		if files[i].name == FileSig {
			sums := files[len(files)-2].data
			files[i].data = update.SignSums(other, sums)
		}
	}
	wantPkgErr(t, rawTar(t, files), "подпись пакета неверна")

	// No signature at all.
	files = signedFiles(t, key, nil)
	wantPkgErr(t, rawTar(t, files[:len(files)-1]), "не подписан")
	wantPkgErr(t, rawTar(t, files[:len(files)-2]), "не подписан")

	// A file changed after signing.
	files = signedFiles(t, key, nil)
	for i := range files {
		if files[i].name == FilePlugin {
			files[i].data = append(files[i].data, 0)
		}
	}
	wantPkgErr(t, rawTar(t, files), "контрольная сумма")

	// A garbled signature.
	files = signedFiles(t, key, nil)
	files[len(files)-1].data = []byte("not base64!")
	wantPkgErr(t, rawTar(t, files), "подпись пакета неверна")
}

func TestPackageLayout(t *testing.T) {
	key := newKey(t)
	files := signedFiles(t, key, nil)

	wantPkgErr(t, rawTar(t, append(files, tarFile{name: "extra.txt", data: []byte("x")})), "лишний файл")
	wantPkgErr(t, rawTar(t, append(files, tarFile{name: "../plugin", data: []byte("x")})), "недопустимый путь")
	wantPkgErr(t, rawTar(t, append(files, tarFile{name: "dir/README.md", data: []byte("x")})), "недопустимый путь")
	wantPkgErr(t, rawTar(t, append(files, tarFile{name: "/etc/passwd", data: []byte("x")})), "недопустимый путь")
	wantPkgErr(t, rawTar(t, append(files, tarFile{name: FileIcon, typ: tar.TypeSymlink, link: "/etc/passwd"})), "только обычные файлы")
	wantPkgErr(t, rawTar(t, append(files, tarFile{name: FileReadme, typ: tar.TypeLink, link: FilePlugin})), "только обычные файлы")
	wantPkgErr(t, rawTar(t, append(files, files[0])), "дважды")
	wantPkgErr(t, []byte("plain text"), "tar.gz")

	// README not covered by SHA256SUMS.
	wantPkgErr(t, rawTar(t, append(files, tarFile{name: FileReadme, data: []byte("x")})), "в SHA256SUMS нет")

	// No binary.
	var noBin []tarFile
	for _, f := range files {
		if f.name != FilePlugin {
			noBin = append(noBin, f)
		}
	}
	wantPkgErr(t, rawTar(t, noBin), "нет plugin")

	// A dynamically linked binary.
	wantPkgErr(t, rawTar(t, signedFiles(t, key, map[string][]byte{FilePlugin: testelf.Build(testelf.Opts{Dynamic: true})})), "динамически")
}

func TestPackageTooBig(t *testing.T) {
	key := newKey(t)
	big := make([]byte, MaxPackage-100)
	files := signedFiles(t, key, map[string][]byte{FileReadme: big})
	wantPkgErr(t, rawTar(t, files), "больше 64 МБ")
	wantPkgErr(t, make([]byte, MaxPackage+1), "больше 64 МБ")
}

func TestPackageManifestRules(t *testing.T) {
	key := newKey(t)
	cases := []struct {
		mod  func(*sdk.Manifest)
		want string
	}{
		{func(m *sdk.Manifest) { m.Permissions = append(m.Permissions, "root.everything") }, "неизвестное право"},
		{func(m *sdk.Manifest) { m.ID = "hestia-demo" }, "зарезервирован за официальными"},
		{func(m *sdk.Manifest) { m.ID = "Bad_ID" }, "неверный id"},
		{func(m *sdk.Manifest) { m.ID = "targets" }, "зарезервирован"},
		{func(m *sdk.Manifest) { m.Protocol = 2 }, "протокола 2"},
		{func(m *sdk.Manifest) { m.Version = "1.0" }, "vX.Y.Z"},
		{func(m *sdk.Manifest) { m.MinHestia = "v9.0.0" }, "нужна Hestia v9.0.0"},
		{func(m *sdk.Manifest) { m.Author.Key = "" }, "ключа автора"},
		{func(m *sdk.Manifest) { m.Provides = []sdk.Port{{Type: "Bad Type"}} }, "тип связи"},
		{func(m *sdk.Manifest) { m.Schema.Fields[1].Type = "file" }, "неизвестный тип"},
		{func(m *sdk.Manifest) { m.Schema.Fields[1].Default = "far too long default value!" }, "по умолчанию"},
		{func(m *sdk.Manifest) {
			m.Schema.Fields = append(m.Schema.Fields, sdk.Field{Name: "mode", Type: sdk.FieldEnum, Label: "Режим"})
		}, "нет вариантов"},
		{func(m *sdk.Manifest) {
			m.Schema.Presets = []sdk.Preset{{Name: "x", Label: "X", Values: map[string]any{"target": "ssh:1"}}}
		}, "нельзя задавать пресетом"},
		{func(m *sdk.Manifest) { m.Homepage = "javascript:alert(1)" }, "homepage"},
	}
	for _, c := range cases {
		// Built by hand: Pack itself refuses a manifest without the key.
		content := map[string][]byte{FileManifest: testManifest(key, c.mod), FilePlugin: testelf.Build(testelf.Opts{})}
		sums := update.SumsFile(content)
		data := rawTar(t, []tarFile{{name: FileManifest, data: content[FileManifest]}, {name: FilePlugin, data: content[FilePlugin]},
			{name: FileSums, data: sums}, {name: FileSig, data: update.SignSums(key, sums)}})
		wantPkgErr(t, data, c.want)
	}
}

func TestOfficialKey(t *testing.T) {
	key := newKey(t)
	old := OfficialPub
	t.Cleanup(func() { OfficialPub = old })
	OfficialPub = pubOf(key)
	p, err := ReadPackage(testPackage(t, key, func(m *sdk.Manifest) { m.ID = "hestia-demo" }), "v0.2.0")
	if err != nil || !p.Official {
		t.Fatalf("%+v %v", p, err)
	}
	// Empty official.pub: nothing is official.
	OfficialPub = ""
	if IsOfficialKey(pubOf(key)) {
		t.Fatal("empty key must not match")
	}
}

func TestPackRequiresMatchingKey(t *testing.T) {
	key, other := newKey(t), newKey(t)
	_, err := Pack(other, map[string][]byte{FileManifest: testManifest(key, nil), FilePlugin: []byte("x")})
	if err == nil || !strings.Contains(err.Error(), "author.key") {
		t.Fatal(err)
	}
}

func TestFingerprint(t *testing.T) {
	fp := Fingerprint(pubOf(newKey(t)))
	if len(strings.Fields(fp)) != 16 || len(fp) != 64+15 {
		t.Fatalf("%q", fp)
	}
	if Fingerprint("%%%") != "" {
		t.Fatal("bad key must give empty fingerprint")
	}
}

func TestSanitizeSVG(t *testing.T) {
	in := `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" onload="a()">` +
		`<script>a()</script><foreignObject><div>x</div></foreignObject><a xlink:href="javascript:a()" href="https://evil"><rect onclick="a()" style="fill:url(http://x)" width="2"/></a>` +
		`<use xlink:href="#r"/><svg:script xmlns:svg="http://www.w3.org/2000/svg">b()</svg:script><text>a &lt; b</text></svg>`
	out, err := SanitizeSVG([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, bad := range []string{"script", "onload", "onclick", "javascript", "foreignObject", "https://evil", "url(", "ENTITY"} {
		if strings.Contains(s, bad) {
			t.Fatalf("%q left in %s", bad, s)
		}
	}
	for _, good := range []string{`<use xlink:href="#r">`, "<rect", "a &lt; b"} {
		if !strings.Contains(s, good) {
			t.Fatalf("%q lost in %s", good, s)
		}
	}
	for _, bad := range []string{"<html/>", "", "<svg>", "<svg></svg><svg></svg>", "<svg><a></b></svg>"} {
		if _, err := SanitizeSVG([]byte(bad)); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestCheckValue(t *testing.T) {
	min, max := 1.0, 10.0
	cases := []struct {
		f    sdk.Field
		v    any
		fail bool
	}{
		{sdk.Field{Type: sdk.FieldString, MaxLen: 3}, "abc", false},
		{sdk.Field{Type: sdk.FieldString, MaxLen: 3}, "абвг", true},
		{sdk.Field{Type: sdk.FieldString}, "a\nb", true},
		{sdk.Field{Type: sdk.FieldText}, "a\nb", false},
		{sdk.Field{Type: sdk.FieldString, Pattern: "[a-z]+"}, "abc", false},
		{sdk.Field{Type: sdk.FieldString, Pattern: "[a-z]+"}, "abc1", true},
		{sdk.Field{Type: sdk.FieldInt, Min: &min, Max: &max}, json.Number("5"), false},
		{sdk.Field{Type: sdk.FieldInt, Min: &min, Max: &max}, json.Number("0"), true},
		{sdk.Field{Type: sdk.FieldInt, Min: &min, Max: &max}, float64(11), true},
		{sdk.Field{Type: sdk.FieldInt}, 1.5, true},
		{sdk.Field{Type: sdk.FieldInt}, "5", true},
		{sdk.Field{Type: sdk.FieldBool}, true, false},
		{sdk.Field{Type: sdk.FieldBool}, "true", true},
		{sdk.Field{Type: sdk.FieldEnum, Options: []sdk.Option{{Value: "a"}}}, "a", false},
		{sdk.Field{Type: sdk.FieldEnum, Options: []sdk.Option{{Value: "a"}}}, "b", true},
	}
	for i, c := range cases {
		if got := checkValue(c.f, c.v) != ""; got != c.fail {
			t.Errorf("case %d: fail=%v", i, got)
		}
	}
}
