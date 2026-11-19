package plugins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/testelf"
	"github.com/uxerror/hestia/sdk"
)

func withImage(m *sdk.Manifest) {
	m.Images = []sdk.Image{{Name: "ca-server", File: "image-ca-server"}}
	m.Permissions = append(m.Permissions, sdk.PermDeployDocker)
}

func imagePackage(t *testing.T, key []byte, mod func(*sdk.Manifest), extra map[string][]byte) ([]byte, error) {
	t.Helper()
	files := map[string][]byte{
		FileManifest: testManifest(key, func(m *sdk.Manifest) {
			withImage(m)
			if mod != nil {
				mod(m)
			}
		}),
		FilePlugin: testelf.Build(testelf.Opts{Payload: []byte("plugin")}),
	}
	for n, b := range extra {
		files[n] = b
	}
	return Pack(key, files)
}

func TestPackageImages(t *testing.T) {
	key := newKey(t)
	img := testelf.Build(testelf.Opts{Payload: []byte("ca-server")})
	pkg, err := imagePackage(t, key, nil, map[string][]byte{"image-ca-server": img})
	if err != nil {
		t.Fatal(err)
	}
	p, err := ReadPackage(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Images["ca-server"], img) {
		t.Fatal("image not read")
	}
	if !strings.Contains(imagesNote(p.Images), "ca-server") {
		t.Fatal(imagesNote(p.Images))
	}

	// The signature covers the image: a changed byte is refused.
	files, err := untar(pkg)
	if err != nil {
		t.Fatal(err)
	}
	files["image-ca-server"][len(files["image-ca-server"])-1] ^= 1
	var tf []tarFile
	for n, b := range files {
		tf = append(tf, tarFile{name: n, data: b})
	}
	if _, err := ReadPackage(rawTar(t, tf), ""); err == nil || !strings.Contains(err.Error(), "image-ca-server") {
		t.Fatalf("tampered image: %v", err)
	}

	cases := []struct {
		name  string
		mod   func(*sdk.Manifest)
		extra map[string][]byte
		want  string
	}{
		{"missing", nil, nil, "нет image-ca-server"},
		{"extra", nil, map[string][]byte{"image-ca-server": img, "image-other": img}, "лишний файл"},
		{"not elf", nil, map[string][]byte{"image-ca-server": []byte("#!/bin/sh\n")}, "образ ca-server"},
		{"bad file", func(m *sdk.Manifest) { m.Images[0].File = "ca-server" }, map[string][]byte{"image-ca-server": img}, "file должен быть"},
		{"no perm", func(m *sdk.Manifest) { m.Permissions = []string{sdk.PermTargetsRead} }, map[string][]byte{"image-ca-server": img}, "deploy.docker"},
	}
	for _, c := range cases {
		b, err := imagePackage(t, key, c.mod, c.extra)
		if err == nil {
			_, err = ReadPackage(b, "")
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// Over 32 MB: refused by untar before reading it whole.
	big := rawTar(t, []tarFile{{name: FileManifest, data: testManifest(key, withImage)}, {name: "image-ca-server", data: make([]byte, MaxImage+1)}})
	if _, err := ReadPackage(big, ""); err == nil || !strings.Contains(err.Error(), "32 МБ") {
		t.Fatalf("big image: %v", err)
	}
	// An image without a manifest entry, even in SHA256SUMS: refused.
	if _, err := Pack(key, map[string][]byte{FileManifest: testManifest(key, nil), FilePlugin: img, "image-x": img}); err != nil {
		t.Fatal(err)
	}
	b, _ := Pack(key, map[string][]byte{FileManifest: testManifest(key, nil), FilePlugin: img, "image-x": img})
	if _, err := ReadPackage(b, ""); err == nil || !strings.Contains(err.Error(), "лишний файл") {
		t.Fatalf("image without manifest: %v", err)
	}
}

func TestComposeImages(t *testing.T) {
	ref := sdk.ImageRef("demo", "ca-server", "v0.2.0")
	c := func(img string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"services": map[string]any{"ca": map[string]any{"image": img}}})
		return b
	}
	pc, err := prepareCompose(c(ref), testDir, "demo", 7, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pc.data), `"pull_policy": "never"`) {
		t.Fatal(string(pc.data))
	}
	for _, bad := range []struct {
		img  string
		refs []string
	}{
		{"hestia.local/other/ca-server:v0.2.0", []string{ref}},
		{"hestia.local/demo/ca-server:v0.1.0", []string{ref}},
		{ref, nil},
		{"HESTIA.LOCAL/demo/ca-server:v0.2.0", []string{ref}},
	} {
		if _, err := prepareCompose(c(bad.img), testDir, "demo", 7, bad.refs...); err == nil || !strings.Contains(err.Error(), "hestia.local") {
			t.Errorf("%s: %v", bad.img, err)
		}
	}
}

func TestDeployImages(t *testing.T) {
	e := newDeployEnv(t)
	ctx := context.Background()
	key := newKey(t)
	img := testelf.Build(testelf.Opts{Payload: []byte("ca-server binary")})
	// The demo plugin gets a version with an image (as an install would
	// leave it: the manifest in the database, the file in its directory).
	cur, err := e.h.st.GetPlugin(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	cur.Version, cur.Manifest = "v0.2.0", string(testManifest(key, func(m *sdk.Manifest) { withImage(m); m.Version = "v0.2.0" }))
	if err := e.h.st.SavePlugin(ctx, cur, nil); err != nil {
		t.Fatal(err)
	}
	vdir := filepath.Join(e.h.root, pluginsDir, "demo", "v0.2.0")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vdir, "image-ca-server"), img, 0o644); err != nil {
		t.Fatal(err)
	}
	ref := sdk.ImageRef("demo", "ca-server", "v0.2.0")
	compose, _ := json.Marshal(map[string]any{"services": map[string]any{"ca": map[string]any{"image": ref, "volumes": []string{"ca-data:/data"}}},
		"volumes": map[string]any{"ca-data": map[string]any{}}})
	e.tg.InstallDocker()
	e.tg.Set("service", "ca")
	e.tg.Set("images.list", "hestia.local/demo/ca-server:v0.1.0 old\n")
	req := e.req(e.ssh, "", compose)
	req.Images = []string{"ca-server"}

	// Images not in the manifest, and the reference without images.
	bad := req
	bad.Images = []string{"nosuch"}
	if _, err := e.call(e.s, sdk.MethodDeployPlan, bad); err == nil || !strings.Contains(err.Error(), "нет в манифесте") {
		t.Fatalf("unknown image: %v", err)
	}
	bad.Images = nil
	if _, err := e.call(e.s, sdk.MethodDeployPlan, bad); err == nil || !strings.Contains(err.Error(), "hestia.local") {
		t.Fatalf("no images: %v", err)
	}

	b, err := e.call(e.s, sdk.MethodDeployPlan, req)
	if err != nil {
		t.Fatal(err)
	}
	var pl sdk.DeployPlan
	_ = json.Unmarshal(b, &pl)
	if !strings.Contains(titles(pl.Actions), "change: Загрузить образ ca-server из пакета плагина") {
		t.Fatal(titles(pl.Actions))
	}
	j := e.inJob(t, e.iid, false, func(id string) error {
		r := req
		r.JobID = id
		_, err := e.call(e.s, sdk.MethodDeployUp, r)
		return err
	})
	if j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	imp := e.tg.Log("import.log")
	for _, s := range []string{`ENTRYPOINT ["/ca-server"]`, "USER 65532:65532", "LABEL hestia.sha256=" + sha(img) + " hestia.plugin=demo", ref} {
		if !strings.Contains(imp, s) {
			t.Fatalf("no %q in %s", s, imp)
		}
	}
	// The rootfs: the binary (0755 root), /data (0700 65532), /tmp (1777).
	tgz, _ := os.ReadFile(filepath.Join(e.tg.Dir, "import.tgz"))
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	seen := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		seen[h.Name] = strings.Join([]string{itoa(h.Mode), itoa(int64(h.Uid)), itoa(int64(h.Gid)), itoa(int64(len(data)))}, " ")
		if h.Name == "ca-server" && !bytes.Equal(data, img) {
			t.Fatal("binary differs")
		}
	}
	want := map[string]string{"ca-server": "493 0 0 " + itoa(int64(len(img))), "data/": "448 65532 65532 0", "tmp/": "1023 0 0 0"}
	for n, w := range want {
		if seen[n] != w {
			t.Fatalf("%s: %q, want %q (%v)", n, seen[n], w, seen)
		}
	}
	if up, _ := os.ReadFile(filepath.Join(e.tg.Dir, "up-"+projectName(e.iid, "web")+".yaml")); !strings.Contains(string(up), `"pull_policy": "never"`) {
		t.Fatalf("compose: %s", up)
	}
	if !strings.Contains(e.tg.Log("image-rm.log"), "hestia.local/demo/ca-server:v0.1.0") {
		t.Fatalf("old tag not removed: %s", e.tg.Log("image-rm.log"))
	}

	// Loaded already: no second import.
	b, _ = e.call(e.s, sdk.MethodDeployPlan, req)
	_ = json.Unmarshal(b, &pl)
	if !strings.Contains(titles(pl.Actions), "Образ ca-server уже загружен") {
		t.Fatal(titles(pl.Actions))
	}
	// A different label (another build): imported again.
	e.tg.Set("images.list", ref+" other\n")
	b, _ = e.call(e.s, sdk.MethodDeployPlan, req)
	_ = json.Unmarshal(b, &pl)
	if !strings.Contains(titles(pl.Actions), "Загрузить образ ca-server") {
		t.Fatal(titles(pl.Actions))
	}

	// Down of the last project of the plugin removes its images.
	e.tg.Set("image-rm.log", "")
	e.tg.Set("images.list", ref+" "+sha(img)+"\n")
	j = e.inJob(t, e.iid, false, func(id string) error {
		_, err := e.call(e.s, sdk.MethodDeployDown, sdk.DeployDownRequest{JobID: id, Instance: e.iid, Target: e.ssh, Project: "web", Volumes: true})
		return err
	})
	if j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if !strings.Contains(e.tg.Log("image-rm.log"), ref) {
		t.Fatalf("images left after down: %s", e.tg.Log("image-rm.log"))
	}

	// An action job never deploys.
	e.h.m.mu.Lock()
	e.h.m.applying["act"] = &applyJob{pluginID: "demo", instanceID: e.iid, action: true}
	e.h.m.mu.Unlock()
	r := req
	r.JobID = "act"
	if _, err := e.call(e.s, sdk.MethodDeployUp, r); err == nil || !strings.Contains(err.Error(), "не выполняется") {
		t.Fatalf("deploy in an action job: %v", err)
	}
}
