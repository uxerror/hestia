package plugins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
	"github.com/uxerror/hestia/sdk"
)

// Container images shipped in a plugin package: the file "image-<name>" is
// a static linux/amd64 binary. Hestia (not the plugin) turns it into a
// one-binary rootfs and loads it on a target with `docker import` as
// sdk.ImageRef(plugin, name, plugin version); compose files refer to it
// with pull_policy "never".

// Limits and names of images.
const (
	MaxImage      = 32 << 20 // one image binary
	imagePrefix   = "image-"
	imageRegistry = "hestia.local/"
	// LabelSHA256 is the label of a loaded image: sha256 of its binary.
	LabelSHA256 = "hestia.sha256"
	imageUID    = 65532
)

// imageFileName is the package file of an image.
func imageFileName(name string) string { return imagePrefix + name }

// isImageFile reports whether a package file name has the form of an image.
func isImageFile(file string) bool {
	name, ok := strings.CutPrefix(file, imagePrefix)
	return ok && reImageName.MatchString(name)
}

// mbText renders a size in megabytes the Russian way ("7,1 МБ").
func mbText(n int64) string {
	return strings.Replace(fmt.Sprintf("%.1f МБ", float64(n)/(1<<20)), ".", ",", 1)
}

// imagesNote is the line of the install preview listing the images.
func imagesNote(imgs map[string][]byte) string {
	if len(imgs) == 0 {
		return ""
	}
	names := make([]string, 0, len(imgs))
	for n := range imgs {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s (%s)", n, mbText(int64(len(imgs[n])))))
	}
	return "Пакет содержит образы: " + strings.Join(parts, ", ")
}

// deployImage is an image of a deploy call.
type deployImage struct {
	name string
	ref  string
	data []byte
	sha  string
}

// specImages resolves the images of a deploy call: names from the caller's
// manifest, the bytes of the installed (or dev) plugin and the reference
// with the installed version.
func (m *Manager) specImages(ctx context.Context, pid string, names []string) ([]deployImage, error) {
	if len(names) == 0 {
		return nil, nil
	}
	p, err := m.Store.GetPlugin(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("плагин %s: %w", pid, err)
	}
	man, err := storedManifest(p.Manifest)
	if err != nil {
		return nil, err
	}
	var out []deployImage
	for _, n := range names {
		if !slices.ContainsFunc(man.Images, func(im sdk.Image) bool { return im.Name == n }) {
			return nil, badParams("images: образа %q нет в манифесте плагина", n)
		}
		if slices.ContainsFunc(out, func(d deployImage) bool { return d.name == n }) {
			return nil, badParams("images: %s указан дважды", n)
		}
		data, err := m.imageFile(ctx, pid, p.Version, n)
		if err != nil {
			return nil, err
		}
		out = append(out, deployImage{name: n, ref: sdk.ImageRef(pid, n, p.Version), data: data, sha: sha(data)})
	}
	return out, nil
}

// imageFile returns the binary of an image of an installed plugin
// (/var/lib/hestia-plugins/<id>/<version>/image-<name>, readable by the
// controller: the directories are 0755, the file 0644) or, for a dev
// plugin, "image-<name>" next to its binary (or "server" there if the
// manifest has exactly one image).
func (m *Manager) imageFile(ctx context.Context, pluginID, version, name string) ([]byte, error) {
	p, err := m.Store.GetPlugin(ctx, pluginID)
	if err != nil {
		return nil, fmt.Errorf("плагин %s: %w", pluginID, err)
	}
	var paths []string
	if p.Source == store.PluginSourceDev {
		bin := m.devBinary(pluginID)
		if bin == "" {
			return nil, fmt.Errorf("образ %s: dev-плагин %s не запущен", name, pluginID)
		}
		dir := filepath.Dir(bin)
		paths = append(paths, filepath.Join(dir, imageFileName(name)))
		if man, err := storedManifest(p.Manifest); err == nil && len(man.Images) == 1 {
			paths = append(paths, filepath.Join(dir, "server"))
		}
	} else {
		l := layout{root: m.Root}
		paths = append(paths, l.p(l.versionDir(pluginID, version)+"/"+imageFileName(name)))
	}
	for _, path := range paths {
		st, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("образ %s: %w", name, err)
		}
		if st.Size() > MaxImage {
			return nil, fmt.Errorf("образ %s больше 32 МБ", name)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("образ %s: %w", name, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("образ %s плагина %s не найден (%s)", name, pluginID, strings.Join(paths, ", "))
}

// devBinary is the path of the running dev plugin with this id ("" if none).
func (m *Manager) devBinary(id string) string {
	m.mu.Lock()
	devs := append([]*devPlugin(nil), m.devs...)
	m.mu.Unlock()
	for _, d := range devs {
		d.mu.Lock()
		ok := d.id == id
		d.mu.Unlock()
		if ok {
			return d.path
		}
	}
	return ""
}

// rootfs builds the filesystem of an image: /<name> (0755, root), /data/
// (0700, 65532) and /tmp/ (1777), gzipped.
func rootfs(name string, bin []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	mt := time.Unix(0, 0)
	hdrs := []struct {
		h    tar.Header
		data []byte
	}{
		{tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(bin)), ModTime: mt, Format: tar.FormatPAX}, bin},
		{tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: imageUID, Gid: imageUID, ModTime: mt, Format: tar.FormatPAX}, nil},
		{tar.Header{Name: "tmp/", Typeflag: tar.TypeDir, Mode: 0o1777, ModTime: mt, Format: tar.FormatPAX}, nil},
	}
	for _, e := range hdrs {
		if err := tw.WriteHeader(&e.h); err != nil {
			return nil, err
		}
		if e.data != nil {
			if _, err := tw.Write(e.data); err != nil {
				return nil, err
			}
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

// importScript loads a rootfs from stdin as the image.
func importScript(pluginID string, im deployImage) string {
	return fmt.Sprintf("docker import --change %s --change %s --change %s - %s",
		target.Quote(`ENTRYPOINT ["/`+im.name+`"]`),
		target.Quote(fmt.Sprintf("USER %d:%d", imageUID, imageUID)),
		target.Quote(fmt.Sprintf("LABEL %s=%s %s=%s", LabelSHA256, im.sha, LabelPlugin, pluginID)),
		target.Quote(im.ref))
}

// imageInspectFormat prints the sha256 label of an image.
const imageInspectFormat = `{{index .Config.Labels "hestia.sha256"}}`

// probeImages is the part of the probe script reporting the loaded images
// ("image <ref> <label>"; no label: not loaded).
func probeImages(imgs []deployImage) string {
	if len(imgs) == 0 {
		return ""
	}
	refs := make([]string, 0, len(imgs))
	for _, im := range imgs {
		refs = append(refs, target.Quote(im.ref))
	}
	return fmt.Sprintf("if command -v docker >/dev/null 2>&1; then for r in %s; do echo \"image $r $(docker image inspect --format %s \"$r\" 2>/dev/null)\"; done; fi\n",
		strings.Join(refs, " "), target.Quote(imageInspectFormat))
}

// imageLoaded reports whether the probe saw the image with the same binary.
func (p *probe) imageLoaded(im deployImage) bool {
	return p.images[im.ref] == im.sha
}

// loadImages imports the images the target does not have yet; each is a
// step of the job.
func (m *Manager) loadImages(ctx context.Context, a *applyJob, sp *deploySpec, p *probe) error {
	for _, im := range sp.images {
		if p.imageLoaded(im) {
			continue
		}
		if err := m.jobStep(a, "Загрузка образа "+im.name, func() error {
			tgz, err := rootfs(im.name, im.data)
			if err != nil {
				return err
			}
			m.logJob(a, "info", fmt.Sprintf("%s: %s, sha256 %s…", im.ref, mbText(int64(len(im.data))), im.sha[:12]))
			res, err := m.texec(ctx, sp.refStr, importScript(sp.pluginID, im)+" 2>&1", tgz, m.DeployUpTimeout)
			m.logOutput(a, res.Stdout)
			if err != nil {
				return fmt.Errorf("docker import: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// pluginImages lists the images hestia.local/<plugin>/… on the target and
// the images used by any container.
func (m *Manager) pluginImages(ctx context.Context, ref, pluginID string) (own []string, used map[string]bool, err error) {
	script := `command -v docker >/dev/null 2>&1 || exit 0
docker image ls --format '{{.Repository}}:{{.Tag}}' && echo ---ps && docker ps -a --format '{{.Image}}'`
	res, err := m.texec(ctx, ref, script, nil, deployProbeT)
	if err != nil {
		return nil, nil, err
	}
	imgs, ps, _ := strings.Cut(res.Stdout, "---ps\n")
	used = map[string]bool{}
	for _, l := range strings.Split(ps, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			used[l] = true
		}
	}
	prefix := imageRegistry + pluginID + "/"
	for _, l := range strings.Split(imgs, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, prefix) && !strings.HasSuffix(l, ":<none>") && !strings.ContainsAny(l, " '\"\\$`") {
			own = append(own, l)
		}
	}
	sort.Strings(own)
	return own, used, nil
}

// removeImages removes the plugin's images except keep and those used by
// containers; errors go to the log only.
func (m *Manager) removeImages(ctx context.Context, a *applyJob, ref, pluginID string, keep map[string]bool) {
	ctx = context.WithoutCancel(ctx)
	own, used, err := m.pluginImages(ctx, ref, pluginID)
	if err != nil {
		m.logJob(a, "warn", "Список образов на цели: "+err.Error())
		return
	}
	var rm []string
	for _, r := range own {
		if !keep[r] && !used[r] {
			rm = append(rm, target.Quote(r))
		}
	}
	if len(rm) == 0 {
		return
	}
	res, err := m.texec(ctx, ref, "docker image rm "+strings.Join(rm, " ")+" 2>&1", nil, deployDownT)
	if err != nil {
		m.logJob(a, "warn", "Удаление старых образов: "+err.Error())
		return
	}
	m.logOutput(a, res.Stdout)
	m.logJob(a, "info", "Удалены образы: "+strings.Join(rm, ", "))
}

// cleanupAfterDown removes all images of the plugin from the target when
// no container of the plugin is left there.
func (m *Manager) cleanupAfterDown(ctx context.Context, a *applyJob, sp *deploySpec) {
	p, err := m.Store.GetPlugin(ctx, sp.pluginID)
	if err != nil {
		return
	}
	if man, err := storedManifest(p.Manifest); err != nil || len(man.Images) == 0 {
		return
	}
	ctx = context.WithoutCancel(ctx)
	script := fmt.Sprintf("command -v docker >/dev/null 2>&1 || exit 0\ndocker ps -a -q --filter %s",
		target.Quote("label="+LabelPlugin+"="+sp.pluginID))
	res, err := m.texec(ctx, sp.refStr, script, nil, deployProbeT)
	if err != nil {
		m.logJob(a, "warn", "Контейнеры плагина на цели: "+err.Error())
		return
	}
	if strings.TrimSpace(res.Stdout) != "" {
		return // other projects of the plugin still run there
	}
	m.removeImages(ctx, a, sp.refStr, sp.pluginID, nil)
}
