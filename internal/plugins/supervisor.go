package plugins

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/target"
)

// Supervisor starts and stops plugin processes. The systemd implementation
// is used in production (through the root path to the controller's machine),
// the child one in dev mode; both hand the RPC layer an io.ReadWriteCloser
// (the unix socket connection or the child's stdio).
type Supervisor interface {
	Enable(ctx context.Context, id string) error // start now and on boot
	Disable(ctx context.Context, id string) error
	Restart(ctx context.Context, id string) error
	Active(ctx context.Context, id string) (string, error)
}

// Files installed on the controller's machine.
var (
	//go:embed files/hestia-plugin@.service
	unitTemplate []byte
	//go:embed files/tmpfiles-hestia.conf
	tmpfilesConf []byte
	//go:embed files/no-network.conf
	noNetworkConf []byte
	//go:embed files/hestia-plugins-socket.conf
	controllerDropin []byte
)

// Paths on the controller's machine (prefixed with Manager.Root).
const (
	pluginsDir   = "/var/lib/hestia-plugins"
	unitPath     = "/etc/systemd/system/hestia-plugin@.service"
	tmpfilesPath = "/etc/tmpfiles.d/hestia.conf"
	stateDir     = "/var/lib/private/hestia-plugin"
	// controllerDropinPath opens /run/hestia to the controller's own unit.
	controllerDropinPath = "/etc/systemd/system/hestia.service.d/10-plugins.conf"
)

func unitName(id string) string { return "hestia-plugin@" + id + ".service" }

func dropinDir(id string) string { return "/etc/systemd/system/" + unitName(id) + ".d" }

// layout resolves paths under the test prefix.
type layout struct{ root string }

func (l layout) p(path string) string           { return l.root + path }
func (l layout) q(path string) string           { return target.Quote(l.p(path)) }
func (l layout) pluginDir(id string) string     { return pluginsDir + "/" + id }
func (l layout) versionDir(id, v string) string { return pluginsDir + "/" + id + "/" + v }

// systemd is the production Supervisor: systemctl through the root shell.
type systemd struct {
	sh Shell
	l  layout
}

func (s systemd) run(ctx context.Context, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	r, err := s.sh.Exec(ctx, script, nil)
	if err != nil {
		return r.Stdout, err
	}
	return r.Stdout, nil
}

func (s systemd) Enable(ctx context.Context, id string) error {
	_, err := s.run(ctx, "systemctl enable --now "+unitName(id))
	return err
}

func (s systemd) Disable(ctx context.Context, id string) error {
	_, err := s.run(ctx, "systemctl disable --now "+unitName(id))
	return err
}

func (s systemd) Restart(ctx context.Context, id string) error {
	_, err := s.run(ctx, "systemctl enable "+unitName(id)+" && systemctl restart "+unitName(id))
	return err
}

func (s systemd) Active(ctx context.Context, id string) (string, error) {
	// is-active exits non-zero for anything but "active"; the state is on stdout.
	out, err := s.run(ctx, "systemctl is-active "+unitName(id)+" || true")
	st := strings.TrimSpace(out)
	if st == "" && err != nil {
		return "", err
	}
	if st == "" {
		st = "unknown"
	}
	return st, nil
}

// prepare writes the shared files (unit template, tmpfiles, socket
// directory) when missing or outdated and reloads systemd.
func (s systemd) prepare(ctx context.Context, log func(string)) error {
	if err := s.sh.PutFile(ctx, log, s.l.p(unitPath), unitTemplate, "0644", "root:root"); err != nil {
		return err
	}
	if _, err := s.run(ctx, "test -f "+s.l.q(tmpfilesPath)); err != nil {
		if _, err := s.run(ctx, "mkdir -p "+s.l.q("/etc/tmpfiles.d")); err != nil {
			return err
		}
		if err := s.sh.PutFile(ctx, log, s.l.p(tmpfilesPath), tmpfilesConf, "0644", "root:root"); err != nil {
			return err
		}
	}
	if _, err := s.run(ctx, "systemd-tmpfiles --create "+s.l.q(tmpfilesPath)); err != nil {
		return fmt.Errorf("каталог сокета: %w", err)
	}
	if _, err := s.run(ctx, "test -f "+s.l.q(controllerDropinPath)); err != nil {
		if _, err := s.run(ctx, "mkdir -p "+s.l.q("/etc/systemd/system/hestia.service.d")); err != nil {
			return err
		}
		if err := s.sh.PutFile(ctx, log, s.l.p(controllerDropinPath), controllerDropin, "0644", "root:root"); err != nil {
			return err
		}
	}
	return nil
}

// restartController restarts the controller a few seconds later, outside
// its own cgroup (the job that asks for it has finished by then).
func (s systemd) restartController(ctx context.Context) error {
	_, err := s.run(ctx, fmt.Sprintf("systemd-run --on-active=5 --unit hestia-restart-%d --collect systemctl restart hestia.service",
		time.Now().Unix()))
	return err
}

// sandbox writes (or removes) the per-plugin drop-in that cuts the network
// for plugins without net.outbound.
func (s systemd) sandbox(ctx context.Context, log func(string), id string, net bool) error {
	dir := dropinDir(id)
	if net {
		_, err := s.run(ctx, "rm -rf "+s.l.q(dir))
		return err
	}
	if _, err := s.run(ctx, "mkdir -p "+s.l.q(dir)); err != nil {
		return err
	}
	return s.sh.PutFile(ctx, log, s.l.p(dir+"/10-hestia.conf"), noNetworkConf, "0644", "root:root")
}

func (s systemd) daemonReload(ctx context.Context) error {
	_, err := s.run(ctx, "systemctl daemon-reload")
	return err
}

// switchCurrent points <id>/current at version atomically.
func (s systemd) switchCurrent(ctx context.Context, id, version string) error {
	dir := s.l.pluginDir(id)
	_, err := s.run(ctx, "ln -sfn "+target.Quote(version)+" "+s.l.q(dir+"/current.new")+
		" && mv -Tf "+s.l.q(dir+"/current.new")+" "+s.l.q(dir+"/current"))
	return err
}

// purge removes everything of a plugin on the machine: unit drop-in, files,
// token and state directory.
func (s systemd) purge(ctx context.Context, id string) error {
	u := unitName(id)
	script := strings.Join([]string{
		"systemctl disable --now " + u + " >/dev/null 2>&1 || true",
		"systemctl clean --what=state " + u + " >/dev/null 2>&1 || true",
		"rm -rf " + s.l.q(s.l.pluginDir(id)) + " " + s.l.q(dropinDir(id)) + " " + s.l.q(stateDir+"/"+id),
		"systemctl daemon-reload",
	}, "\n")
	_, err := s.run(ctx, script)
	return err
}

var errNoShell = errors.New("нет root-доступа к машине контроллера")
