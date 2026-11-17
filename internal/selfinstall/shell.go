package selfinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/target"
)

// pctShell runs scripts as root inside container vmid through `pct exec` on
// its node. client returns a live SSH connection to the node (reconnecting
// when needed).
func pctShell(vmid int, client func(ctx context.Context) (*sshx.Client, error)) shellFn {
	pfx := "pct exec " + strconv.Itoa(vmid) + " -- sh -c "
	return func(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
		cl, err := client(ctx)
		if err != nil {
			return sshx.Result{}, err
		}
		return cl.Exec(ctx, pfx+target.Quote(script), stdin)
	}
}

// putFile writes data through stdin to path, fixes mode/owner and verifies
// the sha256 of the stored file. log receives one progress line.
func putFile(ctx context.Context, sh shellFn, log func(string), path string, data []byte, mode, owner string) error {
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if log != nil {
		log(fmt.Sprintf("→ %s (%d байт, sha256 %s…)", path, len(data), want[:12]))
	}
	q := target.Quote(path)
	script := "cat > " + q + " && chmod " + mode + " " + q
	if owner != "" {
		script += " && chown " + owner + " " + q
	}
	uctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := sh(uctx, script, data); err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	r, err := sh(ctx, "sha256sum "+q, nil)
	if err != nil {
		return fmt.Errorf("проверка %s: %w", path, err)
	}
	if f := strings.Fields(r.Stdout); len(f) == 0 || f[0] != want {
		return fmt.Errorf("контрольная сумма %s не совпала после записи", path)
	}
	return nil
}

// ControllerShell runs scripts as root on the machine that hosts the
// installed controller: inside its LXC container through the Proxmox node
// (`pct exec`), or on the standalone server (root or `sudo -n`).
type ControllerShell struct {
	sh     shellFn
	closer func() error
}

// Exec runs a shell script, optionally feeding stdin.
func (c *ControllerShell) Exec(ctx context.Context, script string, stdin []byte) (sshx.Result, error) {
	return c.sh(ctx, script, stdin)
}

// PutFile writes data to path (see putFile).
func (c *ControllerShell) PutFile(ctx context.Context, log func(string), path string, data []byte, mode, owner string) error {
	return putFile(ctx, c.sh, log, path, data, mode, owner)
}

// Close drops the SSH connection.
func (c *ControllerShell) Close() error { return c.closer() }

// OpenShell connects to the machine where the controller lives (loc comes
// from settings.controller_location). Host keys are pinned exactly as during
// the installation.
func (s *Service) OpenShell(ctx context.Context, loc Location) (*ControllerShell, error) {
	t, err := s.Store.GetTarget(ctx, loc.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("цель, на которой установлен контроллер, больше не подключена к Hestia")
	}
	if err != nil {
		return nil, err
	}
	switch loc.Kind {
	case "lxc":
		node, ok := findNode(t, loc.Node)
		if !ok {
			return nil, fmt.Errorf("узел %s не найден в цели %s", loc.Node, t.Name)
		}
		cfg, ok := s.nodeCfg(t, node)
		if !ok {
			return nil, fmt.Errorf("у узла %s нет закреплённого SSH-ключа", loc.Node)
		}
		var cl *sshx.Client
		client := func(ctx context.Context) (*sshx.Client, error) {
			if cl != nil && cl.Alive() {
				return cl, nil
			}
			if cl != nil {
				_ = cl.Close()
				cl = nil
			}
			c, err := s.Dial(ctx, cfg)
			if err != nil {
				return nil, fmt.Errorf("вход на узел %s: %w", loc.Node, err)
			}
			cl = c
			return cl, nil
		}
		if _, err := client(ctx); err != nil {
			return nil, err
		}
		return &ControllerShell{sh: pctShell(loc.VMID, client), closer: func() error {
			if cl != nil {
				return cl.Close()
			}
			return nil
		}}, nil
	case "ssh":
		cl, err := s.Dial(ctx, sshx.Config{Host: t.Host, Port: t.Port, User: t.SSHUser,
			Signer: s.Identity.Signer, ExpectedFP: t.HostKeyFP})
		if err != nil {
			return nil, fmt.Errorf("вход на сервер %s: %w", t.Host, err)
		}
		facts, err := target.NewSSH(cl).Facts(ctx)
		if err != nil {
			_ = cl.Close()
			return nil, err
		}
		if !facts.IsRoot() && !facts.Sudo {
			_ = cl.Close()
			return nil, errors.New("на сервере нужен root или sudo без пароля")
		}
		return &ControllerShell{sh: serverShell(cl, facts.IsRoot()), closer: cl.Close}, nil
	}
	return nil, fmt.Errorf("неизвестный вид расположения контроллера %q", loc.Kind)
}
