package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
	"github.com/uxerror/hestia/sdk"
)

// TargetExec runs a shell script as root on a target given by its grant
// reference ("ssh:<id>" or "lxc:<id>:<node>:<vmid>").
type TargetExec interface {
	Exec(ctx context.Context, ref, script string, stdin []byte) (sshx.Result, error)
}

// Ref is a parsed grant reference.
type Ref struct {
	Kind     string // ssh | lxc
	TargetID int64
	Node     string
	VMID     int
}

// String renders the reference.
func (r Ref) String() string {
	if r.Kind == "lxc" {
		return fmt.Sprintf("lxc:%d:%s:%d", r.TargetID, r.Node, r.VMID)
	}
	return fmt.Sprintf("ssh:%d", r.TargetID)
}

// ParseRef parses a grant reference.
func ParseRef(s string) (Ref, error) {
	parts := strings.Split(s, ":")
	bad := fmt.Errorf("неверная ссылка на цель %q", s)
	if len(parts) < 2 {
		return Ref{}, bad
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || id <= 0 {
		return Ref{}, bad
	}
	switch {
	case parts[0] == "ssh" && len(parts) == 2:
		return Ref{Kind: "ssh", TargetID: id}, nil
	case parts[0] == "lxc" && len(parts) == 4:
		vmid, err := strconv.Atoi(parts[3])
		if err != nil || vmid <= 0 || parts[2] == "" || strings.ContainsAny(parts[2], " /'\"") {
			return Ref{}, bad
		}
		return Ref{Kind: "lxc", TargetID: id, Node: parts[2], VMID: vmid}, nil
	}
	return Ref{}, bad
}

// SSHTargets is the real TargetExec: SSH with Hestia's key and the pinned
// host key; LXC containers through `pct exec` on their node.
type SSHTargets struct {
	Store    *store.Store
	Identity secrets.Identity
	// Dial defaults to sshx.Dial.
	Dial func(ctx context.Context, cfg sshx.Config) (*sshx.Client, error)
}

// Exec runs script on the target.
func (t *SSHTargets) Exec(ctx context.Context, refStr, script string, stdin []byte) (sshx.Result, error) {
	return t.exec(ctx, refStr, script, stdin, false)
}

// ExecNode runs script as root on the Proxmox node of an "lxc:" reference
// (not inside the container).
func (t *SSHTargets) ExecNode(ctx context.Context, refStr, script string) (sshx.Result, error) {
	if !strings.HasPrefix(refStr, "lxc:") {
		return sshx.Result{}, errors.New("команды на узле — только для контейнеров Proxmox")
	}
	return t.exec(ctx, refStr, script, nil, true)
}

func (t *SSHTargets) exec(ctx context.Context, refStr, script string, stdin []byte, onNode bool) (sshx.Result, error) {
	ref, err := ParseRef(refStr)
	if err != nil {
		return sshx.Result{}, err
	}
	dial := t.Dial
	if dial == nil {
		dial = sshx.Dial
	}
	tg, err := t.Store.GetTarget(ctx, ref.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		return sshx.Result{}, errors.New("цель больше не подключена к Hestia")
	}
	if err != nil {
		return sshx.Result{}, err
	}
	var cfg sshx.Config
	cmd := "sh -c " + target.Quote(script)
	switch ref.Kind {
	case "ssh":
		if tg.Kind != store.KindSSH {
			return sshx.Result{}, errors.New("цель не является SSH-сервером")
		}
		cfg = sshx.Config{Host: tg.Host, Port: tg.Port, User: tg.SSHUser, Signer: t.Identity.Signer, ExpectedFP: tg.HostKeyFP}
		if tg.SSHUser != "root" {
			cmd = "sudo -n " + cmd
		}
	case "lxc":
		if tg.Kind != store.KindProxmox {
			return sshx.Result{}, errors.New("цель не является Proxmox")
		}
		var node *store.Node
		for i := range tg.Nodes {
			if tg.Nodes[i].Name == ref.Node {
				node = &tg.Nodes[i]
			}
		}
		if node == nil || node.IP == "" || node.HostKeyFP == "" {
			return sshx.Result{}, fmt.Errorf("у узла %s нет закреплённого SSH-ключа", ref.Node)
		}
		cfg = sshx.Config{Host: node.IP, Port: tg.Port, User: tg.SSHUser, Signer: t.Identity.Signer,
			ExpectedFP: node.HostKeyFP, HostKeyAlgorithms: sshx.AlgorithmsForKeyType(node.HostKeyType)}
		if !onNode {
			cmd = "pct exec " + strconv.Itoa(ref.VMID) + " -- " + cmd
		}
		if tg.SSHUser != "root" {
			cmd = "sudo -n " + cmd
		}
	}
	cl, err := dial(ctx, cfg)
	if err != nil {
		return sshx.Result{}, err
	}
	defer cl.Close()
	return cl.Exec(ctx, cmd, stdin)
}

// Candidate is a target that can be chosen in a "target" field.
type Candidate struct {
	sdk.TargetInfo
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Candidates lists SSH servers and LXC containers (from the inventory) that
// can be granted to instances.
func (m *Manager) Candidates(ctx context.Context) ([]Candidate, error) {
	ts, err := m.Store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := []Candidate{}
	for _, t := range ts {
		var snap *struct {
			os     string
			guests []guestInfo
		}
		if m.Inventory != nil {
			if e, err := m.Inventory.Get(ctx, t.ID); err == nil && e.Snapshot != nil {
				snap = &struct {
					os     string
					guests []guestInfo
				}{}
				if len(e.Snapshot.Nodes) > 0 {
					snap.os = e.Snapshot.Nodes[0].OS
				}
				for _, g := range e.Snapshot.Guests {
					if g.Type == "lxc" && !g.Template {
						addr := ""
						if len(g.IPs) > 0 {
							addr = g.IPs[0]
						}
						snap.guests = append(snap.guests, guestInfo{node: g.Node, vmid: g.VMID, name: g.Name, addr: addr, status: g.Status})
					}
				}
			}
		}
		switch t.Kind {
		case store.KindSSH:
			c := Candidate{TargetInfo: sdk.TargetInfo{
				ID: Ref{Kind: "ssh", TargetID: t.ID}.String(), Kind: "ssh", Name: t.Name, Address: t.Host,
				Root: t.SSHUser == "root", Sudo: t.SSHUser != "root",
			}, Available: true}
			if snap != nil {
				c.OS = snap.os
			}
			// An unknown OS (no inventory yet) is checked by deploy.plan.
			c.DockerCapable = c.OS == "" || debianLike(c.OS)
			out = append(out, c)
		case store.KindProxmox:
			if snap == nil {
				continue
			}
			for _, g := range snap.guests {
				c := Candidate{TargetInfo: sdk.TargetInfo{
					ID: Ref{Kind: "lxc", TargetID: t.ID, Node: g.node, VMID: g.vmid}.String(), Kind: "lxc",
					Name: fmt.Sprintf("%s (CT %d, %s)", g.name, g.vmid, g.node), Address: g.addr, Root: true,
					// The OS of a container is checked when planning.
					DockerCapable: true,
				}, Available: true}
				if g.status != "running" {
					c.Available, c.Reason = false, "контейнер не запущен"
				}
				out = append(out, c)
			}
		}
	}
	return out, nil
}

type guestInfo struct {
	node   string
	vmid   int
	name   string
	addr   string
	status string
}

func debianLike(os string) bool {
	l := strings.ToLower(os)
	return strings.Contains(l, "debian") || strings.Contains(l, "ubuntu")
}
