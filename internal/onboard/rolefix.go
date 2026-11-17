package onboard

import (
	"context"
	"fmt"
	"time"

	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/target"
)

// RolePlan describes what "complete the Hestia role" would change on a
// Proxmox target. It is computed by a read-only look at the role; nothing is
// changed until FixRole is confirmed.
type RolePlan struct {
	Needed  bool     `json:"needed"`
	Version string   `json:"version"`
	Missing []string `json:"missing"`
	Command string   `json:"command"`
}

// hestiaLogin dials the target with Hestia's own key and the pinned host key.
func (s *Service) hestiaLogin(ctx context.Context, t store.Target) (*target.SSH, error) {
	cl, err := s.Dial(ctx, sshx.Config{Host: t.Host, Port: t.Port, User: t.SSHUser, Signer: s.Identity.Signer, ExpectedFP: t.HostKeyFP})
	if err != nil {
		return nil, err
	}
	return target.NewSSH(cl), nil
}

func (s *Service) proxmoxTarget(ctx context.Context, id int64) (store.Target, error) {
	t, err := s.Store.GetTarget(ctx, id)
	if err != nil {
		return t, err
	}
	if t.Kind != store.KindProxmox {
		return t, newErr(400, "это не Proxmox: у отдельного сервера нет роли Hestia", nil)
	}
	return t, nil
}

func rolePlanOf(st proxmox.State) RolePlan {
	p := RolePlan{Version: st.Version, Missing: []string{}}
	switch {
	case !st.RoleExists:
		p.Needed, p.Missing = true, proxmox.PrivilegesFor(st.Version)
		p.Command = proxmox.CmdRoleCreate(st.Version)
	case len(st.MissingPrivs()) > 0:
		p.Needed, p.Missing = true, st.MissingPrivs()
		p.Command = proxmox.CmdRoleModify(st.Version, st.RolePrivs)
	}
	return p
}

// RolePlan reads the current Hestia role over SSH (read-only).
func (s *Service) RolePlan(ctx context.Context, id int64) (RolePlan, error) {
	t, err := s.proxmoxTarget(ctx, id)
	if err != nil {
		return RolePlan{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tg, err := s.hestiaLogin(ctx, t)
	if err != nil {
		return RolePlan{}, newErr(422, "вход ключом Hestia не удался: "+err.Error(), err)
	}
	defer tg.Close()
	st, err := proxmox.Inspect(ctx, tg)
	if err != nil {
		return RolePlan{}, newErr(422, "проверка роли не удалась: "+err.Error(), err)
	}
	return rolePlanOf(st), nil
}

// FixRole starts the job that completes the role. The caller must have shown
// the plan to the user and received a confirmation.
func (s *Service) FixRole(ctx context.Context, id int64) (store.Job, error) {
	t, err := s.proxmoxTarget(ctx, id)
	if err != nil {
		return store.Job{}, err
	}
	return s.Runner.Start("target.role_fix", "Дополнение роли Hestia: "+t.Name, func(jctx context.Context, run *jobs.Run) error {
		var tg *target.SSH
		if err := run.Step("Подключение ключом Hestia", func(ctx context.Context) error {
			var err error
			tg, err = s.hestiaLogin(ctx, t)
			return err
		}); err != nil {
			return err
		}
		defer tg.Close()
		var plan RolePlan
		if err := run.Step("Проверка роли "+proxmox.RoleName, func(ctx context.Context) error {
			st, err := proxmox.Inspect(ctx, tg)
			if err != nil {
				return err
			}
			plan = rolePlanOf(st)
			if plan.Needed {
				run.Log("info", fmt.Sprintf("Не хватает прав: %v", plan.Missing))
			}
			return nil
		}); err != nil {
			return err
		}
		err := run.Step("Дополнение роли", func(ctx context.Context) error {
			if !plan.Needed {
				run.Log("info", "Роль уже в порядке — изменений не требуется")
				return nil
			}
			run.Log("info", "$ "+plan.Command)
			_, err := tg.Exec(ctx, plan.Command)
			return err
		})
		if err == nil && s.AfterChange != nil {
			s.AfterChange(t.ID) // the inventory can now read what it could not
		}
		return err
	})
}
