package onboard

import (
	"context"
	"errors"
	"fmt"

	"hestia/internal/jobs"
	"hestia/internal/proxmox"
	"hestia/internal/sshx"
	"hestia/internal/store"
	"hestia/internal/target"
)

// Remove starts the job that deletes a target. With revert it first undoes
// Hestia's changes on the target using Hestia's own key; without it the target
// is only forgotten locally.
func (s *Service) Remove(ctx context.Context, id int64, revert bool) (store.Job, error) {
	t, err := s.Store.GetTarget(ctx, id)
	if err != nil {
		return store.Job{}, err
	}
	title := "Удаление: " + t.Name
	if revert {
		title = "Удаление с откатом изменений: " + t.Name
	}
	return s.Runner.Start("target.remove", title, func(jctx context.Context, run *jobs.Run) error {
		if revert {
			if err := s.revert(jctx, run, t); err != nil {
				return err
			}
		}
		return run.Step("Удаление записи", func(ctx context.Context) error {
			if err := s.Store.DeleteTarget(ctx, t.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			run.Log("info", "Цель удалена из Hestia")
			return nil
		})
	})
}

func (s *Service) revert(ctx context.Context, run *jobs.Run, t store.Target) error {
	var tg *target.SSH
	if err := run.Step("Подключение ключом Hestia", func(ctx context.Context) error {
		cl, err := s.Dial(ctx, sshx.Config{
			Host: t.Host, Port: t.Port, User: t.SSHUser, Signer: s.Identity.Signer, ExpectedFP: t.HostKeyFP,
		})
		if err != nil {
			return fmt.Errorf("%w (если цель недоступна, удалите её без отката изменений)", err)
		}
		tg = target.NewSSH(cl)
		return nil
	}); err != nil {
		return err
	}
	defer tg.Close()

	sh := func(cmd string) error {
		run.Log("info", "$ "+cmd)
		_, err := tg.Exec(ctx, cmd)
		return err
	}
	if t.Kind == store.KindProxmox {
		var st proxmox.State
		if err := run.Step("Проверка Proxmox", func(ctx context.Context) error {
			var err error
			st, err = proxmox.Inspect(ctx, tg)
			return err
		}); err != nil {
			return err
		}
		type item struct {
			title  string
			exists bool
			cmd    string
			soft   bool // failure is only a warning
		}
		for _, it := range []item{
			{"Удаление API-токена", st.TokenExist, proxmox.CmdTokenDel, false},
			{"Удаление прав на /", st.ACLExists, proxmox.CmdACLDel, false},
			{"Удаление пользователя " + proxmox.UserID, st.UserExists, proxmox.CmdUserDel, false},
			{"Удаление роли " + proxmox.RoleName, st.RoleExists, proxmox.CmdRoleDel, true},
		} {
			err := run.Step(it.title, func(ctx context.Context) error {
				if !it.exists {
					run.Log("info", "Уже отсутствует")
					return nil
				}
				if err := sh(it.cmd); err != nil {
					if it.soft {
						run.Log("warn", "Не удалось, оставляем: "+err.Error())
						return nil
					}
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	// The key goes last: it is the one we are logged in with (the open
	// connection keeps working).
	return run.Step("Удаление ключа Hestia", func(ctx context.Context) error {
		path, err := target.AuthorizedKeysPath(ctx, tg)
		if err != nil {
			return err
		}
		return target.RemoveAuthorizedKey(ctx, tg, path, s.Identity.AuthorizedKey)
	})
}
