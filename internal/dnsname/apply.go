package dnsname

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"hestia/internal/integrations/adguard"
	"hestia/internal/jobs"
	"hestia/internal/store"
)

// JobKind is the kind of the job that applies a plan.
const JobKind = "dns-name"

var errStale = errors.New("план устарел: записи в AdGuard или адрес Hestia изменились, составьте план заново")

// Apply starts the job for a confirmed plan (plan_id + hash).
func (s *Service) Apply(ctx context.Context, planID, hash string) (store.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.takePlanLocked(planID, hash)
	if err != nil {
		return store.Job{}, err
	}
	in, err := s.integration(ctx)
	if err != nil {
		return store.Job{}, err
	}
	if in.ID != p.integrationID {
		return store.Job{}, newErr(410, "plan_gone", "Подключение AdGuard изменилось: составьте план заново")
	}
	title := "Имя Hestia: " + p.Domain
	if p.Action == ActionRemove {
		title = "Убрать имя Hestia: " + p.Domain
	}
	job, err := s.Runner.Start(JobKind, title, func(ctx context.Context, run *jobs.Run) error {
		defer func() {
			s.mu.Lock()
			s.applying = ""
			s.mu.Unlock()
		}()
		return s.runApply(ctx, run, in, p)
	})
	if err != nil {
		return store.Job{}, err
	}
	s.applying = job.ID
	return job, nil
}

func (s *Service) runApply(ctx context.Context, run *jobs.Run, in store.Integration, p *planState) error {
	cl, err := s.clientOf(ctx, in)
	if err != nil {
		return err
	}
	var st adguard.Status
	err = run.Step("Проверка плана", func(ctx context.Context) error {
		list, err := cl.RewriteList(ctx)
		if err != nil {
			return mapErr(err)
		}
		if listHash(list) != p.listHash {
			return errStale
		}
		if p.Action != ActionRemove {
			if ip, err := adguard.LocalIP(ctx, in.BaseURL); err != nil || ip != p.Answer {
				return errStale
			}
		}
		if st, err = cl.Status(ctx); err != nil {
			return mapErr(err)
		}
		run.Log("info", "Состояние AdGuard совпадает с планом")
		return nil
	})
	if err != nil {
		return err
	}
	if p.Action == ActionRemove {
		return s.runRemove(run, cl, p)
	}

	changed := false
	err = run.Step("Запись в AdGuard", func(ctx context.Context) error {
		switch p.op {
		case opNone:
			run.Log("info", "Запись уже есть, AdGuard не меняется")
		case opAdd:
			if err := cl.RewriteAdd(ctx, p.Domain, p.Answer); err != nil {
				return mapErr(err)
			}
			changed = true
			run.Log("info", "Добавлено: "+p.Domain+" → "+p.Answer)
		case opUpdate:
			if err := cl.RewriteUpdate(ctx, p.Domain, p.oldAnswer, p.Answer); err != nil {
				return mapErr(err)
			}
			changed = true
			run.Log("info", "Обновлено: "+p.Domain+" "+p.oldAnswer+" → "+p.Answer)
		}
		return nil
	})
	if err != nil {
		return err
	}

	verify := func() error {
		if err := run.Step("Проверка DNS", func(ctx context.Context) error {
			return s.verifyDNS(ctx, run, cl.Host(), st.DNSPort, p.Domain, p.Answer)
		}); err != nil {
			return err
		}
		return run.Step("Проверка доступности по имени", func(ctx context.Context) error {
			return s.verifyHealth(ctx, run, p.Answer, p.Domain)
		})
	}
	err = verify()
	if err == nil {
		err = run.Step("Сохранение", func(ctx context.Context) error {
			now := s.Now().UTC()
			return s.Store.SaveDNSName(ctx, &store.DNSName{IntegrationID: in.ID, Domain: p.Domain, Answer: p.Answer,
				Status: StatusOK, VerifiedAt: &now, CheckedAt: &now})
		})
	}
	if err != nil {
		if changed {
			s.rollback(run, cl, p)
		}
		return err
	}
	run.SetResult(map[string]any{"domain": p.Domain, "answer": p.Answer, "url": "http://" + p.Domain})
	return nil
}

// rollback puts AdGuard back the way it was; it must run even when the job
// was cancelled, so it does not depend on the job context.
func (s *Service) rollback(run *jobs.Run, cl *adguard.Client, p *planState) {
	do := func(ctx context.Context) error {
		// The job context may already be cancelled: the rollback still has to reach AdGuard.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		switch p.op {
		case opAdd:
			return mapErr(cl.RewriteDelete(ctx, p.Domain, p.Answer))
		case opUpdate:
			return mapErr(cl.RewriteUpdate(ctx, p.Domain, p.Answer, p.oldAnswer))
		}
		return nil
	}
	ran := false
	err := run.Step("Откат изменений в AdGuard", func(ctx context.Context) error {
		ran = true
		return do(ctx)
	})
	if !ran { // the job was cancelled before the step could start
		fresh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = do(fresh)
		if err != nil {
			run.Log("error", "Откат не удался: "+err.Error())
		} else {
			run.Log("warn", "Изменения в AdGuard откатаны")
		}
	}
	if err != nil && ran {
		run.Log("error", "Откат не удался, проверьте запись "+p.Domain+" в AdGuard вручную")
	}
}

func (s *Service) runRemove(run *jobs.Run, cl *adguard.Client, p *planState) error {
	if p.op == opDelete {
		if err := run.Step("Удаление записи из AdGuard", func(ctx context.Context) error {
			if err := cl.RewriteDelete(ctx, p.Domain, p.Answer); err != nil {
				return mapErr(err)
			}
			run.Log("info", "Удалено: "+p.Domain+" → "+p.Answer)
			return nil
		}); err != nil {
			return err
		}
	}
	return run.Step("Убрать имя в Hestia", func(ctx context.Context) error {
		n, err := s.Store.GetDNSName(ctx)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return s.Store.DeleteDNSName(ctx, n.ID)
	})
}

// verifyDNS asks the DNS server of AdGuard itself: its cache may need a few
// seconds to forget a negative answer.
func (s *Service) verifyDNS(ctx context.Context, run *jobs.Run, host string, port int, domain, answer string) error {
	if port == 0 {
		port = 53
	}
	server := net.JoinHostPort(host, strconv.Itoa(port))
	want, _ := netip.ParseAddr(answer)
	var last string
	for i := 1; i <= s.DNSAttempts; i++ {
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		got, err := s.Query(qctx, server, domain)
		cancel()
		switch {
		case err != nil:
			last = err.Error()
		case len(got) == 0:
			last = "AdGuard не знает имени " + domain
		default:
			for _, a := range got {
				if a == want {
					run.Log("info", fmt.Sprintf("DNS %s: %s → %s", server, domain, answer))
					return nil
				}
			}
			last = fmt.Sprintf("DNS отвечает %s вместо %s", got[0], answer)
		}
		if i < s.DNSAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.DNSPause):
			}
		}
	}
	return fmt.Errorf("проверка DNS не прошла: %s", last)
}

// verifyHealth opens the controller at its address with the new name as Host:
// the answer must be this very instance.
func (s *Service) verifyHealth(ctx context.Context, run *jobs.Run, ip, domain string) error {
	hostport := ip
	if s.HealthPort != 80 {
		hostport = net.JoinHostPort(ip, strconv.Itoa(s.HealthPort))
	} else if strings.Contains(ip, ":") {
		hostport = "[" + ip + "]"
	}
	var last string
	for i := 1; i <= 3; i++ {
		last = s.healthOnce(ctx, "http://"+hostport+"/api/v1/health", domain)
		if last == "" {
			run.Log("info", "http://"+domain+" отвечает Hestia")
			return nil
		}
		if i < 3 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.DNSPause):
			}
		}
	}
	return errors.New("проверка доступности не прошла: " + last)
}

func (s *Service) healthOnce(ctx context.Context, url, host string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err.Error()
	}
	req.Host = host
	resp, err := (&http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			err = ue.Unwrap()
		}
		return "Hestia не отвечает на " + url + ": " + err.Error()
	}
	defer resp.Body.Close()
	var h struct {
		Status     string `json:"status"`
		InstanceID string `json:"instance_id"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h) != nil || h.Status != "ok" {
		return fmt.Sprintf("по адресу %s отвечает не Hestia (ответ %d)", url, resp.StatusCode)
	}
	if h.InstanceID != s.InstanceID {
		return "по имени открывается другая Hestia (другой instance_id)"
	}
	return ""
}
