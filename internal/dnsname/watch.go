package dnsname

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/integrations/adguard"
	"github.com/uxerror/hestia/internal/store"
)

// evaluate compares the rewrites of AdGuard with the bound name and the
// address the controller has now.
func evaluate(n store.DNSName, list []adguard.Rewrite, ip string) (status, detail string) {
	exact := exactRecords(list, n.Domain)
	if len(exact) == 0 {
		return StatusMissing, "Записи " + n.Domain + " больше нет в AdGuard"
	}
	for _, r := range exact {
		if r.Answer == ip && enabled(r) {
			return StatusOK, ""
		}
	}
	for _, r := range exact {
		if r.Answer == n.Answer && enabled(r) {
			return StatusIPChanged, "Запись указывает на " + n.Answer + ", а адрес Hestia теперь " + ip
		}
	}
	answers := make([]string, 0, len(exact))
	for _, r := range exact {
		answers = append(answers, r.Answer)
	}
	return StatusChanged, "Запись указывает на " + strings.Join(answers, ", ") + ", а не на адрес Hestia " + ip
}

// Check refreshes the status of the name: GET requests to AdGuard only.
func (s *Service) Check(ctx context.Context) error {
	n, err := s.Store.GetDNSName(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	busy := s.applying != ""
	s.mu.Unlock()
	if busy {
		return nil // the job writes the status itself
	}
	in, err := s.Store.GetIntegrationByKind(ctx, store.KindAdGuard)
	if err != nil {
		return err
	}
	status, detail, answer := s.probeStatus(ctx, in, n)
	return s.Store.UpdateDNSNameStatus(ctx, n.ID, status, detail, answer, s.Now().UTC(), nil)
}

func (s *Service) probeStatus(ctx context.Context, in store.Integration, n store.DNSName) (status, detail, answer string) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	fail := func(err error) (string, string, string) {
		var ce *adguard.CertChangedError
		var ue *adguard.UnreachableError
		switch {
		case errors.As(err, &ce):
			return StatusCertChanged, "Сертификат AdGuard изменился, новый отпечаток " + ce.Fingerprint, ""
		case errors.Is(err, adguard.ErrAuth):
			return StatusAuthFailed, "AdGuard не принимает сохранённые логин и пароль", ""
		case errors.As(err, &ue):
			return StatusUnreachable, ue.Error(), ""
		}
		return StatusUnreachable, err.Error(), ""
	}
	cl, err := s.clientOf(cctx, in)
	if err != nil {
		return fail(err)
	}
	list, err := cl.RewriteList(cctx)
	if err != nil {
		return fail(err)
	}
	ip, err := adguard.LocalIP(cctx, in.BaseURL)
	if err != nil {
		return fail(err)
	}
	status, detail = evaluate(n, list, ip)
	if status == StatusOK && n.Answer != ip {
		answer = ip // the record already follows the new address
	}
	return status, detail, answer
}

// Start runs the watcher: a check shortly after start and then periodically.
// It stops with ctx; Wait waits for it.
func (s *Service) Start(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		timer := time.NewTimer(s.FirstCheck)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if err := s.Check(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("проверка имени Hestia", "err", err)
			}
			timer.Reset(s.CheckEvery)
		}
	}()
}
