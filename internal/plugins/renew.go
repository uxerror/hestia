package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// Links whose type has a request (tls.cert) and renewable links: the
// consumer is asked for the request (link.prepare) before the provider, the
// binding is checked against it, and Hestia renews the link itself at 2/3
// of its lifetime (job link-renew).

// JobRenew is the job kind of a renewal ("Продлить сейчас" or scheduled).
const JobRenew = "link-renew"

// RenewInterval is how often due renewals are looked for.
const RenewInterval = time.Minute

// msgNamesChanged starts the renewal error of a link whose consumer now
// asks for other names: only a confirmed plan (reissue) may issue them.
const msgNamesChanged = "Имена изменились: "

// renewBackoff is the delay before the n-th retry of a failed renewal.
func renewBackoff(n int) time.Duration {
	switch {
	case n <= 1:
		return 5 * time.Minute
	case n == 2:
		return 15 * time.Minute
	}
	return time.Hour
}

// publicRequest is the request of a link as the API shows it: the names
// only (the CSR is not secret, but nobody needs to read it there).
func publicRequest(s string) json.RawMessage {
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil || len(m) == 0 {
		return nil
	}
	delete(m, "csr_pem")
	b, _ := json.Marshal(m)
	return b
}

func decodeTLSRequest(raw json.RawMessage) types.TLSRequest {
	var r types.TLSRequest
	_ = json.Unmarshal(raw, &r)
	return r
}

// prepareRequest asks the consumer for the request of the link
// (link.prepare) and checks it against the type; for a create or a reissue
// the names must equal the preview of the confirmed plan.
func (m *Manager) prepareRequest(ctx context.Context, run *jobs.Run, ls *linkStep, reason string) (json.RawMessage, error) {
	action := sdk.ActionCreate
	if reason != sdk.ReasonCreate {
		action = sdk.ActionUpdate
	}
	req := ls.request(ls.consumer, action)
	req.Reason = reason
	run.Log("info", fmt.Sprintf("«%s»: запрос сертификата (link.prepare, %s)", ls.consumer.inst.Name, reason))
	var out sdk.LinkPrepared
	if err := m.callLink(ctx, ls, ls.consumer, sdk.MethodLinkPrepare, req, &out, run, nil); err != nil {
		return nil, err
	}
	if len(out.Request) == 0 || string(out.Request) == "null" {
		return nil, fmt.Errorf("«%s» не вернул запрос (request)", ls.consumer.inst.Name)
	}
	if len(out.Request) > types.MaxBinding {
		return nil, fmt.Errorf("«%s»: запрос слишком большой", ls.consumer.inst.Name)
	}
	if _, err := types.ValidateRequest(ls.typ, out.Request, false); err != nil {
		return nil, fmt.Errorf("«%s»: запрос не по контракту типа: %v", ls.consumer.inst.Name, err)
	}
	got := decodeTLSRequest(out.Request)
	if ls.typ == types.TLSCertType {
		if _, err := types.ParseCSR(got.CSRPEM); err != nil {
			return nil, fmt.Errorf("«%s»: %v", ls.consumer.inst.Name, err)
		}
	}
	if reason != sdk.ReasonRenew {
		want := decodeTLSRequest(ls.consPlan.Request)
		if !got.SameNames(want) {
			return nil, fmt.Errorf("«%s» запросил другие имена (%s), чем в подтверждённом плане (%s) — составьте план заново",
				ls.consumer.inst.Name, strings.Join(got.Names(), ", "), strings.Join(want.Names(), ", "))
		}
	}
	return canonical(out.Request)
}

// checkRequestBinding checks a binding against the request it answers
// (tls.cert: key, names, chain, lifetime; see types.CheckTLSCert).
func checkRequestBinding(typ string, binding, request json.RawMessage, wantCA string, now time.Time) error {
	if typ != types.TLSCertType {
		return nil
	}
	var b types.TLSCert
	if err := json.Unmarshal(binding, &b); err != nil {
		return fmt.Errorf("данные связи: %v", err)
	}
	if err := types.CheckTLSCert(b, decodeTLSRequest(request), wantCA, now); err != nil {
		return fmt.Errorf("сертификат от поставщика отклонён: %v", err)
	}
	return nil
}

// providerRoot is the root a provider is pinned to for a link: the root of
// the link's current binding (renewal, reissue), else the root the same
// instance gives by ca.issuer or in its other tls.cert links. "" if none.
func (m *Manager) providerRoot(ctx context.Context, iid, link int64) string {
	fp := func(binding string) (issuer, cert string) {
		var b map[string]any
		if json.Unmarshal([]byte(binding), &b) != nil {
			return "", ""
		}
		if s, ok := b["ca_sha256"].(string); ok {
			cert = types.NormalizeSHA256(s)
		}
		if s, ok := b["sha256"].(string); ok {
			issuer = types.NormalizeSHA256(s)
		} else if s, ok := b["ca_pem"].(string); ok && cert == "" {
			if c, err := types.ParseCert(s); err == nil {
				issuer = types.CertSHA256(c.Raw)
			}
		}
		return issuer, cert
	}
	if l, err := m.Store.GetLink(ctx, link); err == nil {
		if _, c := fp(l.Binding); c != "" {
			return c
		}
	}
	links, err := m.Store.LinksOfInstance(ctx, iid)
	if err != nil {
		return ""
	}
	other := ""
	for _, l := range links {
		if l.ID == link || l.ProviderInstance != iid || !l.Active() {
			continue
		}
		i, c := fp(l.Binding)
		if i != "" {
			return i
		}
		if other == "" {
			other = c
		}
	}
	return other
}

// recordRenewal stores when a binding of a renewable type expires and is
// renewed (and clears a renewal error).
func (m *Manager) recordRenewal(ctx context.Context, id int64, typ, binding string) error {
	t, ok := types.Lookup(typ)
	if !ok || !t.Renewable {
		return nil
	}
	var b struct {
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
	}
	if err := json.Unmarshal([]byte(binding), &b); err != nil {
		return err
	}
	if !b.NotAfter.After(b.NotBefore) {
		return errors.New("not_after не позже not_before")
	}
	m.mu.Lock()
	delete(m.renewFails, id)
	m.mu.Unlock()
	return m.Store.SetLinkRenewal(ctx, id, b.NotAfter, types.RenewAfter(b.NotBefore, b.NotAfter))
}

func dateText(t time.Time) string { return t.Local().Format("02.01.2006 15:04") }

// renewalState is the state of a link from its renewal ("" if fine): down
// after expiry, degraded when the names changed or the renewal fails for
// longer than 10 % of the lifetime past renew_after.
func renewalState(l store.PluginLink, now time.Time) (string, string) {
	if l.ExpiresAt == nil {
		return "", ""
	}
	if !now.Before(*l.ExpiresAt) {
		return sdk.StateDown, "Сертификат истёк " + dateText(*l.ExpiresAt)
	}
	if strings.HasPrefix(l.RenewError, msgNamesChanged) {
		return sdk.StateDegraded, l.RenewError
	}
	if l.RenewError != "" && l.RenewAfter != nil {
		life := 3 * l.ExpiresAt.Sub(*l.RenewAfter)
		if now.After(l.RenewAfter.Add(life / 10)) {
			return sdk.StateDegraded, fmt.Sprintf("Продление не удалось: %s. Сертификат действует до %s", l.RenewError, dateText(*l.ExpiresAt))
		}
	}
	return "", ""
}

// errNamesChanged: the consumer asks for other names than were confirmed.
type errNamesChanged struct{ msg string }

func (e *errNamesChanged) Error() string { return e.msg }

// rotateLink gets a new binding for a link with a request: link.prepare at
// the consumer → link.refresh {request} at the provider → checks →
// link.apply {update} at the consumer. On failure the previous binding
// stays in use. A renewal with other names stops before the provider.
func (m *Manager) rotateLink(ctx context.Context, run *jobs.Run, ls *linkStep, reason string) error {
	id := ls.link.ID
	bg := context.WithoutCancel(ctx)
	full, err := m.prepareRequest(ctx, run, ls, reason)
	if err != nil {
		return err
	}
	if reason == sdk.ReasonRenew {
		prev, got := decodeTLSRequest(json.RawMessage(ls.link.Request)), decodeTLSRequest(full)
		if !got.SameNames(prev) {
			return &errNamesChanged{msg: fmt.Sprintf("%s%s → %s — нужен план", msgNamesChanged,
				strings.Join(prev.Names(), ", "), strings.Join(got.Names(), ", "))}
		}
	}
	run.Log("info", fmt.Sprintf("«%s»: выпуск (link.refresh)", ls.provider.inst.Name))
	var res sdk.LinkResult
	preq := ls.request(&ls.provider, sdk.ActionUpdate)
	preq.Request, preq.Reason = full, reason
	if err := m.callLink(ctx, ls, &ls.provider, sdk.MethodLinkRefresh, preq, &res, run, nil); err != nil {
		return err
	}
	binding, secs, err := processBinding(id, ls.typ, res.Binding, true)
	if err == nil {
		err = checkRequestBinding(ls.typ, res.Binding, full, m.providerRoot(ctx, ls.provider.inst.ID, id), m.Now())
	}
	if err != nil {
		return err
	}
	var nb types.TLSCert
	_ = json.Unmarshal([]byte(binding), &nb)
	if nb.Serial != "" {
		run.Log("info", fmt.Sprintf("Выпущен сертификат %s, действует до %s", nb.Serial, dateText(nb.NotAfter)))
	}
	run.Log("info", fmt.Sprintf("«%s»: установка нового сертификата", ls.consumer.inst.Name))
	creq := ls.request(ls.consumer, sdk.ActionUpdate)
	creq.Binding, creq.Request, creq.Reason = json.RawMessage(binding), full, reason
	creq.Plan = &ls.consPlan
	if err := m.callLink(ctx, ls, ls.consumer, sdk.MethodLinkApply, creq, nil, run, secretValues(secs)); err != nil {
		if nb.Serial != "" {
			run.Log("warn", fmt.Sprintf("Сертификат %s выпущен, но не применён (не отзывается, истечёт сам)", nb.Serial))
		}
		return err
	}
	if err := m.Store.DeleteSecretsByPrefix(bg, linkSecretPrefix(id)); err != nil {
		return err
	}
	if err := m.storeLinkSecrets(bg, id, secs); err != nil {
		return err
	}
	if err := m.Store.SetLinkBinding(bg, id, binding); err != nil {
		return err
	}
	if err := m.Store.SetLinkRequest(bg, id, string(full)); err != nil {
		return err
	}
	if err := m.recordRenewal(bg, id, ls.typ, binding); err != nil {
		run.Log("warn", "Срок действия связи: "+err.Error())
	}
	run.Log("info", "Связь обновлена: "+ls.title())
	return nil
}

// RenewLink starts a renewal of a renewable link now (job link-renew); 409
// while a job works on either side.
func (m *Manager) RenewLink(ctx context.Context, id int64) (store.Job, error) {
	l, err := m.Store.GetLink(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && l.Status == store.LinkDraft) {
		return store.Job{}, newErr(http.StatusNotFound, "связь не найдена")
	}
	if err != nil {
		return store.Job{}, err
	}
	if !l.Active() || l.Status == store.LinkApplying {
		return store.Job{}, newErr(http.StatusConflict, "со связью уже выполняется задача")
	}
	ls, err := m.existingLinkStep(ctx, l)
	if err != nil {
		return store.Job{}, err
	}
	if t, ok := types.Lookup(ls.typ); !ok || !t.Renewable || !ls.hasRequest() {
		return store.Job{}, newErr(http.StatusBadRequest, "связь типа %s не продлевается", ls.typ)
	}
	ls.action = sdk.ActionUpdate
	ids := []int64{ls.provider.inst.ID, ls.consumer.inst.ID}
	m.mu.Lock()
	for _, iid := range ids {
		if m.instJobs[iid] {
			m.mu.Unlock()
			return store.Job{}, newErr(http.StatusConflict, "со связью уже выполняется задача")
		}
	}
	for _, iid := range ids {
		m.instJobs[iid] = true
	}
	m.mu.Unlock()
	job, err := m.Runner.Start(JobRenew, "Hestia: продление связи "+ls.title(), func(ctx context.Context, run *jobs.Run) error {
		defer m.releaseInstances(ids...)
		err := m.rotateLink(ctx, run, ls, sdk.ReasonRenew)
		bg := context.WithoutCancel(ctx)
		if err != nil {
			var nc *errNamesChanged
			retry := m.Now().Add(time.Hour)
			msg := truncate(err.Error(), 1000)
			run.Log("error", msg)
			if errors.As(err, &nc) {
				run.Log("warn", nc.msg+": сертификат не выпущен, нужен план «reissue»")
			} else {
				m.mu.Lock()
				m.renewFails[id]++
				n := m.renewFails[id]
				m.mu.Unlock()
				retry = m.Now().Add(renewBackoff(n))
				run.Log("warn", "Прежний сертификат остаётся в работе; повтор "+dateText(retry))
			}
			_ = m.Store.SetLinkRenewError(bg, id, msg, retry.UTC())
		}
		go m.refreshLink(m.ctx, id)
		return err
	})
	if err != nil {
		m.releaseInstances(ids...)
	}
	return job, err
}

// renewDue starts the renewals that are due (one job per link; links whose
// sides are busy wait for the next tick).
func (m *Manager) renewDue(ctx context.Context) {
	list, err := m.Store.DueRenewals(ctx, m.Now())
	if err != nil {
		return
	}
	for _, l := range list {
		if ctx.Err() != nil {
			return
		}
		if _, err := m.RenewLink(ctx, l.ID); err != nil {
			var pe *Error
			if !errors.As(err, &pe) || pe.Status != http.StatusConflict {
				_ = m.Store.SetLinkRenewError(ctx, l.ID, truncate(errText(err), 1000), m.Now().Add(time.Hour).UTC())
			}
		}
	}
}

// ReissuePlan plans a new certificate with the consumer's current names
// from the same provider (types with a request).
func (m *Manager) reissuePlan(ctx context.Context, l store.PluginLink) (*PlanView, error) {
	ls, err := m.existingLinkStep(ctx, l)
	if err != nil {
		return nil, err
	}
	if !ls.hasRequest() {
		return nil, newErr(http.StatusBadRequest, "повторный выпуск есть только у связей с запросом (tls.cert)")
	}
	ls.action = actionReissue
	if err := m.planSides(ctx, ls); err != nil {
		return nil, err
	}
	cp := &compositePlan{kind: compLink, title: "повторный выпуск " + ls.title(),
		root: InstanceRefV{ID: ls.provider.inst.ID, Name: ls.provider.inst.Name}, steps: []*compStep{{link: ls}}}
	return m.register(cp)
}
