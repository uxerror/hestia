package dnsname

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/uxerror/hestia/internal/integrations/adguard"
	"github.com/uxerror/hestia/internal/store"
)

const (
	planTTL  = 15 * time.Minute
	maxPlans = 16
)

// Plan operations (what the apply job does in AdGuard).
const (
	opNone   = "none" // the record is already right: only check and bind
	opAdd    = "add"
	opUpdate = "update" // old answer → new answer
	opDelete = "delete"
	opUnbind = "unbind" // nothing to delete in AdGuard: only forget the name
)

// planState is a confirmed-to-be plan kept in memory until applied or expired.
type planState struct {
	Plan
	integrationID int64
	op            string
	oldAnswer     string
	listHash      string
	expires       time.Time
}

// listHash fingerprints the rewrites: a plan is only valid for the state of
// AdGuard it was made from.
func listHash(list []adguard.Rewrite) string {
	lines := make([]string, 0, len(list))
	for _, r := range list {
		on := true
		if r.Enabled != nil {
			on = *r.Enabled
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%t", strings.ToLower(r.Domain), r.Answer, on))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// planHash covers everything the user confirms.
func planHash(p *planState) string {
	b, _ := json.Marshal(struct {
		ID, Action, Domain, Answer, Op, Old, List string
		Integration                               int64
		Actions                                   []PlanAction
		Conflicts                                 []Conflict
	}{p.PlanID, p.Action, p.Domain, p.Answer, p.op, p.oldAnswer, p.listHash, p.integrationID, p.Actions, p.Conflicts})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func exactRecords(list []adguard.Rewrite, domain string) []adguard.Rewrite {
	var out []adguard.Rewrite
	for _, r := range list {
		if strings.EqualFold(strings.TrimSuffix(r.Domain, "."), domain) {
			out = append(out, r)
		}
	}
	return out
}

func enabled(r adguard.Rewrite) bool { return r.Enabled == nil || *r.Enabled }

// MakePlan reads the rewrites (GET) and builds the plan for an action.
func (s *Service) MakePlan(ctx context.Context, action, rawDomain string) (*Plan, error) {
	in, err := s.integration(ctx)
	if err != nil {
		return nil, err
	}
	switch action {
	case ActionAdd, ActionReplace, ActionUpdateIP, ActionRemove:
	default:
		return nil, newErr(400, "bad_request", "неизвестное действие")
	}
	name, nameErr := s.Store.GetDNSName(ctx)
	if nameErr != nil && !errors.Is(nameErr, store.ErrNotFound) {
		return nil, nameErr
	}
	bound := nameErr == nil
	domain := ""
	if action == ActionUpdateIP || action == ActionRemove {
		if !bound {
			return nil, newErr(409, "no_name", "у Hestia нет имени в сети")
		}
		domain = name.Domain
	} else {
		if domain, err = NormalizeDomain(rawDomain); err != nil {
			return nil, newErr(400, "bad_domain", err.Error())
		}
	}

	cl, err := s.clientOf(ctx, in)
	if err != nil {
		return nil, err
	}
	list, err := cl.RewriteList(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	ip, err := adguard.LocalIP(ctx, in.BaseURL)
	if err != nil {
		return nil, mapErr(err)
	}

	st := &planState{integrationID: in.ID, listHash: listHash(list), expires: s.Now().Add(planTTL)}
	st.Action, st.Domain, st.Answer = action, domain, ip
	st.Actions, st.Conflicts, st.Warnings = []PlanAction{}, []Conflict{}, []string{}
	exact := exactRecords(list, domain)

	if action == ActionRemove {
		st.Answer = name.Answer
		if err := s.planRemove(st, exact, name); err != nil {
			return nil, err
		}
	} else {
		if err := s.planPut(ctx, st, exact, list); err != nil {
			return nil, err
		}
		s.putWarnings(ctx, st, cl, list, ip)
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	st.PlanID = hex.EncodeToString(b)
	st.Hash = planHash(st)
	s.mu.Lock()
	s.purgePlansLocked()
	s.plans[st.PlanID] = st
	s.mu.Unlock()
	p := st.Plan
	return &p, nil
}

func (s *Service) planRemove(st *planState, exact []adguard.Rewrite, name store.DNSName) error {
	del := fmt.Sprintf("%s → %s", st.Domain, st.Answer)
	for _, r := range exact {
		if r.Answer == name.Answer {
			st.op = opDelete
			st.Actions = append(st.Actions,
				PlanAction{ID: "delete", Kind: "delete", Title: "Удалить запись из AdGuard", Detail: del},
				PlanAction{ID: "unbind", Kind: "unbind", Title: "Убрать имя в Hestia", Detail: st.Domain})
			return nil
		}
	}
	st.op = opUnbind
	st.Actions = append(st.Actions, PlanAction{ID: "unbind", Kind: "unbind", Title: "Убрать имя в Hestia", Detail: st.Domain})
	if len(exact) == 0 {
		st.Warnings = append(st.Warnings, "Записи "+st.Domain+" в AdGuard уже нет: имя будет только убрано в Hestia")
	} else {
		st.Warnings = append(st.Warnings, "В AdGuard "+st.Domain+" указывает не на тот адрес, что запомнила Hestia ("+exact[0].Answer+"): запись не тронута, имя будет только убрано в Hestia")
	}
	return nil
}

func (s *Service) planPut(ctx context.Context, st *planState, exact []adguard.Rewrite, list []adguard.Rewrite) error {
	target := fmt.Sprintf("%s → %s", st.Domain, st.Answer)
	verify := []PlanAction{
		{ID: "verify-dns", Kind: "verify", Title: "Проверить имя запросом к DNS AdGuard", Detail: st.Domain},
		{ID: "verify-http", Kind: "verify", Title: "Проверить, что по имени отвечает Hestia", Detail: "http://" + st.Domain},
		{ID: "bind", Kind: "bind", Title: "Запомнить имя в Hestia", Detail: target},
	}
	var same, other []adguard.Rewrite
	for _, r := range exact {
		if r.Answer == st.Answer {
			same = append(same, r)
		} else {
			other = append(other, r)
		}
	}
	switch {
	case len(same) > 0 && enabled(same[0]) && len(other) == 0:
		st.op, st.NoOp = opNone, true
		st.Warnings = append(st.Warnings, "Запись уже есть в AdGuard: она будет только проверена и привязана")
	case len(same) > 0 && !enabled(same[0]) && len(other) == 0:
		st.op, st.oldAnswer = opUpdate, st.Answer
		st.Actions = append(st.Actions, PlanAction{ID: "enable", Kind: "update", Title: "Включить запись в AdGuard", Detail: target})
	case len(exact) == 0:
		st.op = opAdd
		st.Actions = append(st.Actions, PlanAction{ID: "add", Kind: "add", Title: "Добавить запись в AdGuard", Detail: target})
	default:
		// A record with another answer: the user decides separately.
		replaceable := len(exact) == 1 && len(other) == 1
		switch {
		case replaceable && (st.Action == ActionReplace || st.Action == ActionUpdateIP):
			st.op, st.oldAnswer = opUpdate, other[0].Answer
			st.Actions = append(st.Actions, PlanAction{ID: "update", Kind: "update", Title: "Заменить запись в AdGuard",
				Detail: fmt.Sprintf("%s: %s → %s", st.Domain, other[0].Answer, st.Answer)})
		case !replaceable && (st.Action == ActionReplace || st.Action == ActionUpdateIP):
			return newErr(409, "multiple_records", "У имени "+st.Domain+" в AdGuard несколько записей: оставьте одну в AdGuard и составьте план заново")
		default:
			st.op = opNone
			for _, r := range exact {
				st.Conflicts = append(st.Conflicts, Conflict{Domain: r.Domain, Answer: r.Answer, Owner: s.ownerOf(ctx, r.Answer)})
			}
			return nil // no actions until the replacement is confirmed
		}
	}
	st.Actions = append(st.Actions, verify...)
	return nil
}

func (s *Service) putWarnings(ctx context.Context, st *planState, cl *adguard.Client, list []adguard.Rewrite, ip string) {
	for _, w := range coveringWildcards(list, st.Domain) {
		st.Warnings = append(st.Warnings, fmt.Sprintf("В AdGuard есть запись %s → %s, она накрывает это имя; точная запись имеет приоритет", w.Domain, w.Answer))
	}
	if a, err := netip.ParseAddr(ip); err == nil && (a.IsLoopback() || a.IsUnspecified()) {
		st.Warnings = append(st.Warnings, "Адрес "+ip+" виден только на этом компьютере: другие устройства по имени Hestia не найдут")
	}
	if s.isLocal(ctx) {
		st.Warnings = append(st.Warnings, "Hestia пока работает на этом компьютере; лучше сначала перенести её на сервер")
	}
	if on, err := cl.RewritesEnabled(ctx); err == nil && !on {
		st.Warnings = append(st.Warnings, "В AdGuard выключены DNS-перезаписи (rewrite): запись не будет работать, пока их не включить")
	}
}

func (s *Service) purgePlansLocked() {
	now := s.Now()
	for k, p := range s.plans {
		if now.After(p.expires) {
			delete(s.plans, k)
		}
	}
	for len(s.plans) >= maxPlans {
		oldest := ""
		for k, p := range s.plans {
			if oldest == "" || p.expires.Before(s.plans[oldest].expires) {
				oldest = k
			}
		}
		delete(s.plans, oldest)
	}
}

// takePlanLocked returns a plan by id and hash and removes it: a plan is
// applied once. The caller holds s.mu.
func (s *Service) takePlanLocked(id, hash string) (*planState, error) {
	s.purgePlansLocked()
	p, ok := s.plans[id]
	if !ok {
		return nil, newErr(410, "plan_gone", "План устарел или не найден: составьте его заново")
	}
	if p.Hash != hash {
		return nil, newErr(400, "bad_hash", "Подтверждён не тот план: составьте его заново")
	}
	if len(p.Actions) == 0 {
		return nil, newErr(409, "empty_plan", "В плане нет действий: сначала подтвердите замену чужой записи")
	}
	if s.applying != "" {
		return nil, &Error{HTTP: 409, Code: "busy", Msg: "Уже выполняется задача по имени Hestia", Job: s.applying}
	}
	delete(s.plans, id)
	return p, nil
}
