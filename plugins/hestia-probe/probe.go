package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// Timeouts and defaults.
var (
	checkTimeout    = 5 * time.Second
	defaultInterval = 60 * time.Second
)

// stateFile keeps the bindings in $STATE_DIRECTORY (systemd); without it
// (dev mode) they live in memory and come back with the hello of Hestia.
const stateFile = "links.json"

// result is the outcome of one check.
type result struct {
	state  string
	detail string
	at     time.Time
}

// target is what an instance checks.
type target struct {
	Link    int64             `json:"link"`
	Binding types.HTTPService `json:"binding"`
}

type probe struct {
	// HTTP does the checks (tests replace it); Now is the clock.
	HTTP *http.Client
	// StateDir overrides $STATE_DIRECTORY ("" and no env: memory only).
	StateDir string

	mu       sync.Mutex
	loaded   bool
	targets  map[int64]target // instance → linked provider
	last     map[int64]result
	pollers  map[int64]context.CancelFunc
	interval map[int64]time.Duration
}

func newProbe() *probe {
	return &probe{targets: map[int64]target{}, last: map[int64]result{}, pollers: map[int64]context.CancelFunc{},
		interval: map[int64]time.Duration{}}
}

var _ sdk.Plugin = (*probe)(nil)
var _ sdk.Linker = (*probe)(nil)

func (p *probe) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: checkTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *probe) stateDir() string {
	if p.StateDir != "" {
		return p.StateDir
	}
	return os.Getenv("STATE_DIRECTORY")
}

// load restores the bindings once: from the state file and from the active
// links Hestia listed in its welcome (those win).
func (p *probe) load(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded {
		return
	}
	p.loaded = true
	if dir := p.stateDir(); dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, stateFile)); err == nil {
			_ = json.Unmarshal(b, &p.targets)
		}
	}
	host := sdk.HostFrom(ctx)
	if host == nil {
		return
	}
	w := host.Welcome()
	known := map[int64]sdk.Instance{}
	for _, in := range w.Instances {
		known[in.ID] = in
	}
	for id := range p.targets {
		if _, ok := known[id]; !ok {
			delete(p.targets, id) // the instance is gone
		}
	}
	for _, l := range w.Links {
		if l.Role != sdk.RoleConsumer {
			continue
		}
		var b types.HTTPService
		if json.Unmarshal(l.Binding, &b) == nil && b.URL != "" {
			p.targets[l.Instance] = target{Link: l.Link, Binding: b}
		}
	}
	for id := range p.targets {
		p.interval[id] = intervalOf(known[id].Config)
		p.startLocked(id)
	}
	p.saveLocked()
}

func (p *probe) saveLocked() {
	dir := p.stateDir()
	if dir == "" {
		return
	}
	b, _ := json.Marshal(p.targets)
	tmp := filepath.Join(dir, stateFile+".tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(dir, stateFile))
	}
}

func intervalOf(cfg sdk.Config) time.Duration {
	if s := cfg.Int("interval_s"); s >= 30 && s <= 3600 {
		return time.Duration(s) * time.Second
	}
	return defaultInterval
}

// startLocked (re)starts the poller of an instance (p.mu held).
func (p *probe) startLocked(id int64) {
	if c := p.pollers[id]; c != nil {
		c()
	}
	t, ok := p.targets[id]
	if !ok {
		delete(p.pollers, id)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.pollers[id] = cancel
	every := p.interval[id]
	if every <= 0 {
		every = defaultInterval
	}
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			r := p.check(ctx, t.Binding.URL)
			p.mu.Lock()
			if ctx.Err() == nil {
				p.last[id] = r
			}
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
}

func (p *probe) stopLocked(id int64) {
	if c := p.pollers[id]; c != nil {
		c()
	}
	delete(p.pollers, id)
	delete(p.targets, id)
	delete(p.last, id)
}

// check GETs url once.
func (p *probe) check(ctx context.Context, url string) result {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return result{state: sdk.StateDown, detail: "неверный адрес: " + err.Error(), at: start}
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return result{state: sdk.StateDown, detail: "не отвечает: " + shortErr(err), at: start}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	ms := time.Since(start).Milliseconds()
	detail := fmt.Sprintf("%d, %d мс", resp.StatusCode, ms)
	if name := nameLine(string(body)); name != "" {
		detail += ", " + name
	}
	if resp.StatusCode != http.StatusOK {
		return result{state: sdk.StateDegraded, detail: detail, at: start}
	}
	return result{state: sdk.StateOK, detail: detail, at: start}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// nameLine is the first "Name: …" line of the body (whoami shows the
// greeting there).
func nameLine(body string) string {
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Name:") {
			if len(l) > 200 {
				l = l[:200]
			}
			return l
		}
	}
	return ""
}

// ---- sdk.Plugin ----

func (p *probe) Validate(ctx context.Context, cfg sdk.Config) []sdk.FieldError {
	if s := cfg.Int("interval_s"); s < 30 || s > 3600 {
		return []sdk.FieldError{{Field: "interval_s", Msg: "от 30 до 3600 секунд"}}
	}
	return nil
}

func (p *probe) Plan(ctx context.Context, req sdk.PlanRequest) (sdk.Plan, error) {
	p.load(ctx)
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	switch req.Action {
	case sdk.ActionCreate:
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Создать проверку «" + req.Instance.Name + "»",
			Detail: fmt.Sprintf("раз в %s, без действий на серверах", intervalOf(req.Config)), Risk: sdk.RiskInfo})
		for _, l := range req.Links {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Проверять «" + l.Peer.Name + "»", Risk: sdk.RiskInfo})
		}
		if len(req.Links) == 0 {
			pl.Warnings = append(pl.Warnings, "Проверка не подключена к сервису — свяжите её с поставщиком http.service")
		}
	case sdk.ActionUpdate:
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Проверять раз в %s", intervalOf(req.Config)), Risk: sdk.RiskInfo})
	case sdk.ActionRemove:
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Удалить проверку «" + req.Instance.Name + "»", Risk: sdk.RiskInfo})
	}
	return pl, nil
}

func (p *probe) Apply(ctx context.Context, req sdk.ApplyRequest, job *sdk.Job) error {
	p.load(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	id := req.Instance.ID
	switch req.Action {
	case sdk.ActionRemove:
		p.stopLocked(id)
		delete(p.interval, id)
		p.saveLocked()
		job.Log("info", "Проверка удалена")
	default:
		p.interval[id] = intervalOf(req.Config)
		if _, ok := p.targets[id]; ok {
			p.startLocked(id)
		}
		job.Logf("Интервал проверки: %s", p.interval[id])
	}
	return nil
}

func (p *probe) Status(ctx context.Context, inst sdk.Instance) (sdk.Status, error) {
	p.load(ctx)
	p.mu.Lock()
	t, ok := p.targets[inst.ID]
	p.mu.Unlock()
	if !ok {
		return sdk.Status{State: sdk.StateDegraded, Detail: "Не подключён к сервису", Endpoints: []sdk.Endpoint{}}, nil
	}
	r := p.check(ctx, t.Binding.URL)
	p.mu.Lock()
	if _, still := p.targets[inst.ID]; still {
		p.last[inst.ID] = r
	}
	p.mu.Unlock()
	return sdk.Status{State: r.state, Detail: r.detail, Endpoints: []sdk.Endpoint{{Name: "проверяемый адрес", URL: t.Binding.URL}}}, nil
}

// ---- sdk.Linker (consumer of http.service) ----

func errRole(req sdk.LinkRequest) error {
	return fmt.Errorf("hestia-probe только потребитель http.service (роль %s)", req.Role)
}

func (p *probe) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	if req.Role != sdk.RoleConsumer {
		return pl, errRole(req)
	}
	peer := "поставщик"
	if req.Peer != nil {
		peer = req.Peer.Name
	}
	if req.Action == sdk.ActionRemove {
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Перестать проверять «" + peer + "»", Risk: sdk.RiskInfo})
	} else {
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Проверять «" + peer + "»", Detail: "раз в " + intervalOf(req.Instance.Config).String(), Risk: sdk.RiskInfo})
	}
	return pl, nil
}

func (p *probe) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	if req.Role != sdk.RoleConsumer {
		return nil, errRole(req)
	}
	p.load(ctx)
	var b types.HTTPService
	if err := json.Unmarshal(req.Binding, &b); err != nil || b.URL == "" {
		return nil, errors.New("нет адреса сервиса в данных связи")
	}
	p.mu.Lock()
	p.targets[req.Instance.ID] = target{Link: req.Link, Binding: b}
	if p.interval[req.Instance.ID] == 0 {
		p.interval[req.Instance.ID] = intervalOf(req.Instance.Config)
	}
	p.startLocked(req.Instance.ID)
	p.saveLocked()
	p.mu.Unlock()
	job.Logf("Проверяю %s", b.URL)
	return nil, nil
}

func (p *probe) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	if req.Role != sdk.RoleConsumer {
		return errRole(req)
	}
	p.load(ctx)
	p.mu.Lock()
	if t, ok := p.targets[req.Instance.ID]; ok && (t.Link == req.Link || t.Link == 0) {
		p.stopLocked(req.Instance.ID)
		p.saveLocked()
	}
	p.mu.Unlock()
	job.Log("info", "Проверка отключена от сервиса")
	return nil
}

func (p *probe) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	if req.Role != sdk.RoleConsumer {
		return sdk.LinkStatus{}, errRole(req)
	}
	p.load(ctx)
	p.mu.Lock()
	t, ok := p.targets[req.Instance.ID]
	r, has := p.last[req.Instance.ID]
	p.mu.Unlock()
	if !ok || t.Link != req.Link {
		return sdk.LinkStatus{State: sdk.StateDown, Detail: "проверка не знает об этой связи"}, nil
	}
	if !has {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "ещё не проверялось"}, nil
	}
	return sdk.LinkStatus{State: r.state, Detail: r.detail}, nil
}

func (p *probe) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	return nil, errRole(req)
}
