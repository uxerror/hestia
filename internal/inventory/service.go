package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/proxmox"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/target"
)

// JobKind is the kind of the refresh job.
const JobKind = "inventory.refresh"

// DefaultInterval is how often watched targets are refreshed.
const DefaultInterval = 60 * time.Second

const subBuffer = 32

// Service collects and serves inventories. Hook fields default to the real
// implementations and exist so tests never touch a real network.
type Service struct {
	Store    *store.Store
	Secrets  *secrets.Service
	Runner   *jobs.Runner
	Identity secrets.Identity

	Dial       func(ctx context.Context, cfg sshx.Config) (*sshx.Client, error)
	NewAPI     func(cfg proxmox.ClientConfig) API
	APIPort    int
	Now        func() time.Time
	Interval   time.Duration
	ReqTimeout time.Duration // per Proxmox API request

	mu      sync.Mutex
	running map[int64]string // target id → id of the collecting job
	subs    map[chan Entry]struct{}
	kick    chan struct{}
	loop    sync.WaitGroup
}

// Init fills in defaults and returns s; call it once after building the struct.
func (s *Service) Init() *Service {
	if s.Dial == nil {
		s.Dial = sshx.Dial
	}
	if s.NewAPI == nil {
		s.NewAPI = func(cfg proxmox.ClientConfig) API { return proxmox.NewClient(cfg) }
	}
	if s.APIPort == 0 {
		s.APIPort = proxmox.APIPort
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Interval <= 0 {
		s.Interval = DefaultInterval
	}
	if s.ReqTimeout <= 0 {
		s.ReqTimeout = DefaultReqTimeout
	}
	s.running = map[int64]string{}
	s.subs = map[chan Entry]struct{}{}
	s.kick = make(chan struct{}, 1)
	return s
}

// ---- reading ----

// Get returns the stored inventory of a target (an empty entry if none was
// collected yet). ErrNotFound if the target does not exist.
func (s *Service) Get(ctx context.Context, id int64) (Entry, error) {
	if _, err := s.Store.GetTarget(ctx, id); err != nil {
		return Entry{}, err
	}
	return s.entry(ctx, id)
}

// List returns an entry for every target.
func (s *Service) List(ctx context.Context) ([]Entry, error) {
	ts, err := s.Store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.ListInventory(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]store.InventoryRow{}
	for _, r := range rows {
		byID[r.TargetID] = r
	}
	out := make([]Entry, 0, len(ts))
	for _, t := range ts {
		out = append(out, s.toEntry(t.ID, byID[t.ID]))
	}
	return out, nil
}

func (s *Service) entry(ctx context.Context, id int64) (Entry, error) {
	row, err := s.Store.GetInventory(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return Entry{}, err
	}
	return s.toEntry(id, row), nil
}

func (s *Service) toEntry(id int64, row store.InventoryRow) Entry {
	e := Entry{TargetID: id, Error: row.Error}
	s.mu.Lock()
	_, e.Collecting = s.running[id]
	s.mu.Unlock()
	if !row.CollectedAt.IsZero() {
		at := row.CollectedAt
		age := int64(s.Now().Sub(at).Seconds())
		if age < 0 {
			age = 0
		}
		e.CollectedAt, e.AgeSeconds = &at, &age
	}
	if len(row.Data) > 0 {
		var snap Snapshot
		if err := json.Unmarshal(row.Data, &snap); err == nil {
			e.Snapshot = &snap
		}
	}
	return e
}

// ---- collecting ----

// Refresh starts a collection job for the target. If one is already running
// for it, that job is returned instead (at most one collection per target).
func (s *Service) Refresh(ctx context.Context, id int64) (store.Job, error) {
	t, err := s.Store.GetTarget(ctx, id)
	if err != nil {
		return store.Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if jid, ok := s.running[id]; ok {
		return s.Store.GetJob(ctx, jid)
	}
	job, err := s.Runner.Start(JobKind, "Обновление инвентаря: "+t.Name, func(jctx context.Context, run *jobs.Run) error {
		return s.runCollect(jctx, run, t)
	})
	if err != nil {
		return store.Job{}, err
	}
	s.running[id] = job.ID
	go s.publish(id) // announce "collecting"; takes the lock after Refresh returns
	return job, nil
}

// RefreshQuiet is Refresh for callers that only want the collection started
// (for example right after a target was connected).
func (s *Service) RefreshQuiet(id int64) {
	if _, err := s.Refresh(context.Background(), id); err != nil {
		slog.Warn("не удалось запустить обновление инвентаря", "target", id, "err", err)
	}
}

func (s *Service) runCollect(ctx context.Context, run *jobs.Run, t store.Target) (err error) {
	defer func() {
		s.mu.Lock()
		delete(s.running, t.ID)
		s.mu.Unlock()
		s.publish(t.ID)
	}()
	snap, secret, err := s.collect(ctx, run, t)
	if err != nil {
		msg := secrets.Mask(err.Error(), secret)
		// The job context is cancelled on shutdown; the error must still be stored.
		if serr := s.Store.SetInventoryError(context.Background(), t.ID, msg); serr != nil && !errors.Is(serr, context.Canceled) {
			slog.Debug("инвентарь: не сохранена ошибка", "target", t.ID, "err", serr)
		}
		return errors.New(msg)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := s.Store.PutInventory(context.Background(), t.ID, s.Now().UTC(), data); err != nil {
		return fmt.Errorf("сохранение инвентаря: %w", err)
	}
	run.Log("info", fmt.Sprintf("Узлов: %d, хранилищ: %d, гостей: %d", len(snap.Nodes), len(snap.Storages), len(snap.Guests)))
	return nil
}

// collect returns the snapshot and the API token (for masking error text).
func (s *Service) collect(ctx context.Context, run *jobs.Run, t store.Target) (*Snapshot, string, error) {
	if t.Kind == store.KindProxmox {
		raw, err := s.Secrets.Get(ctx, t.TokenSecretRef)
		if err != nil {
			return nil, "", fmt.Errorf("токен API: %w", err)
		}
		secret := string(raw)
		api := s.NewAPI(proxmox.ClientConfig{Host: t.Host, Port: s.APIPort, TokenID: t.TokenID, Secret: secret, PinFP: t.APICertFP})
		snap, err := collectProxmox(ctx, api, run, s.ReqTimeout, t.Cluster)
		return snap, secret, err
	}
	var tg *target.SSH
	if err := run.Step("Подключение по SSH", func(ctx context.Context) error {
		cl, err := s.Dial(ctx, sshx.Config{Host: t.Host, Port: t.Port, User: t.SSHUser, Signer: s.Identity.Signer, ExpectedFP: t.HostKeyFP})
		if err != nil {
			return err
		}
		tg = target.NewSSH(cl)
		return nil
	}); err != nil {
		return nil, "", err
	}
	defer tg.Close()
	snap, err := collectSSH(ctx, run, tg, t.Host)
	return snap, "", err
}

// ---- subscriptions and the periodic refresh ----

// Subscribe returns a channel of entries published whenever a collection
// starts or ends, and a cancel func. A slow subscriber is dropped (its channel
// is closed). The first subscriber wakes the refresh loop.
func (s *Service) Subscribe() (<-chan Entry, func()) {
	ch := make(chan Entry, subBuffer)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
	}
}

// Subscribers is the number of open event streams.
func (s *Service) Subscribers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.subs)
}

func (s *Service) publish(id int64) {
	e, err := s.entry(context.Background(), id)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- e:
		default:
			delete(s.subs, ch)
			close(ch)
		}
	}
}

// Tick refreshes the targets whose snapshot is at least half an interval old.
// Without subscribers it does nothing: nobody is looking.
func (s *Service) Tick(ctx context.Context) {
	if s.Subscribers() == 0 {
		return
	}
	ts, err := s.Store.ListTargets(ctx)
	if err != nil {
		return
	}
	for _, t := range ts {
		row, err := s.Store.GetInventory(ctx, t.ID)
		if err == nil && !row.CollectedAt.IsZero() && s.Now().Sub(row.CollectedAt) < s.Interval/2 {
			continue
		}
		if _, err := s.Refresh(ctx, t.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			slog.Warn("инвентарь: обновление не запущено", "target", t.ID, "err", err)
		}
	}
}

// Start runs the periodic refresh until ctx is cancelled.
func (s *Service) Start(ctx context.Context) {
	s.loop.Add(1)
	go func() {
		defer s.loop.Done()
		tk := time.NewTicker(s.Interval)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
			case <-s.kick:
			}
			s.Tick(ctx)
		}
	}()
}

// Wait blocks until the refresh loop has stopped (after its context ended).
func (s *Service) Wait() { s.loop.Wait() }
