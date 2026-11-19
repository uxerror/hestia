package dnsname

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/uxerror/hestia/internal/integrations/adguard"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/netscan"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/store"
)

// HostSource is the last network scan (netscan.Manager).
type HostSource interface {
	View(ctx context.Context) (netscan.View, error)
}

// Service owns the AdGuard connection and the name of the controller.
type Service struct {
	Store   *store.Store
	Secrets *secrets.Service
	Runner  *jobs.Runner
	Hosts   HostSource
	// InstanceID is what GET /api/v1/health must answer on the new name.
	InstanceID string
	// Local reports that the controller still runs on the PC (optional).
	Local func(ctx context.Context) bool
	// HealthPort is the port the name is served on (80: the name is opened
	// without a port).
	HealthPort int
	// Query asks the DNS server of AdGuard directly (UDP).
	Query       func(ctx context.Context, server, domain string) ([]netip.Addr, error)
	DNSAttempts int
	DNSPause    time.Duration
	// FirstCheck and CheckEvery pace the watcher.
	FirstCheck time.Duration
	CheckEvery time.Duration
	Now        func() time.Time

	mu       sync.Mutex // connection changes and plans
	plans    map[string]*planState
	applying string // id of the running dns-name job
	zone     struct {
		at     time.Time
		domain string
	}
	wg sync.WaitGroup
}

// Init fills defaults.
func (s *Service) Init() *Service {
	if s.HealthPort == 0 {
		s.HealthPort = 80
	}
	if s.DNSAttempts == 0 {
		s.DNSAttempts = 5
	}
	if s.DNSPause == 0 {
		s.DNSPause = time.Second
	}
	if s.FirstCheck == 0 {
		s.FirstCheck = time.Minute
	}
	if s.CheckEvery == 0 {
		s.CheckEvery = 30 * time.Minute
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Query == nil {
		s.Query = func(ctx context.Context, server, domain string) ([]netip.Addr, error) {
			return QueryA(ctx, server, domain, 2*time.Second)
		}
	}
	s.plans = map[string]*planState{}
	return s
}

// Wait waits for the watcher to stop (after its context is cancelled).
func (s *Service) Wait() { s.wg.Wait() }

func purposeOf(id int64) string { return "adguard:" + strconv.FormatInt(id, 10) }

// integration returns the saved AdGuard connection or a 409 error.
func (s *Service) integration(ctx context.Context) (store.Integration, error) {
	in, err := s.Store.GetIntegrationByKind(ctx, store.KindAdGuard)
	if errors.Is(err, store.ErrNotFound) {
		return in, newErr(409, "not_connected", "AdGuard не подключён")
	}
	return in, err
}

// clientOf opens a client for a saved integration (decrypts the password).
func (s *Service) clientOf(ctx context.Context, in store.Integration) (*adguard.Client, error) {
	pw, err := s.Secrets.Get(ctx, in.SecretID)
	if err != nil {
		return nil, err
	}
	return adguard.NewClient(adguard.Config{BaseURL: in.BaseURL, Username: in.Username, Password: string(pw), PinSHA256: in.TLSPin})
}

// mapErr turns client errors into API errors.
func mapErr(err error) error {
	var ce *adguard.CertChangedError
	var ue *adguard.UnreachableError
	switch {
	case errors.As(err, &ce):
		return &Error{HTTP: 409, Code: "cert_changed", Msg: ce.Error(), Fingerprint: ce.Fingerprint}
	case errors.Is(err, adguard.ErrAuth):
		return newErr(400, "auth_failed", adguard.ErrAuth.Error())
	case errors.Is(err, adguard.ErrNoPin):
		return newErr(400, "no_pin", adguard.ErrNoPin.Error())
	case errors.Is(err, adguard.ErrNotAdGuard):
		return newErr(400, "not_adguard", adguard.ErrNotAdGuard.Error())
	case errors.As(err, &ue):
		return newErr(502, "unreachable", ue.Error())
	}
	return err
}

func (s *Service) isLocal(ctx context.Context) bool { return s.Local != nil && s.Local(ctx) }

// Candidates lists the hosts with AdGuard Home from the last scan.
func (s *Service) Candidates(ctx context.Context) ([]Candidate, error) {
	if s.Hosts == nil {
		return []Candidate{}, nil
	}
	v, err := s.Hosts.View(ctx)
	if err != nil {
		return nil, err
	}
	return candidatesOf(v.Hosts), nil
}

func candidatesOf(hosts []netscan.Host) []Candidate {
	out := []Candidate{}
	for _, h := range hosts {
		if !h.Alive {
			continue
		}
		var eps []Endpoint
		for _, sv := range h.Services {
			if sv.Rule != "adguard" || (sv.Proto != "http" && sv.Proto != "https") {
				continue
			}
			host := h.IP
			if sv.Port != defaultPort(sv.Proto) {
				host = net.JoinHostPort(h.IP, strconv.Itoa(sv.Port))
			}
			eps = append(eps, Endpoint{URL: sv.Proto + "://" + host, Scheme: sv.Proto, Port: sv.Port})
		}
		if len(eps) == 0 {
			continue
		}
		sort.SliceStable(eps, func(i, j int) bool {
			if eps[i].Scheme != eps[j].Scheme {
				return eps[i].Scheme == "https"
			}
			return eps[i].Port < eps[j].Port
		})
		out = append(out, Candidate{Host: h.IP, Endpoints: eps})
	}
	sort.SliceStable(out, func(i, j int) bool { return addrLess(out[i].Host, out[j].Host) })
	return out
}

func defaultPort(proto string) int {
	if proto == "https" {
		return 443
	}
	return 80
}

func addrLess(a, b string) bool {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return a < b
	}
	return x.Less(y)
}

func nameView(n store.DNSName) *NameView {
	return &NameView{Domain: n.Domain, Answer: n.Answer, Status: n.Status, StatusDetail: n.StatusDetail,
		VerifiedAt: n.VerifiedAt, CheckedAt: n.CheckedAt}
}

// View is the state for GET /dns.
func (s *Service) View(ctx context.Context) (*View, error) {
	v := &View{Local: s.isLocal(ctx), DefaultDomain: DefaultDomain(nil)}
	var err error
	if v.Candidates, err = s.Candidates(ctx); err != nil {
		return nil, err
	}
	in, err := s.Store.GetIntegrationByKind(ctx, store.KindAdGuard)
	switch {
	case err == nil:
		v.Integration = viewOf(in)
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	probe := ""
	if v.Integration != nil {
		probe = in.BaseURL
		if n, err := s.Store.GetDNSName(ctx); err == nil {
			v.Name = nameView(n)
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		} else {
			v.DefaultDomain = s.cachedDefaultDomain(ctx, in)
		}
	} else if len(v.Candidates) > 0 {
		probe = v.Candidates[0].Endpoints[0].URL
	}
	if probe != "" {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		v.ControllerIP, _ = adguard.LocalIP(cctx, probe)
		cancel()
	}
	return v, nil
}

// cachedDefaultDomain reads the rewrites (GET) to learn the zone, at most
// once a minute; any failure gives the plain default.
func (s *Service) cachedDefaultDomain(ctx context.Context, in store.Integration) string {
	s.mu.Lock()
	if s.Now().Sub(s.zone.at) < time.Minute && s.zone.domain != "" {
		d := s.zone.domain
		s.mu.Unlock()
		return d
	}
	s.mu.Unlock()
	d := DefaultDomain(nil)
	cl, err := s.clientOf(ctx, in)
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		if list, err := cl.RewriteList(cctx); err == nil {
			d = DefaultDomain(list)
			s.mu.Lock()
			s.zone.at, s.zone.domain = s.Now(), d
			s.mu.Unlock()
		}
	}
	return d
}

// Probe looks at an endpoint without a password.
func (s *Service) Probe(ctx context.Context, rawURL string) (*adguard.ProbeResult, error) {
	res, err := adguard.Probe(ctx, rawURL)
	if err != nil {
		var ue *adguard.UnreachableError
		if errors.As(err, &ue) {
			return nil, newErr(502, "unreachable", ue.Error())
		}
		return nil, newErr(400, "bad_request", err.Error())
	}
	return res, nil
}

// Connect checks the login (nothing is changed in AdGuard) and saves the
// connection; replace=true updates the existing one (PUT).
func (s *Service) Connect(ctx context.Context, req ConnectRequest, replace bool) (*ConnectResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	base, err := adguard.ParseBase(req.URL)
	if err != nil {
		return nil, newErr(400, "bad_request", err.Error())
	}
	pin := ""
	if base.Scheme == "https" {
		if pin = adguard.NormalizeFP(req.TLSPin); pin == "" {
			return nil, mapErr(adguard.ErrNoPin)
		}
	}
	if len(req.Username) > 128 || len(req.Password) > 1024 {
		return nil, newErr(400, "bad_request", "слишком длинный логин или пароль")
	}
	old, oldErr := s.Store.GetIntegrationByKind(ctx, store.KindAdGuard)
	if oldErr != nil && !errors.Is(oldErr, store.ErrNotFound) {
		return nil, oldErr
	}
	exists := oldErr == nil
	switch {
	case replace && !exists:
		return nil, newErr(409, "not_connected", "AdGuard не подключён")
	case !replace && exists:
		return nil, newErr(409, "exists", "AdGuard уже подключён: измените подключение или удалите его")
	}
	password := req.Password
	if replace && password == "" {
		pw, err := s.Secrets.Get(ctx, old.SecretID)
		if err != nil {
			return nil, err
		}
		password = string(pw)
	}
	cl, err := adguard.NewClient(adguard.Config{BaseURL: base.String(), Username: req.Username, Password: password, PinSHA256: pin})
	if err != nil {
		return nil, mapErr(err)
	}
	st, err := cl.Status(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	res := &ConnectResult{Warnings: []string{}, Server: ServerStatus{
		Version: st.Version, Running: st.Running, DNSPort: st.DNSPort, DNSAddresses: append([]string{}, st.DNSAddresses...)}}
	if res.Server.DNSAddresses == nil {
		res.Server.DNSAddresses = []string{}
	}
	if !st.Running {
		res.Warnings = append(res.Warnings, "DNS-сервер AdGuard сейчас остановлен")
	}
	if on, err := cl.RewritesEnabled(ctx); err != nil {
		return nil, mapErr(err)
	} else if !on {
		res.Warnings = append(res.Warnings, "В AdGuard выключены DNS-перезаписи (rewrite): запись не будет работать, пока их не включить")
	}
	list, err := cl.RewriteList(ctx)
	if err != nil {
		return nil, mapErr(err)
	}
	res.DefaultDomain = DefaultDomain(list)
	if base.Scheme == "http" {
		res.Warnings = append(res.Warnings, "Подключение по HTTP: пароль идёт по сети открытым текстом")
	}
	res.ControllerIP, _ = adguard.LocalIP(ctx, base.String())

	in := store.Integration{Kind: store.KindAdGuard, BaseURL: base.String(), TLSPin: pin, Username: req.Username, Version: st.Version}
	if replace {
		in = old
		in.BaseURL, in.TLSPin, in.Username, in.Version = base.String(), pin, req.Username, st.Version
		if req.Password != "" {
			sid, err := s.Secrets.Put(ctx, purposeOf(in.ID), []byte(password))
			if err != nil {
				return nil, err
			}
			in.SecretID = sid
		}
		if err := s.Store.UpdateIntegration(ctx, &in); err != nil {
			if in.SecretID != old.SecretID {
				_ = s.Secrets.Delete(ctx, in.SecretID)
			}
			return nil, err
		}
		if in.SecretID != old.SecretID {
			_ = s.Secrets.Delete(ctx, old.SecretID)
		}
	} else {
		if in.ID, err = s.Store.NextIntegrationID(ctx); err != nil {
			return nil, err
		}
		in.Name = "AdGuard Home (" + cl.Host() + ")"
		if in.SecretID, err = s.Secrets.Put(ctx, purposeOf(in.ID), []byte(password)); err != nil {
			return nil, err
		}
		if err := s.Store.CreateIntegration(ctx, &in); err != nil {
			_ = s.Secrets.Delete(ctx, in.SecretID)
			return nil, err
		}
	}
	res.Integration = viewOf(in)
	s.zone.domain = ""
	return res, nil
}

// Disconnect forgets the connection and the name binding. It changes nothing
// in AdGuard: the record stays there until it is removed with a plan.
func (s *Service) Disconnect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applying != "" {
		return &Error{HTTP: 409, Code: "busy", Msg: "сейчас выполняется задача по имени Hestia", Job: s.applying}
	}
	in, err := s.integration(ctx)
	if err != nil {
		return err
	}
	s.plans = map[string]*planState{}
	s.zone.domain = ""
	return s.Store.DeleteIntegration(ctx, in.ID)
}

// PublicURL is "http://<name>" while the name is verified and healthy, else "".
func (s *Service) PublicURL(ctx context.Context) string {
	n, err := s.Store.GetDNSName(ctx)
	if err != nil || n.Status != StatusOK {
		return ""
	}
	return "http://" + n.Domain
}

// ownerOf names the host with the given IP from the scan (for conflicts).
func (s *Service) ownerOf(ctx context.Context, ip string) string {
	if s.Hosts == nil {
		return ""
	}
	v, err := s.Hosts.View(ctx)
	if err != nil {
		return ""
	}
	for _, h := range v.Hosts {
		if h.IP != ip {
			continue
		}
		switch {
		case h.Link != nil && h.Link.Name != "":
			return fmt.Sprintf("%s (гость %s)", h.Link.Name, ip)
		case h.Link != nil && h.Link.Node != "":
			return fmt.Sprintf("%s (узел %s)", h.Link.Node, ip)
		case len(h.Names) > 0:
			return fmt.Sprintf("%s (%s)", h.Names[0].Name, ip)
		case h.Vendor != "":
			return fmt.Sprintf("%s (%s)", h.Vendor, ip)
		}
		return ip
	}
	return ""
}
