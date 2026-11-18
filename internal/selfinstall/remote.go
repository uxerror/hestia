package selfinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Location describes where the controller moved to, without anything that
// depends on how it is reached (that is Remote's URL).
type Location struct {
	Kind     string    `json:"kind"` // lxc | ssh
	TargetID int64     `json:"target_id"`
	Node     string    `json:"node,omitempty"`
	VMID     int       `json:"vmid,omitempty"`
	Host     string    `json:"host,omitempty"`
	MAC      string    `json:"mac,omitempty"`
	IP       string    `json:"ip"`
	MovedAt  time.Time `json:"moved_at"`
}

// Remote is the content of <data>/remote.json: the controller now lives at URL.
type Remote struct {
	URL string `json:"url"`
	// FallbackURL is the address that worked before URL was switched to the
	// DNS name of the controller; it is tried when URL does not answer.
	FallbackURL string `json:"fallback_url,omitempty"`
	InstanceID  string `json:"instance_id"`
	Location
}

// RemoteFile is the name of the marker file inside the data directory.
const RemoteFile = "remote.json"

// ReadRemote reads <dir>/remote.json. A missing file is (nil, nil).
func ReadRemote(dir string) (*Remote, error) {
	b, err := os.ReadFile(filepath.Join(dir, RemoteFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Remote
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s повреждён: %w", RemoteFile, err)
	}
	if r.URL == "" {
		return nil, fmt.Errorf("%s: нет адреса", RemoteFile)
	}
	return &r, nil
}

// WriteRemote writes <dir>/remote.json atomically with mode 0600.
func WriteRemote(dir string, r Remote) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, RemoteFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, RemoteFile))
}

// CheckTimeout bounds the health check of the remote controller.
const CheckTimeout = 3 * time.Second

// CheckRemote reports whether the remote controller answers its health
// endpoint with the instance id recorded in remote.json, at URL or at the
// fallback address.
func CheckRemote(ctx context.Context, r Remote) bool {
	_, ok := ReachableURL(ctx, r)
	return ok
}

// ReachableURL returns the first of URL and FallbackURL that answers with the
// recorded instance id.
func ReachableURL(ctx context.Context, r Remote) (string, bool) {
	for _, u := range []string{r.URL, r.FallbackURL} {
		if u == "" {
			continue
		}
		if h, ok := fetchHealthInfo(ctx, nil, u); ok && h.Status == "ok" && (r.InstanceID == "" || h.InstanceID == r.InstanceID) {
			return u, true
		}
	}
	return "", false
}

// healthInfo is the part of GET /api/v1/health the desktop app reads.
type healthInfo struct {
	Status     string `json:"status"`
	InstanceID string `json:"instance_id"`
	DNSURL     string `json:"dns_url"`
}

// fetchHealthInfo calls GET <base>/api/v1/health. ok is false when the
// request failed or the answer is not a health document.
func fetchHealthInfo(ctx context.Context, c *http.Client, base string) (healthInfo, bool) {
	var h healthInfo
	if c == nil {
		c = &http.Client{Transport: &http.Transport{Proxy: nil}}
	}
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/health", nil)
	if err != nil {
		return h, false
	}
	resp, err := c.Do(req)
	if err != nil {
		return h, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return h, false
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h) != nil {
		return healthInfo{}, false
	}
	return h, true
}

// fetchHealth calls GET <base>/api/v1/health and returns the instance id.
func fetchHealth(ctx context.Context, c *http.Client, base string) (string, bool) {
	h, ok := fetchHealthInfo(ctx, c, base)
	if !ok || h.Status != "ok" {
		return "", false
	}
	return h.InstanceID, true
}

// StartOptions are the hooks of ResolveStart (nil: the real thing).
type StartOptions struct {
	// Resolve checks that the name resolves on this computer.
	Resolve func(ctx context.Context, host string) error
}

// ResolveTimeout bounds the name lookup on the PC.
const ResolveTimeout = 2 * time.Second

func defaultResolve(ctx context.Context, host string) error {
	ctx, cancel := context.WithTimeout(ctx, ResolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err == nil && len(addrs) == 0 {
		err = errors.New("no addresses")
	}
	return err
}

// ResolveStart picks the address the desktop app opens and, when the
// controller announces a DNS name that works from this PC, switches
// remote.json to it (the old address becomes the fallback). ok is false when
// the controller answers at neither address; r is then unchanged.
//
// The name is adopted only if it resolves here and answers with the same
// instance id. If the controller stops announcing a name, remote.json is left
// alone: the stored addresses keep working.
func ResolveStart(ctx context.Context, dir string, r Remote, o StartOptions) (Remote, bool) {
	active, ok := ReachableURL(ctx, r)
	if !ok {
		return r, false
	}
	h, _ := fetchHealthInfo(ctx, nil, active)
	dns := strings.TrimRight(h.DNSURL, "/")
	if dns == "" || dns == r.URL {
		r.URL = active
		return r, true
	}
	cur := r
	cur.URL = active
	u, err := url.Parse(dns)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return cur, true
	}
	if o.Resolve == nil {
		o.Resolve = defaultResolve
	}
	if err := o.Resolve(ctx, u.Hostname()); err != nil {
		return cur, true
	}
	if got, ok := fetchHealthInfo(ctx, nil, dns); !ok || got.Status != "ok" || got.InstanceID != h.InstanceID ||
		(r.InstanceID != "" && got.InstanceID != r.InstanceID) {
		return cur, true
	}
	next := r
	next.URL = dns
	next.FallbackURL = active
	if active == dns {
		next.FallbackURL = r.URL
	}
	if err := WriteRemote(dir, next); err != nil {
		return cur, true // keep working with what answered
	}
	return next, true
}

// Gate carries the two process-wide modes of the controller: "transferring"
// (state is being copied to a server; writes are refused) and "moved" (the
// controller lives elsewhere; only the redirect screen is served).
type Gate struct {
	transferring atomic.Bool
	moved        atomic.Pointer[Remote]
}

// Transferring reports the transfer mode.
func (g *Gate) Transferring() bool { return g != nil && g.transferring.Load() }

// SetTransferring switches the transfer mode.
func (g *Gate) SetTransferring(v bool) { g.transferring.Store(v) }

// Moved returns where the controller moved to, or nil.
func (g *Gate) Moved() *Remote {
	if g == nil {
		return nil
	}
	return g.moved.Load()
}

// SetMoved switches to the moved mode for good.
func (g *Gate) SetMoved(r Remote) { g.moved.Store(&r) }
