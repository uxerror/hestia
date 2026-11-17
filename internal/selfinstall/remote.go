package selfinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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
	URL        string `json:"url"`
	InstanceID string `json:"instance_id"`
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
// endpoint with the instance id recorded in remote.json.
func CheckRemote(ctx context.Context, r Remote) bool {
	id, ok := fetchHealth(ctx, nil, r.URL)
	return ok && (r.InstanceID == "" || id == r.InstanceID)
}

// fetchHealth calls GET <base>/api/v1/health and returns the instance id.
func fetchHealth(ctx context.Context, c *http.Client, base string) (string, bool) {
	if c == nil {
		c = &http.Client{Transport: &http.Transport{Proxy: nil}}
	}
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/health", nil)
	if err != nil {
		return "", false
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var h struct {
		Status     string `json:"status"`
		InstanceID string `json:"instance_id"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h) != nil || h.Status != "ok" {
		return "", false
	}
	return h.InstanceID, true
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
