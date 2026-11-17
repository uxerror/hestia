// Package target abstracts "how to run an action on a connected system".
// Only the SSH transport exists so far; the Proxmox API client lives in
// package proxmox.
package target

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"hestia/internal/sshx"
)

// Result is the outcome of a command.
type Result = sshx.Result

// Target runs commands and moves files on a system.
type Target interface {
	// Exec runs cmd; a non-zero exit status is an error (*sshx.ExitError)
	// but the Result is still returned.
	Exec(ctx context.Context, cmd string) (Result, error)
	// Put writes data to path (creating or truncating it) with the given mode.
	Put(ctx context.Context, path string, data []byte, mode fs.FileMode) error
	// Get reads a file; a missing file yields an error satisfying
	// errors.Is(err, fs.ErrNotExist).
	Get(ctx context.Context, path string) ([]byte, error)
	// Facts collects read-only information about the system.
	Facts(ctx context.Context) (Facts, error)
	Close() error
}

// Quote single-quotes s for a POSIX shell.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// SSH is a Target over an SSH connection.
type SSH struct{ c *sshx.Client }

// NewSSH wraps an established connection; Close closes it.
func NewSSH(c *sshx.Client) *SSH { return &SSH{c: c} }

// Client returns the underlying connection.
func (s *SSH) Client() *sshx.Client { return s.c }

func (s *SSH) Exec(ctx context.Context, cmd string) (Result, error) {
	return s.c.Exec(ctx, cmd, nil)
}

func (s *SSH) Close() error { return s.c.Close() }

func (s *SSH) Put(ctx context.Context, path string, data []byte, mode fs.FileMode) error {
	p := Quote(path)
	// chmod is best effort: /etc/pve (pmxcfs) files have fixed permissions.
	cmd := fmt.Sprintf("cat > %s && { chmod %04o %s 2>/dev/null || true; }", p, mode.Perm(), p)
	_, err := s.c.Exec(ctx, cmd, data)
	if err != nil {
		return fmt.Errorf("запись %s: %w", path, err)
	}
	return nil
}

func (s *SSH) Get(ctx context.Context, path string) ([]byte, error) {
	r, err := s.c.Exec(ctx, "cat "+Quote(path), nil)
	if err != nil {
		if strings.Contains(r.Stderr, "No such file") {
			return nil, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
		}
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	return []byte(r.Stdout), nil
}

// Home returns the login user's home directory.
func Home(ctx context.Context, t Target) (string, error) {
	r, err := t.Exec(ctx, `printf '%s\n' "$HOME"`)
	if err != nil {
		return "", err
	}
	h := strings.TrimSpace(r.Stdout)
	if h == "" || !strings.HasPrefix(h, "/") {
		return "", errors.New("не удалось определить домашний каталог")
	}
	return h, nil
}

// AuthorizedKeysPath returns ~/.ssh/authorized_keys of the login user.
func AuthorizedKeysPath(ctx context.Context, t Target) (string, error) {
	h, err := Home(ctx, t)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(h, "/") + "/.ssh/authorized_keys", nil
}

// keyBody returns "type base64" of an authorized_keys line (drops options and comment).
func keyBody(line string) string {
	f := strings.Fields(line)
	for i, w := range f {
		if strings.HasPrefix(w, "ssh-") || strings.HasPrefix(w, "ecdsa-") || strings.HasPrefix(w, "sk-") {
			if i+1 < len(f) {
				return w + " " + f[i+1]
			}
		}
	}
	return ""
}

// HasAuthorizedKey reports whether the key (matched by type+blob, so the
// comment may differ) is in the file contents.
func HasAuthorizedKey(contents, line string) bool {
	want := keyBody(line)
	if want == "" {
		return false
	}
	for _, l := range strings.Split(contents, "\n") {
		if keyBody(l) == want {
			return true
		}
	}
	return false
}

// AddAuthorizedKey appends line to path unless the key is already there,
// creating the directory (0700) and file (0600) as needed. It returns whether
// the file was changed.
func AddAuthorizedKey(ctx context.Context, t Target, path, line string) (bool, error) {
	cur, err := t.Get(ctx, path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if HasAuthorizedKey(string(cur), line) {
		return false, nil
	}
	dir := path[:strings.LastIndex(path, "/")]
	if _, err := t.Exec(ctx, "mkdir -p "+Quote(dir)+" && chmod 700 "+Quote(dir)); err != nil {
		return false, fmt.Errorf("каталог %s: %w", dir, err)
	}
	next := string(cur)
	if next != "" && !strings.HasSuffix(next, "\n") {
		next += "\n"
	}
	next += strings.TrimSpace(line) + "\n"
	if err := t.Put(ctx, path, []byte(next), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveAuthorizedKey deletes every line holding the same key as line.
// A missing file is fine.
func RemoveAuthorizedKey(ctx context.Context, t Target, path, line string) error {
	cur, err := t.Get(ctx, path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	want := keyBody(line)
	var keep []string
	changed := false
	for _, l := range strings.Split(strings.TrimRight(string(cur), "\n"), "\n") {
		if want != "" && keyBody(l) == want {
			changed = true
			continue
		}
		keep = append(keep, l)
	}
	if !changed {
		return nil
	}
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	return t.Put(ctx, path, []byte(out), 0o600)
}

// Facts describes a standalone server.
type Facts struct {
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
	OS       string `json:"os"`
	CPUs     int    `json:"cpus"`
	MemTotal int64  `json:"mem_total"`
	MemAvail int64  `json:"mem_available"`
	Disks    []Disk `json:"disks"`
	Docker   bool   `json:"docker"`
	UID      int    `json:"uid"`
	Sudo     bool   `json:"sudo"`
}

// Disk is a mounted filesystem.
type Disk struct {
	Mount string `json:"mount"`
	Size  int64  `json:"size"`
	Used  int64  `json:"used"`
}

// IsRoot reports uid 0.
func (f Facts) IsRoot() bool { return f.UID == 0 }

// Facts gathers system facts. Individual failures leave fields zero; only a
// total failure to run commands is an error.
func (s *SSH) Facts(ctx context.Context) (Facts, error) {
	var f Facts
	r, err := s.Exec(ctx, "uname -srm")
	if err != nil {
		return f, fmt.Errorf("uname: %w", err)
	}
	parts := strings.Fields(r.Stdout)
	if len(parts) >= 3 {
		f.Kernel = parts[0] + " " + parts[1]
		f.Arch = parts[2]
	}
	if r, err := s.Exec(ctx, "hostname"); err == nil {
		f.Hostname = strings.TrimSpace(r.Stdout)
	}
	if r, err := s.Exec(ctx, "cat /etc/os-release"); err == nil {
		f.OS = ParseOSRelease(r.Stdout)
	}
	if r, err := s.Exec(ctx, "nproc"); err == nil {
		f.CPUs, _ = strconv.Atoi(strings.TrimSpace(r.Stdout))
	}
	if r, err := s.Exec(ctx, "free -b"); err == nil {
		f.MemTotal, f.MemAvail = ParseFree(r.Stdout)
	}
	if r, err := s.Exec(ctx, "df -B1 -x tmpfs -x devtmpfs"); err == nil {
		f.Disks = ParseDF(r.Stdout)
	}
	if _, err := s.Exec(ctx, "command -v docker"); err == nil {
		f.Docker = true
	}
	if r, err := s.Exec(ctx, "id -u"); err == nil {
		f.UID, _ = strconv.Atoi(strings.TrimSpace(r.Stdout))
	}
	if f.UID == 0 {
		f.Sudo = true
	} else if _, err := s.Exec(ctx, "sudo -n true"); err == nil {
		f.Sudo = true
	}
	if f.Disks == nil {
		f.Disks = []Disk{}
	}
	return f, nil
}

// ParseOSRelease returns PRETTY_NAME (or NAME VERSION) from /etc/os-release.
func ParseOSRelease(s string) string {
	kv := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	if v := kv["PRETTY_NAME"]; v != "" {
		return v
	}
	return strings.TrimSpace(kv["NAME"] + " " + kv["VERSION"])
}

// ParseFree reads total and available bytes from `free -b`.
func ParseFree(s string) (total, avail int64) {
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.HasPrefix(f[0], "Mem:") {
			total, _ = strconv.ParseInt(f[1], 10, 64)
			if len(f) >= 7 {
				avail, _ = strconv.ParseInt(f[6], 10, 64)
			} else if len(f) >= 4 {
				avail, _ = strconv.ParseInt(f[3], 10, 64)
			}
		}
	}
	return
}

// ParseDF reads `df -B1` output (size and used in bytes).
func ParseDF(s string) []Disk {
	out := []Disk{}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if i == 0 || len(f) < 6 {
			continue
		}
		size, e1 := strconv.ParseInt(f[1], 10, 64)
		used, e2 := strconv.ParseInt(f[2], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		out = append(out, Disk{Mount: f[len(f)-1], Size: size, Used: used})
	}
	return out
}
