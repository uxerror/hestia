package proxmox

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/target"
)

// Where a Proxmox VE cluster keeps the SSH host keys of its nodes (shared
// through pmxcfs, so any node can read all of them). On PVE 8/9 the files
// hold only ssh-rsa keys, even though the nodes offer ecdsa and ed25519 too.
const (
	nodeKnownHostsFmt = "/etc/pve/nodes/%s/ssh_known_hosts"
	legacyKnownHosts  = "/etc/pve/priv/known_hosts"
)

// HostKey is the SSH host key of a node: its known_hosts type ("ssh-rsa") and
// SHA256 fingerprint ("SHA256:…").
type HostKey struct {
	Type string
	FP   string
}

var nodeNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)

// ParseKnownHosts parses known_hosts content into host → keys (file order).
// Hashed entries, wildcard patterns, markers and malformed lines are skipped.
// Hosts of the form [host]:port are reported as host.
func ParseKnownHosts(b []byte) map[string][]HostKey {
	out := map[string][]HostKey{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		marker, hosts, pub, _, _, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || marker != "" {
			continue
		}
		hk := HostKey{Type: pub.Type(), FP: ssh.FingerprintSHA256(pub)}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|") || strings.ContainsAny(h, "*?!") {
				continue
			}
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			h = strings.Trim(h, "[]")
			out[h] = append(out[h], hk)
		}
	}
	return out
}

// pickKey chooses one key from keys, preferring modern types.
func pickKey(keys []HostKey) (HostKey, bool) {
	for _, want := range []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA} {
		for _, k := range keys {
			if k.Type == want {
				return k, true
			}
		}
	}
	if len(keys) > 0 {
		return keys[0], true
	}
	return HostKey{}, false
}

// NodeKey finds the key of node (matched by name or cluster IP) in parsed
// known_hosts content.
func NodeKey(known map[string][]HostKey, name, ip string) (HostKey, bool) {
	keys := append([]HostKey(nil), known[name]...)
	if ip != "" {
		keys = append(keys, known[ip]...)
	}
	return pickKey(keys)
}

// readNodeKeys fills HostKeyFP/Type of nodes from the cluster files. A node
// without any key stays empty; callers decide what that means.
func readNodeKeys(ctx context.Context, t target.Target, nodes []Node) error {
	var legacy map[string][]HostKey
	legacyRead := false
	for i := range nodes {
		n := &nodes[i]
		if !nodeNameRe.MatchString(n.Name) {
			continue // never put an odd name into a path
		}
		var known map[string][]HostKey
		b, err := t.Get(ctx, strings.Replace(nodeKnownHostsFmt, "%s", n.Name, 1))
		switch {
		case err == nil:
			known = ParseKnownHosts(b)
		case !isNotExist(err):
			return err
		}
		k, ok := NodeKey(known, n.Name, n.IP)
		if !ok {
			if !legacyRead {
				legacyRead = true
				b, err := t.Get(ctx, legacyKnownHosts)
				switch {
				case err == nil:
					legacy = ParseKnownHosts(b)
				case !isNotExist(err):
					return err
				}
			}
			k, ok = NodeKey(legacy, n.Name, n.IP)
		}
		if ok {
			n.HostKeyType, n.HostKeyFP = k.Type, k.FP
		}
	}
	return nil
}

// isNoSuchUser reports pveum's failure for a user that does not exist
// (exit code 255, "no such user").
func isNoSuchUser(err error) bool {
	var ee *sshx.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	return ee.Result.ExitCode == 255 && strings.Contains(ee.Result.Stderr+ee.Result.Stdout, "no such user")
}
