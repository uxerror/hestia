// Package proxmox configures a Proxmox VE host over SSH (pveum/pvesh CLI) and
// talks to its REST API with an API token and a pinned TLS certificate.
package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"hestia/internal/sshx"
	"hestia/internal/target"
)

// Names and constants of what Hestia creates on Proxmox.
const (
	RoleName  = "Hestia"
	UserID    = "hestia@pve"
	TokenName = "hestia"
	TokenID   = UserID + "!" + TokenName
	Comment   = "Hestia controller"
)

// Privileges is the minimal privilege set of the Hestia role.
var Privileges = []string{
	"Sys.Audit", "Datastore.Audit", "Datastore.AllocateSpace", "Datastore.AllocateTemplate",
	"VM.Audit", "VM.Allocate", "VM.Clone", "VM.Config.Disk", "VM.Config.CPU", "VM.Config.Memory",
	"VM.Config.Network", "VM.Config.Options", "VM.PowerMgmt", "SDN.Use", "Pool.Audit",
}

// ErrNotProxmox means pveversion is missing on the host.
var ErrNotProxmox = errors.New("это не Proxmox — подключите как отдельный сервер")

// Node is a cluster member.
type Node struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Online bool   `json:"online"`
	// SSH host key from the cluster files (empty if none was found).
	HostKeyFP   string `json:"host_key_fp"`
	HostKeyType string `json:"host_key_type"`
}

// State is what a read-only inspection found.
type State struct {
	Version    string
	Cluster    string // empty for a single node
	LocalNode  string
	Nodes      []Node
	RoleExists bool
	RolePrivs  []string // current privileges of the Hestia role
	UserExists bool
	TokenExist bool
	ACLExists  bool
}

var versionRe = regexp.MustCompile(`pve-manager/([^/\s]+)`)

// Inspect runs the read-only checks. t must be a root (or equivalent) login.
func Inspect(ctx context.Context, t target.Target) (State, error) {
	var st State
	r, err := t.Exec(ctx, "pveversion")
	if err != nil {
		var ee *sshx.ExitError
		if errors.As(err, &ee) {
			return st, ErrNotProxmox
		}
		return st, err
	}
	m := versionRe.FindStringSubmatch(r.Stdout)
	if m == nil {
		return st, ErrNotProxmox
	}
	st.Version = m[1]

	// /etc/pve/.members is absent on a node that never joined a cluster.
	if b, err := t.Get(ctx, "/etc/pve/.members"); err == nil {
		st.Cluster, st.LocalNode, st.Nodes, err = ParseMembers(b)
		if err != nil {
			return st, fmt.Errorf("/etc/pve/.members: %w", err)
		}
	} else if !isNotExist(err) {
		return st, err
	}
	if len(st.Nodes) == 0 {
		name := hostnameOf(ctx, t)
		st.LocalNode = name
		st.Nodes = []Node{{Name: name, Online: true}}
	}

	if len(st.Nodes) > 1 {
		if err := readNodeKeys(ctx, t, st.Nodes); err != nil {
			return st, fmt.Errorf("ключи узлов кластера: %w", err)
		}
	}

	var roles []struct {
		RoleID string `json:"roleid"`
		Privs  string `json:"privs"`
	}
	if err := pveumJSON(ctx, t, "pveum role list --output-format json", &roles); err != nil {
		return st, err
	}
	for _, ro := range roles {
		if ro.RoleID == RoleName {
			st.RoleExists = true
			st.RolePrivs = splitPrivs(ro.Privs)
		}
	}
	var users []struct {
		UserID string `json:"userid"`
	}
	if err := pveumJSON(ctx, t, "pveum user list --output-format json", &users); err != nil {
		return st, err
	}
	for _, u := range users {
		if u.UserID == UserID {
			st.UserExists = true
		}
	}
	// Asked even when the user is missing: "no such user" just means no tokens.
	var toks []struct {
		TokenID string `json:"tokenid"`
	}
	if err := pveumJSON(ctx, t, "pveum user token list "+UserID+" --output-format json", &toks); err != nil && !isNoSuchUser(err) {
		return st, err
	}
	for _, tk := range toks {
		if tk.TokenID == TokenName {
			st.TokenExist = true
		}
	}
	var acls []struct {
		Path   string `json:"path"`
		RoleID string `json:"roleid"`
		UGID   string `json:"ugid"`
	}
	if err := pveumJSON(ctx, t, "pveum acl list --output-format json", &acls); err != nil {
		return st, err
	}
	for _, a := range acls {
		if a.Path == "/" && a.RoleID == RoleName && a.UGID == UserID {
			st.ACLExists = true
		}
	}
	return st, nil
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

func hostnameOf(ctx context.Context, t target.Target) string {
	if r, err := t.Exec(ctx, "hostname"); err == nil {
		if h := strings.TrimSpace(r.Stdout); h != "" {
			return h
		}
	}
	return "pve"
}

func pveumJSON(ctx context.Context, t target.Target, cmd string, v any) error {
	r, err := t.Exec(ctx, cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", strings.Fields(cmd)[0]+" "+strings.Fields(cmd)[1], err)
	}
	out := strings.TrimSpace(r.Stdout)
	if out == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		return fmt.Errorf("разбор ответа %q: %w", cmd, err)
	}
	return nil
}

func splitPrivs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// ParseMembers parses /etc/pve/.members.
func ParseMembers(b []byte) (cluster, local string, nodes []Node, err error) {
	var m struct {
		NodeName string `json:"nodename"`
		Cluster  *struct {
			Name string `json:"name"`
		} `json:"cluster"`
		NodeList map[string]struct {
			Online int    `json:"online"`
			IP     string `json:"ip"`
		} `json:"nodelist"`
	}
	if err = json.Unmarshal(b, &m); err != nil {
		return
	}
	if m.Cluster != nil {
		cluster = m.Cluster.Name
	}
	local = m.NodeName
	for name, n := range m.NodeList {
		nodes = append(nodes, Node{Name: name, IP: n.IP, Online: n.Online != 0})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return
}

// MissingPrivs returns the privileges of the Hestia role that are not granted yet.
func (s State) MissingPrivs() []string {
	have := map[string]bool{}
	for _, p := range s.RolePrivs {
		have[p] = true
	}
	var miss []string
	for _, p := range Privileges {
		if !have[p] {
			miss = append(miss, p)
		}
	}
	return miss
}

func privString(extra []string) string {
	set := map[string]bool{}
	for _, p := range Privileges {
		set[p] = true
	}
	for _, p := range extra {
		set[p] = true
	}
	all := make([]string, 0, len(set))
	for p := range set {
		all = append(all, p)
	}
	sort.Strings(all)
	return strings.Join(all, ",")
}

// Commands used for changes (also by revert). They are plain strings so the
// order and content are easy to review.
var (
	CmdUserAdd    = "pveum user add " + UserID + " --comment " + target.Quote(Comment)
	CmdUserDel    = "pveum user delete " + UserID
	CmdACLAdd     = "pveum acl modify / --users " + UserID + " --roles " + RoleName
	CmdACLDel     = "pveum acl delete / --users " + UserID + " --roles " + RoleName
	CmdTokenAdd   = "pveum user token add " + UserID + " " + TokenName + " --privsep 0 --output-format json"
	CmdTokenDel   = "pveum user token remove " + UserID + " " + TokenName
	CmdRoleDel    = "pveum role delete " + RoleName
	CmdRoleCreate = "pveum role add " + RoleName + " --privs " + target.Quote(strings.Join(sortedCopy(Privileges), ","))
)

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// CmdRoleModify sets the role to the required privileges plus keep (extra
// privileges that were already granted and must not be removed).
func CmdRoleModify(keep []string) string {
	return "pveum role modify " + RoleName + " --privs " + target.Quote(privString(keep))
}

// CmdRoleRestore sets the role to exactly privs (used by rollback).
func CmdRoleRestore(privs []string) string {
	return "pveum role modify " + RoleName + " --privs " + target.Quote(strings.Join(sortedCopy(privs), ","))
}

// AddToken creates the API token and returns its secret value. The command
// output is never logged by callers.
func AddToken(ctx context.Context, t target.Target) (string, error) {
	r, err := t.Exec(ctx, CmdTokenAdd)
	if err != nil {
		return "", err
	}
	var out struct {
		Value string `json:"value"`
		Full  string `json:"full-tokenid"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.Stdout)), &out); err != nil || out.Value == "" {
		return "", errors.New("Proxmox не вернул значение токена")
	}
	if out.Full != "" && out.Full != TokenID {
		return "", fmt.Errorf("Proxmox создал токен %q вместо %q", out.Full, TokenID)
	}
	return out.Value, nil
}
