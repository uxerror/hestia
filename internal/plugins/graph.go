package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uxerror/hestia/internal/netscan"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
)

// linksRecheck: opening the map checks the links again when the last
// check is older than this.
const linksRecheck = time.Minute

// GraphHost is a host of the network map with the target reference it
// corresponds to ("" if none).
type GraphHost struct {
	netscan.Host
	Ref string `json:"ref"`
}

// GraphContainer is a container of an instance (from the last deploy.*).
type GraphContainer struct {
	Name  string           `json:"name"`
	Image string           `json:"image"`
	State string           `json:"state"`
	Ports []sdk.DeployPort `json:"ports"`
}

// GraphInstance is an instance on the map.
type GraphInstance struct {
	ID         int64            `json:"id"`
	PluginID   string           `json:"plugin_id"`
	PluginName string           `json:"plugin_name"`
	Name       string           `json:"name"`
	IconURL    string           `json:"icon_url"`
	Status     string           `json:"status"`
	Detail     string           `json:"detail"`
	HostRef    string           `json:"host_ref"`
	HostIP     string           `json:"host_ip"`
	Controller bool             `json:"controller"` // no target: runs on the controller
	Builtin    bool             `json:"builtin"`    // the pseudo plugin of the controller itself
	Provides   []GraphPort      `json:"provides"`
	Requires   []GraphPort      `json:"requires"`
	Containers []GraphContainer `json:"containers"`
}

// GraphPort is a port of an instance with what the map needs to draw it.
type GraphPort struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Label    string `json:"label"`
	Client   bool   `json:"client,omitempty"`
	Multi    bool   `json:"multi"`
	Optional bool   `json:"optional,omitempty"`
	Linked   int    `json:"linked"`
	// Linkable: the plugin is connected (link.* can be asked).
	Linkable bool `json:"linkable"`
}

// LinkEndView is a side of a link.
type LinkEndView struct {
	Instance int64  `json:"instance"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	PluginID string `json:"plugin_id"`
}

// DeviceView is the device of a link.
type DeviceView struct {
	Ref    string `json:"ref"`
	Name   string `json:"name"`
	HostIP string `json:"host_ip"`
}

// LinkView is a link as the API shows it (binding with references only).
type LinkView struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	Type      string          `json:"type"`
	Provider  LinkEndView     `json:"provider"`
	Consumer  *LinkEndView    `json:"consumer"`
	Device    *DeviceView     `json:"device"`
	Config    json.RawMessage `json:"config"`
	Binding   json.RawMessage `json:"binding"`
	Status    string          `json:"status"`
	Detail    string          `json:"detail"`
	CreatedAt time.Time       `json:"created_at"`
	CheckedAt *time.Time      `json:"checked_at"`
	// Request (names; the CSR is not shown) and renewal of renewable types.
	Request    json.RawMessage `json:"request,omitempty"`
	ExpiresAt  *time.Time      `json:"expires_at"`
	RenewAfter *time.Time      `json:"renew_after"`
	RenewError string          `json:"renew_error"`
}

// Graph is GET /graph.
type Graph struct {
	Hosts        []GraphHost               `json:"hosts"`
	ControllerIP string                    `json:"controller_ip"`
	Instances    []GraphInstance           `json:"instances"`
	Links        []LinkView                `json:"links"`
	Positions    map[string]store.Position `json:"positions"`
}

// graphIndex resolves references and instances for the views.
type graphIndex struct {
	insts   map[int64]store.PluginInstance
	icons   map[string]bool
	mans    map[string]sdk.Manifest
	names   map[string]string // plugin id → name
	cands   map[string]Candidate
	refIP   map[string]string // target ref → IP on the map
	targets map[int64]store.Target
}

func (m *Manager) index(ctx context.Context, hosts []netscan.Host) (*graphIndex, error) {
	ix := &graphIndex{insts: map[int64]store.PluginInstance{}, icons: map[string]bool{}, mans: map[string]sdk.Manifest{}, names: map[string]string{},
		cands: map[string]Candidate{}, refIP: map[string]string{}, targets: map[int64]store.Target{}}
	insts, err := m.Store.ListInstances(ctx, "", false)
	if err != nil {
		return nil, err
	}
	for _, in := range insts {
		ix.insts[in.ID] = in
	}
	ps, err := m.Store.ListPlugins(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		man, _ := storedManifest(p.Manifest)
		ix.mans[p.ID] = man
		ix.icons[p.ID] = p.Icon != ""
		ix.names[p.ID] = man.Name
		if man.Name == "" {
			ix.names[p.ID] = p.ID
		}
	}
	cands, err := m.Candidates(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range cands {
		ix.cands[c.ID] = c
		if net.ParseIP(c.Address) != nil {
			ix.refIP[c.ID] = c.Address
		}
	}
	ts, err := m.Store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		ix.targets[t.ID] = t
	}
	// The inventory links of the map are more reliable than addresses.
	for _, h := range hosts {
		if ref := ix.hostRef(h); ref != "" {
			ix.refIP[ref] = h.IP
		}
	}
	return ix, nil
}

// hostRef is the target reference of a host of the map ("" if none).
func (ix *graphIndex) hostRef(h netscan.Host) string {
	if h.Link != nil {
		switch {
		case h.Link.Kind == "guest" && h.Link.GuestType == "lxc":
			return Ref{Kind: "lxc", TargetID: h.Link.TargetID, Node: h.Link.Node, VMID: h.Link.VMID}.String()
		case h.Link.Kind == "node" && ix.targets[h.Link.TargetID].Kind == store.KindSSH:
			return Ref{Kind: "ssh", TargetID: h.Link.TargetID}.String()
		}
	}
	for ref, c := range ix.cands {
		if c.Address == h.IP {
			return ref
		}
	}
	return ""
}

func (ix *graphIndex) instName(id int64) string {
	if in, ok := ix.insts[id]; ok {
		return in.Name
	}
	return fmt.Sprintf("экземпляр %d", id)
}

func (ix *graphIndex) linkView(l store.PluginLink) LinkView {
	prov := ix.insts[l.ProviderInstance]
	v := LinkView{ID: l.ID, Kind: l.Kind, Status: l.Status, Detail: l.Detail, CreatedAt: l.CreatedAt, CheckedAt: l.CheckedAt,
		Config: json.RawMessage(nonEmptyJSON(l.Config)), Binding: json.RawMessage(nonEmptyJSON(l.Binding)),
		Provider: LinkEndView{Instance: l.ProviderInstance, Port: l.ProviderPort, Name: ix.instName(l.ProviderInstance), PluginID: prov.PluginID},
		Request:  publicRequest(l.Request), ExpiresAt: l.ExpiresAt, RenewAfter: l.RenewAfter, RenewError: l.RenewError}
	if p, ok := findPort(ix.mans[prov.PluginID].Provides, l.ProviderPort); ok {
		v.Type = p.Type
	}
	if l.Kind == store.LinkKindService {
		v.Consumer = &LinkEndView{Instance: l.ConsumerInstance, Port: l.ConsumerPort, Name: ix.instName(l.ConsumerInstance),
			PluginID: ix.insts[l.ConsumerInstance].PluginID}
	} else {
		d := &DeviceView{Ref: l.DeviceRef, Name: l.DeviceRef, HostIP: ix.refIP[l.DeviceRef]}
		if c, ok := ix.cands[l.DeviceRef]; ok {
			d.Name = c.Name
		}
		v.Device = d
	}
	return v
}

func nonEmptyJSON(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}

// Graph assembles the map: hosts, instances (with their host and
// containers), links and saved positions. Links are checked in the
// background when the last check is old.
func (m *Manager) Graph(ctx context.Context) (Graph, error) {
	g := Graph{Hosts: []GraphHost{}, Instances: []GraphInstance{}, Links: []LinkView{}}
	var hosts []netscan.Host
	if m.Netscan != nil {
		v, err := m.Netscan.View(ctx)
		if err != nil {
			return g, err
		}
		hosts = v.Hosts
	}
	ix, err := m.index(ctx, hosts)
	if err != nil {
		return g, err
	}
	onMap := map[string]bool{}
	for _, h := range hosts {
		g.Hosts = append(g.Hosts, GraphHost{Host: h, Ref: ix.hostRef(h)})
		onMap[h.IP] = true
	}
	if loc, err := m.location(ctx); err == nil && loc != nil && onMap[loc.IP] {
		g.ControllerIP = loc.IP
	}
	links, err := m.Store.ListLinks(ctx)
	if err != nil {
		return g, err
	}
	count := map[string]int{} // "<instance>/<p|r>/<port>"
	for _, l := range links {
		count[fmt.Sprintf("%d/p/%s", l.ProviderInstance, l.ProviderPort)]++
		if l.Kind == store.LinkKindService {
			count[fmt.Sprintf("%d/r/%s", l.ConsumerInstance, l.ConsumerPort)]++
		}
		g.Links = append(g.Links, ix.linkView(l))
	}
	for _, in := range sortedInstances(ix.insts) {
		man := ix.mans[in.PluginID]
		gi := GraphInstance{ID: in.ID, PluginID: in.PluginID, PluginName: ix.names[in.PluginID], Name: in.Name, Status: in.Status,
			Detail: in.Detail, Provides: []GraphPort{}, Requires: []GraphPort{}, Containers: []GraphContainer{},
			Builtin: in.PluginID == BuiltinID}
		if gi.Builtin {
			gi.Controller = true
		}
		if gi.PluginName == "" {
			gi.PluginName = in.PluginID
		}
		if ix.icons[in.PluginID] {
			gi.IconURL = "/api/v1/plugins/" + in.PluginID + "/icon"
		}
		linkable := m.conn(in.PluginID) != nil
		for _, p := range man.Provides {
			gi.Provides = append(gi.Provides, GraphPort{Name: p.PortName(), Type: p.Type, Label: p.Label, Client: p.Client,
				Multi: p.IsMulti(true), Linked: count[fmt.Sprintf("%d/p/%s", in.ID, p.PortName())], Linkable: linkable})
		}
		for _, p := range man.Requires {
			gi.Requires = append(gi.Requires, GraphPort{Name: p.PortName(), Type: p.Type, Label: p.Label, Optional: p.Optional,
				Multi: p.IsMulti(false), Linked: count[fmt.Sprintf("%d/r/%s", in.ID, p.PortName())], Linkable: linkable})
		}
		gs, err := m.Store.Grants(ctx, in.ID)
		if err != nil {
			return g, err
		}
		if len(gs) > 0 {
			gi.HostRef = gs[0].Ref
			gi.HostIP = ix.refIP[gi.HostRef]
		} else {
			gi.Controller = true
			gi.HostIP = g.ControllerIP
		}
		var cached []cachedProject
		_ = json.Unmarshal([]byte(in.Containers), &cached)
		for _, p := range cached {
			for _, c := range p.Containers {
				ports := c.Ports
				if ports == nil {
					ports = []sdk.DeployPort{}
				}
				gi.Containers = append(gi.Containers, GraphContainer{Name: c.Name, Image: c.Image, State: c.State, Ports: ports})
			}
		}
		g.Instances = append(g.Instances, gi)
	}
	if g.Positions, err = m.Store.Positions(ctx); err != nil {
		return g, err
	}
	m.mu.Lock()
	stale := m.Now().Sub(m.linksCheckedAt) > linksRecheck
	if stale {
		m.linksCheckedAt = m.Now()
	}
	m.mu.Unlock()
	if stale && len(links) > 0 {
		m.bg.Add(1)
		go func() {
			defer m.bg.Done()
			m.refreshLinks(m.ctx)
		}()
	}
	return g, nil
}

func sortedInstances(in map[int64]store.PluginInstance) []store.PluginInstance {
	out := make([]store.PluginInstance, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Link returns one link; refresh asks both sides for the status first.
func (m *Manager) Link(ctx context.Context, id int64, refresh bool) (LinkView, error) {
	l, err := m.Store.GetLink(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && l.Status == store.LinkDraft) {
		return LinkView{}, newErr(http.StatusNotFound, "связь не найдена")
	}
	if err != nil {
		return LinkView{}, err
	}
	if refresh {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		l, err = m.LinkHealth(cctx, id)
		cancel()
		if err != nil {
			return LinkView{}, err
		}
	}
	ix, err := m.index(ctx, nil)
	if err != nil {
		return LinkView{}, err
	}
	return ix.linkView(l), nil
}

// LinksOf lists the links of an instance.
func (m *Manager) LinksOf(ctx context.Context, iid int64) ([]LinkView, error) {
	links, err := m.Store.LinksOfInstance(ctx, iid)
	if err != nil {
		return nil, err
	}
	ix, err := m.index(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := []LinkView{}
	for _, l := range links {
		out = append(out, ix.linkView(l))
	}
	return out, nil
}

// ---- positions ----

// SavePositions stores the positions of map nodes the user moved.
func (m *Manager) SavePositions(ctx context.Context, ps map[string]store.Position) error {
	if len(ps) > store.MaxPositions {
		return newErr(http.StatusBadRequest, "больше %d узлов", store.MaxPositions)
	}
	for id, p := range ps {
		if id == "" || len(id) > 200 || !utf8.ValidString(id) || strings.ContainsAny(id, "\x00\n\r") {
			return newErr(http.StatusBadRequest, "неверный id узла %q", truncate(id, 50))
		}
		if math.IsNaN(p.X) || math.IsNaN(p.Y) || p.X > 1e7 || p.X < -1e7 || p.Y > 1e7 || p.Y < -1e7 {
			return newErr(http.StatusBadRequest, "неверная позиция узла %q", truncate(id, 50))
		}
	}
	return m.Store.SavePositions(ctx, ps)
}

// ClearPositions forgets every saved position (the map is laid out again).
func (m *Manager) ClearPositions(ctx context.Context) error { return m.Store.ClearPositions(ctx) }

// ---- candidates ----

// LinkCandidate is a port (or device) the given port can be linked to.
type LinkCandidate struct {
	Instance   int64  `json:"instance,omitempty"`
	PluginID   string `json:"plugin_id,omitempty"`
	PluginName string `json:"plugin_name,omitempty"`
	Name       string `json:"name"`
	Port       string `json:"port,omitempty"`
	Label      string `json:"label,omitempty"`
	Status     string `json:"status,omitempty"`
	HostRef    string `json:"host_ref,omitempty"`
	// Device candidates (dir=provides, client ports).
	Device  string `json:"device,omitempty"`
	Address string `json:"address,omitempty"`
	// Busy: the other port takes one link and has it; Reason says why the
	// candidate cannot be chosen.
	Busy      bool   `json:"busy"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// PluginOffer is an installed plugin that could provide the type as a new
// instance ("Создать новый").
type PluginOffer struct {
	PluginID string `json:"plugin_id"`
	Name     string `json:"name"`
	Port     string `json:"port"`
	Enabled  bool   `json:"enabled"`
}

// LinkCandidates is GET /plugins/links/candidates.
type LinkCandidates struct {
	Type      string          `json:"type"`
	Ports     []LinkCandidate `json:"ports"`
	Devices   []LinkCandidate `json:"devices"`
	NewPlugin []PluginOffer   `json:"new_plugins"`
}

// Candidates lists what a port can be linked to: for a requires port the
// compatible provides ports (and plugins to create a provider from); for a
// provides port the compatible requires ports and, for a client port, the
// devices.
func (m *Manager) LinkCandidates(ctx context.Context, iid int64, port, dir string) (LinkCandidates, error) {
	out := LinkCandidates{Ports: []LinkCandidate{}, Devices: []LinkCandidate{}, NewPlugin: []PluginOffer{}}
	inst, err := m.Store.GetInstance(ctx, iid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && inst.Status == store.InstanceDraft) {
		return out, newErr(http.StatusNotFound, "экземпляр не найден")
	}
	if err != nil {
		return out, err
	}
	ix, err := m.index(ctx, nil)
	if err != nil {
		return out, err
	}
	man := ix.mans[inst.PluginID]
	var own sdk.Port
	var ok bool
	switch dir {
	case "requires":
		own, ok = findPort(man.Requires, port)
	case "provides":
		own, ok = findPort(man.Provides, port)
	default:
		return out, newErr(http.StatusBadRequest, "dir: provides или requires")
	}
	if !ok {
		return out, newErr(http.StatusNotFound, "у экземпляра нет порта %s %q", dir, port)
	}
	out.Type = own.Type
	links, err := m.Store.ListLinks(ctx)
	if err != nil {
		return out, err
	}
	used := func(id int64, p string, provides bool) int {
		n := 0
		for _, l := range links {
			if provides && l.ProviderInstance == id && l.ProviderPort == p {
				n++
			}
			if !provides && l.Kind == store.LinkKindService && l.ConsumerInstance == id && l.ConsumerPort == p {
				n++
			}
		}
		return n
	}
	linked := func(prov int64, pport string, cons int64, cport string) bool {
		for _, l := range links {
			if l.Kind == store.LinkKindService && l.ProviderInstance == prov && l.ProviderPort == pport && l.ConsumerInstance == cons && l.ConsumerPort == cport {
				return true
			}
		}
		return false
	}
	ownBusy := !own.IsMulti(dir == "provides") && used(iid, own.PortName(), dir == "provides") > 0
	for _, other := range sortedInstances(ix.insts) {
		if other.ID == iid {
			continue
		}
		oman := ix.mans[other.PluginID]
		list := oman.Provides
		if dir == "provides" {
			list = oman.Requires
		}
		gs, _ := m.Store.Grants(ctx, other.ID)
		for _, p := range list {
			if p.Type != own.Type {
				continue
			}
			c := LinkCandidate{Instance: other.ID, PluginID: other.PluginID, PluginName: ix.names[other.PluginID], Name: other.Name,
				Port: p.PortName(), Label: p.Label, Status: other.Status, Available: true}
			if len(gs) > 0 {
				c.HostRef = gs[0].Ref
			}
			c.Busy = !p.IsMulti(dir == "requires") && used(other.ID, p.PortName(), dir == "requires") > 0
			switch {
			case dir == "requires" && linked(other.ID, p.PortName(), iid, own.PortName()),
				dir == "provides" && linked(iid, own.PortName(), other.ID, p.PortName()):
				c.Available, c.Reason = false, "уже связаны"
			case c.Busy:
				c.Available, c.Reason = false, "порт уже занят"
			case ownBusy:
				c.Available, c.Reason = false, "этот порт уже занят"
			case m.conn(other.PluginID) == nil:
				c.Available, c.Reason = false, "плагин не подключён"
			}
			out.Ports = append(out.Ports, c)
		}
	}
	if dir == "requires" {
		ps, err := m.Store.ListPlugins(ctx)
		if err != nil {
			return out, err
		}
		for _, p := range ps {
			pman := ix.mans[p.ID]
			if pp, err := providerPort(pman, "", own.Type); err == nil {
				out.NewPlugin = append(out.NewPlugin, PluginOffer{PluginID: p.ID, Name: ix.names[p.ID], Port: pp.PortName(), Enabled: p.Enabled})
			}
		}
		return out, nil
	}
	if !own.Client || !slices.Contains(man.Permissions, sdk.PermLinksClient) {
		return out, nil
	}
	gs, _ := m.Store.Grants(ctx, iid)
	for _, ref := range sortedRefs(ix.cands) {
		c := ix.cands[ref]
		lc := LinkCandidate{Name: c.Name, Device: c.ID, Address: c.Address, Available: c.Available, Reason: c.Reason}
		for _, l := range links {
			if l.Kind == store.LinkKindDevice && l.ProviderInstance == iid && l.ProviderPort == own.PortName() && l.DeviceRef == c.ID {
				lc.Available, lc.Reason = false, "уже связаны"
			}
		}
		if hasRef(gs, c.ID) && lc.Available {
			lc.Reason = "цель самого экземпляра"
		}
		if ownBusy && lc.Available {
			lc.Available, lc.Reason = false, "этот порт уже занят"
		}
		out.Devices = append(out.Devices, lc)
	}
	return out, nil
}

func sortedRefs(m map[string]Candidate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
