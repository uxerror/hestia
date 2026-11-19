// Package sdk is the Go SDK for Hestia plugins. A plugin is a separate
// process that talks to the Hestia controller over JSON-RPC 2.0 (package
// sdk/rpc): Hestia asks it to validate, plan, apply and check instances; the
// plugin reaches targets, secrets and jobs only through the Hestia API (Host)
// and only within the permissions of its manifest. The protocol is described
// in docs/plugins/protocol.md. Only the standard library is used.
package sdk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Protocol is the protocol version this SDK speaks.
const Protocol = 1

// Methods a plugin implements (Hestia → plugin).
const (
	MethodManifest = "manifest"
	MethodValidate = "instance.validate"
	MethodPlan     = "instance.plan"
	MethodApply    = "instance.apply"
	MethodStatus   = "instance.status"

	// Links (optional: a plugin without them answers -32601 and its ports
	// cannot be linked).
	MethodLinkPlan    = "link.plan"
	MethodLinkApply   = "link.apply"
	MethodLinkRemove  = "link.remove"
	MethodLinkStatus  = "link.status"
	MethodLinkRefresh = "link.refresh"
	// MethodLinkPrepare asks the consumer of a link whose type has a request
	// (tls.cert) for that request before the provider is called.
	MethodLinkPrepare = "link.prepare"

	// MethodAction runs an action of the manifest (optional: a plugin
	// without it answers -32601).
	MethodAction = "instance.action"
)

// Methods of Hestia (plugin → Hestia).
const (
	MethodHello        = "hello"
	MethodJobStep      = "job.step"
	MethodJobStepDone  = "job.step_done"
	MethodJobLog       = "job.log"
	MethodSecretPut    = "secret.put"
	MethodSecretGet    = "secret.get"
	MethodSecretDelete = "secret.delete"
	MethodTargetList   = "target.list"
	MethodTargetExec   = "target.exec"
	MethodTargetPut    = "target.put_file"
	MethodInventoryGet = "inventory.get"
	MethodLog          = "log"
	MethodDeployPlan   = "deploy.plan"
	MethodDeployUp     = "deploy.up"
	MethodDeployDown   = "deploy.down"
	MethodDeployStatus = "deploy.status"
)

// Permissions (closed list of protocol v1).
const (
	PermTargetsRead   = "targets.read"
	PermTargetsExec   = "targets.exec"
	PermDeployDocker  = "deploy.docker"
	PermInventoryRead = "inventory.read"
	PermNetOutbound   = "net.outbound"
	// PermLinksClient lets a provider configure the client side of a link on
	// a device of the user (hosts entry, mount, CA trust); ports with
	// "client": true need it.
	PermLinksClient = "links.client"
)

// Link kinds.
const (
	// LinkService connects a "requires" port of one instance to a
	// "provides" port of another.
	LinkService = "service"
	// LinkDevice lets a provider set up its client side on a device.
	LinkDevice = "device"
)

// Roles of a plugin in a link call.
const (
	RoleProvider = "provider" // the provides side of a service link
	RoleConsumer = "consumer" // the requires side of a service link
	RoleClient   = "client"   // the provider of a device link
)

// Plan actions.
const (
	ActionCreate = "create"
	ActionUpdate = "update"
	ActionRemove = "remove"
)

// Risk levels of a plan action.
const (
	RiskInfo   = "info"
	RiskChange = "change"
	RiskDanger = "danger"
)

// Instance states reported by Status.
const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"
	StateUnknown  = "unknown"
)

// Hello is the first message of a plugin.
type Hello struct {
	Protocol int    `json:"protocol"`
	ID       string `json:"id"`
	Version  string `json:"version"`
	Token    string `json:"token"`
}

// Welcome is Hestia's answer to hello.
type Welcome struct {
	Protocol      int        `json:"protocol"`
	HestiaVersion string     `json:"hestia_version"`
	Instances     []Instance `json:"instances"`
	// Links are the active links of the plugin's instances at connect time
	// (a consumer can restore its bindings without its own state).
	Links []LinkInfo `json:"links,omitempty"`
}

// LinkInfo describes an active link of one of the plugin's instances.
type LinkInfo struct {
	Link     int64           `json:"link"`
	Kind     string          `json:"kind"`
	Role     string          `json:"role"`
	Instance int64           `json:"instance"`
	Port     string          `json:"port"`
	Peer     *LinkPeer       `json:"peer,omitempty"`
	Device   string          `json:"device,omitempty"`
	Binding  json.RawMessage `json:"binding,omitempty"`
}

// Instance is a configured copy of the plugin. ID is 0 only in theory: an
// instance being created gets its id before the first plan.
type Instance struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Config Config `json:"config"`
}

// Config is the instance configuration (field name → value). A "secret"
// field holds {"secret": "<name>"}: read the value with Host.SecretGet.
// A "target" field holds the target id (see TargetInfo.ID).
type Config map[string]any

// String returns a string field ("" if missing or not a string).
func (c Config) String(name string) string {
	s, _ := c[name].(string)
	return s
}

// Int returns an integer field (0 if missing or not a number).
func (c Config) Int(name string) int64 {
	switch v := c[name].(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case int:
		return int64(v)
	case int64:
		return v
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

// Bool returns a boolean field.
func (c Config) Bool(name string) bool {
	b, _ := c[name].(bool)
	return b
}

// SecretName returns the secret name a "secret" field refers to.
func (c Config) SecretName(name string) string {
	if m, ok := c[name].(map[string]any); ok {
		s, _ := m["secret"].(string)
		return s
	}
	return ""
}

// FieldError is a validation error of one field.
type FieldError struct {
	Field string `json:"field"`
	Msg   string `json:"msg"`
}

// PlanRequest asks what create/update/remove of an instance would do.
type PlanRequest struct {
	Instance Instance `json:"instance"`
	Config   Config   `json:"config"`
	Action   string   `json:"action"`
	// Links are the providers that will be linked to the new instance right
	// after it is created (a composite plan); the binding comes later with
	// link.apply.
	Links []PlannedLink `json:"links,omitempty"`
}

// PlannedLink is a link of a composite plan: Port is the instance's own
// (requires) port, Peer the provider.
type PlannedLink struct {
	Port string   `json:"port"`
	Peer LinkPeer `json:"peer"`
}

// Action is one line of a plan.
type Action struct {
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Risk   string `json:"risk"`
}

// Plan is what the plugin is going to do. Data is opaque to Hestia: it is
// stored with the plan and handed back to Apply unchanged. Request is set
// only by the consumer of a link whose type has a request (tls.cert): the
// preview of what it will ask the provider for (no key material, e.g. the
// names without the CSR); Hestia shows it to the provider's link.plan.
type Plan struct {
	Actions  []Action        `json:"actions"`
	Warnings []string        `json:"warnings"`
	Data     json.RawMessage `json:"data,omitempty"`
	Request  json.RawMessage `json:"request,omitempty"`
}

// ApplyRequest carries out a confirmed plan.
type ApplyRequest struct {
	JobID    string        `json:"job_id"`
	Instance Instance      `json:"instance"`
	Config   Config        `json:"config"`
	Action   string        `json:"action"`
	Plan     Plan          `json:"plan"`
	Links    []PlannedLink `json:"links,omitempty"`
}

// ---- links (Hestia → plugin) ----

// LinkPeer is the other side of a service link: the only foreign instance
// a plugin ever learns about.
type LinkPeer struct {
	Plugin   string `json:"plugin"`
	Instance int64  `json:"instance"`
	Name     string `json:"name"`
	Port     string `json:"port"`
}

// LinkRequest is the parameter of every link.* method. Instance is the
// plugin's own instance of this side, Port its port; Peer is set for
// service links, Device (a target of the user, with its address) for
// device links. Action is "create" or "remove" (link.plan); JobID is set
// in link.apply and link.remove; Binding is what the provider gave
// (consumer and client in link.apply; secrets are references
// {"secret": "link:<id>:<field>"}, read them with Host.SecretGet); Plan is
// this side's plan (link.apply, link.remove).
//
// Request is what the consumer asks for (types with a request, tls.cert):
// the preview in the provider's link.plan, the full request (with the CSR)
// in the provider's link.apply and link.refresh, the consumer's own request
// in its link.apply. Reason is the cause of link.prepare: create, renew or
// reissue.
type LinkRequest struct {
	JobID    string          `json:"job_id,omitempty"`
	Link     int64           `json:"link"`
	Kind     string          `json:"kind"`
	Role     string          `json:"role"`
	Action   string          `json:"action,omitempty"`
	Instance Instance        `json:"instance"`
	Port     string          `json:"port"`
	Type     string          `json:"type"`
	Peer     *LinkPeer       `json:"peer,omitempty"`
	Device   *TargetInfo     `json:"device,omitempty"`
	Config   Config          `json:"config"`
	Binding  json.RawMessage `json:"binding,omitempty"`
	Plan     *Plan           `json:"plan,omitempty"`
	Request  json.RawMessage `json:"request,omitempty"`
	Reason   string          `json:"reason,omitempty"`
}

// Reasons of link.prepare.
const (
	ReasonCreate  = "create"
	ReasonRenew   = "renew"
	ReasonReissue = "reissue"
)

// LinkPrepared is the answer of link.prepare.
type LinkPrepared struct {
	Request json.RawMessage `json:"request"`
}

// LinkResult is the answer of link.apply and link.refresh: the provider
// returns the binding (data by the contract of the port type, see
// sdk/types); a consumer returns an empty object.
type LinkResult struct {
	Binding json.RawMessage `json:"binding,omitempty"`
}

// LinkStatus is the health of one side of a link.
type LinkStatus struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// Status is the health of an instance. ActionsEnabled lists the actions of
// the manifest that can run now (nil: all of them).
type Status struct {
	State          string     `json:"state"`
	Detail         string     `json:"detail,omitempty"`
	Endpoints      []Endpoint `json:"endpoints"`
	ActionsEnabled []string   `json:"actions_enabled"`
}

// ActionRequest runs an action of the manifest. Params are the values of the
// action's fields (secret fields as plain strings): Hestia stores them
// nowhere and masks secret ones in the job log.
type ActionRequest struct {
	JobID    string   `json:"job_id,omitempty"`
	Instance Instance `json:"instance"`
	Action   string   `json:"action"`
	Params   Config   `json:"params"`
}

// MaxDownload bounds ActionResult.Download.Data.
const MaxDownload = 1 << 20

// ActionResult is the answer of instance.action: a message for the user
// and/or a file the browser downloads (Hestia does not keep it).
type ActionResult struct {
	Message  string    `json:"message,omitempty"`
	Download *Download `json:"download,omitempty"`
}

// Download is a file returned by an action.
type Download struct {
	Name string `json:"name"`
	MIME string `json:"mime"`
	Data []byte `json:"data_b64"`
}

// Endpoint is a link shown with the instance (http/https only).
type Endpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ---- Hestia API types ----

// InstanceRef addresses an instance in Hestia calls.
type InstanceRef struct {
	Instance int64 `json:"instance"`
}

// TargetInfo is a target granted to an instance.
type TargetInfo struct {
	// ID is the grant reference: "ssh:<target>" or "lxc:<target>:<node>:<vmid>".
	ID            string `json:"id"`
	Kind          string `json:"kind"` // ssh | lxc
	Name          string `json:"name"`
	Address       string `json:"address"`
	OS            string `json:"os"`
	Root          bool   `json:"root"`
	Sudo          bool   `json:"sudo"`
	DockerCapable bool   `json:"docker_capable"`
}

// ExecRequest runs a command as root on a granted target.
type ExecRequest struct {
	Instance int64  `json:"instance"`
	Target   string `json:"target"`
	Cmd      string `json:"cmd"`
	Stdin    string `json:"stdin,omitempty"`
	TimeoutS int    `json:"timeout_s,omitempty"`
}

// ExecResult is the outcome of a command (output is truncated by Hestia).
type ExecResult struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// PutFileRequest writes a file on a granted target. Mode is octal text
// ("0644").
type PutFileRequest struct {
	Instance int64  `json:"instance"`
	Target   string `json:"target"`
	Path     string `json:"path"`
	DataB64  string `json:"data_b64"`
	Mode     string `json:"mode"`
}

// SecretRequest addresses a secret of an instance (Value only for put).
type SecretRequest struct {
	Instance int64  `json:"instance"`
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
}

// SecretValue is the answer of secret.get.
type SecretValue struct {
	Value  string `json:"value"`
	Exists bool   `json:"exists"`
}

// JobStep, JobStepDone and JobLog report progress of an apply job.
type JobStep struct {
	JobID string `json:"job_id"`
	Title string `json:"title"`
}

// JobStepDone closes the current step; a non-empty Error fails it.
type JobStepDone struct {
	JobID string `json:"job_id"`
	Error string `json:"error,omitempty"`
}

// JobLog is a job log line (level: info, warn, error).
type JobLog struct {
	JobID string `json:"job_id"`
	Level string `json:"level"`
	Line  string `json:"line"`
}

// LogLine is a line of the plugin's system log.
type LogLine struct {
	Level string `json:"level"`
	Line  string `json:"line"`
}

// ---- deploy (Docker compose on a granted target, needs deploy.docker) ----

// DeployFile is a file of a compose project, written next to compose.yaml
// (name without "/", at most 1 MB, mode 0640, owner root).
type DeployFile struct {
	Name string `json:"name"`
	Data []byte `json:"data_b64"`
}

// DeployRequest is the parameter of deploy.plan and deploy.up. Compose is
// the compose file as a JSON object (Docker compose reads JSON as YAML);
// JobID is required for deploy.up (the apply job the steps go to). Images
// are names from the manifest's "images": Hestia loads them from the plugin
// package onto the target (docker import) as
// hestia.local/<plugin>/<name>:<plugin version>.
type DeployRequest struct {
	JobID    string          `json:"job_id,omitempty"`
	Instance int64           `json:"instance"`
	Target   string          `json:"target"`
	Project  string          `json:"project"`
	Compose  json.RawMessage `json:"compose"`
	Files    []DeployFile    `json:"files,omitempty"`
	Images   []string        `json:"images,omitempty"`
}

// DeployDownRequest stops and removes a project (Volumes: its named volumes
// too).
type DeployDownRequest struct {
	JobID    string `json:"job_id"`
	Instance int64  `json:"instance"`
	Target   string `json:"target"`
	Project  string `json:"project"`
	Volumes  bool   `json:"volumes"`
}

// DeployStatusRequest asks about a project.
type DeployStatusRequest struct {
	Instance int64  `json:"instance"`
	Target   string `json:"target"`
	Project  string `json:"project"`
}

// File actions of a deploy plan.
const (
	FileCreate    = "create"
	FileUpdate    = "update"
	FileUnchanged = "unchanged"
	FileRemove    = "remove"
)

// DeployFileChange is one file of a deploy plan.
type DeployFileChange struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Size    int64  `json:"size"`
	OldSize int64  `json:"old_size"`
}

// DeployPlan is the answer of deploy.plan: what deploy.up would do. Put
// Actions and Warnings into the instance plan as they are (an action with
// risk "danger" makes the user confirm it).
type DeployPlan struct {
	// Project is the compose project name, Dir its directory on the target.
	Project string `json:"project"`
	Dir     string `json:"dir"`
	// Exists: the project directory is there; Changed: some file differs.
	Exists  bool `json:"exists"`
	Changed bool `json:"changed"`
	// InstallDocker / EnableFeatures: deploy.up will install Docker or
	// switch on nesting/keyctl of the container (and restart it).
	InstallDocker  bool               `json:"install_docker"`
	EnableFeatures bool               `json:"enable_features"`
	Files          []DeployFileChange `json:"files"`
	Actions        []Action           `json:"actions"`
	Warnings       []string           `json:"warnings"`
}

// DeployPort is a published port of a container.
type DeployPort struct {
	URL           string `json:"url"`
	TargetPort    int    `json:"target_port"`
	PublishedPort int    `json:"published_port"`
	Protocol      string `json:"protocol"`
}

// DeployContainer is a line of `docker compose ps`.
type DeployContainer struct {
	Name     string       `json:"name"`
	Service  string       `json:"service"`
	Image    string       `json:"image,omitempty"`
	State    string       `json:"state"`
	Status   string       `json:"status"`
	Health   string       `json:"health"`
	ExitCode int          `json:"exit_code"`
	Ports    []DeployPort `json:"ports"`
}

// DeployStatus is the answer of deploy.status and deploy.up.
type DeployStatus struct {
	Project    string            `json:"project"`
	Docker     bool              `json:"docker"`
	Exists     bool              `json:"exists"`
	Containers []DeployContainer `json:"containers"`
}

// Running reports whether every container of the project runs (and there
// is at least one).
func (s DeployStatus) Running() bool {
	if len(s.Containers) == 0 {
		return false
	}
	for _, c := range s.Containers {
		if c.State != "running" {
			return false
		}
	}
	return true
}

// ---- manifest ----

// Manifest describes a plugin (manifest.json, embedded into the binary).
type Manifest struct {
	Protocol      int      `json:"protocol"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Description   string   `json:"description"`
	Homepage      string   `json:"homepage,omitempty"`
	Author        Author   `json:"author"`
	MinHestia     string   `json:"min_hestia,omitempty"`
	Permissions   []string `json:"permissions"`
	Provides      []Port   `json:"provides"`
	Requires      []Port   `json:"requires"`
	MultiInstance bool     `json:"multi_instance"`
	Schema        Schema   `json:"schema"`
	// Images are container images shipped in the package (static binaries,
	// see docs/plugins/protocol.md); Actions are buttons of an instance.
	Images  []Image     `json:"images,omitempty"`
	Actions []ActionDef `json:"actions,omitempty"`
}

// Image is a container image in the package: the file "image-<name>" is a
// static linux/amd64 binary that becomes /<name> of the image.
type Image struct {
	Name string `json:"name"`
	File string `json:"file"`
}

// ImageRef is how a compose file refers to an image of the package.
func ImageRef(plugin, name, version string) string {
	return "hestia.local/" + plugin + "/" + name + ":" + version
}

// ActionDef is an action of an instance (instance.action). Confirm
// "password" makes the user enter the Hestia administrator password; Fields
// are a subset of the form types (string, text, secret, bool, enum).
type ActionDef struct {
	Name    string  `json:"name"`
	Label   string  `json:"label"`
	Confirm string  `json:"confirm,omitempty"`
	Fields  []Field `json:"fields,omitempty"`
}

// ConfirmPassword is ActionDef.Confirm for actions that need the
// administrator password.
const ConfirmPassword = "password"

// Author is who signed the package.
type Author struct {
	Name string `json:"name"`
	Key  string `json:"key"` // ed25519 public key, base64
}

// Port is a provides/requires entry. Name defaults to Type with "." and
// "-" replaced by "_" (manifests of protocol 1 before links had no names).
// Multi: provides — may serve many consumers (default true); requires —
// may be linked to several providers (default false). Client (provides
// only): the provider can set up the client side on a device (needs the
// links.client permission). Optional (requires only): the instance works
// without it. LinkSchema (provides only): fields of the link form (as
// schema.fields, without target and secret).
type Port struct {
	Type       string  `json:"type"`
	Name       string  `json:"name,omitempty"`
	Label      string  `json:"label,omitempty"`
	Client     bool    `json:"client,omitempty"`
	Multi      *bool   `json:"multi,omitempty"`
	Optional   bool    `json:"optional,omitempty"`
	LinkSchema *Schema `json:"link_schema,omitempty"`
}

// DefaultPortName is the name of a port without one.
func DefaultPortName(typ string) string {
	return strings.NewReplacer(".", "_", "-", "_").Replace(typ)
}

// PortName returns the name of the port (or its default).
func (p Port) PortName() string {
	if p.Name != "" {
		return p.Name
	}
	return DefaultPortName(p.Type)
}

// IsMulti reports whether the port takes several links; provides is true
// for a provides port (default true), false for requires (default false).
func (p Port) IsMulti(provides bool) bool {
	if p.Multi != nil {
		return *p.Multi
	}
	return provides
}

// Schema is the instance form.
type Schema struct {
	Fields  []Field  `json:"fields"`
	Presets []Preset `json:"presets,omitempty"`
}

// Field types of the form.
const (
	FieldString = "string"
	FieldText   = "text"
	FieldInt    = "int"
	FieldBool   = "bool"
	FieldEnum   = "enum"
	FieldSecret = "secret"
	FieldTarget = "target"
)

// Field is one input of the instance form.
type Field struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Label    string         `json:"label"`
	Help     string         `json:"help,omitempty"`
	Default  any            `json:"default,omitempty"`
	Required bool           `json:"required,omitempty"`
	Advanced bool           `json:"advanced,omitempty"`
	Min      *float64       `json:"min,omitempty"`
	Max      *float64       `json:"max,omitempty"`
	MaxLen   int            `json:"max_len,omitempty"`
	MinLen   int            `json:"min_len,omitempty"`
	Pattern  string         `json:"pattern,omitempty"`
	Options  []Option       `json:"options,omitempty"`
	Filter   map[string]any `json:"filter,omitempty"`
}

// Option is a value of an enum field.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Preset is a named set of field values shown above the form.
type Preset struct {
	Name   string         `json:"name"`
	Label  string         `json:"label"`
	Values map[string]any `json:"values"`
}

// ParseManifest decodes manifest.json (no semantic validation: Hestia does
// that when installing).
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("manifest.json: %w", err)
	}
	return m, nil
}
