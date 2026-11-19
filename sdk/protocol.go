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
)

// Permissions (closed list of protocol v1).
const (
	PermTargetsRead   = "targets.read"
	PermTargetsExec   = "targets.exec"
	PermDeployDocker  = "deploy.docker"
	PermInventoryRead = "inventory.read"
	PermNetOutbound   = "net.outbound"
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
}

// Action is one line of a plan.
type Action struct {
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Risk   string `json:"risk"`
}

// Plan is what the plugin is going to do. Data is opaque to Hestia: it is
// stored with the plan and handed back to Apply unchanged.
type Plan struct {
	Actions  []Action        `json:"actions"`
	Warnings []string        `json:"warnings"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// ApplyRequest carries out a confirmed plan.
type ApplyRequest struct {
	JobID    string   `json:"job_id"`
	Instance Instance `json:"instance"`
	Config   Config   `json:"config"`
	Action   string   `json:"action"`
	Plan     Plan     `json:"plan"`
}

// Status is the health of an instance.
type Status struct {
	State     string     `json:"state"`
	Detail    string     `json:"detail,omitempty"`
	Endpoints []Endpoint `json:"endpoints"`
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
}

// Author is who signed the package.
type Author struct {
	Name string `json:"name"`
	Key  string `json:"key"` // ed25519 public key, base64
}

// Port is a provides/requires entry.
type Port struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
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
