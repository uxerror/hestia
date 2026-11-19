package dnsname

import (
	"time"

	"github.com/uxerror/hestia/internal/store"
)

// Name statuses.
const (
	StatusOK          = "ok"
	StatusIPChanged   = "ip_changed"
	StatusMissing     = "missing"
	StatusChanged     = "changed"
	StatusAuthFailed  = "auth_failed"
	StatusCertChanged = "cert_changed"
	StatusUnreachable = "unreachable"
)

// Plan actions.
const (
	ActionAdd      = "add"
	ActionReplace  = "replace"
	ActionUpdateIP = "update_ip"
	ActionRemove   = "remove"
)

// Error is an error with an HTTP status and a code the UI can act on.
type Error struct {
	HTTP        int
	Code        string
	Msg         string
	Fingerprint string // set with Code "cert_changed"
	Job         string // set with Code "busy": the job that runs now
}

func (e *Error) Error() string { return e.Msg }

func newErr(status int, code, msg string) *Error { return &Error{HTTP: status, Code: code, Msg: msg} }

// Endpoint is one address of AdGuard found by the scan.
type Endpoint struct {
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
	Port   int    `json:"port"`
}

// Candidate is one host with AdGuard Home; HTTPS endpoints come first.
type Candidate struct {
	Host      string     `json:"host"`
	Endpoints []Endpoint `json:"endpoints"`
}

// IntegrationView is the connection without secrets.
type IntegrationView struct {
	ID          int64     `json:"id"`
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	BaseURL     string    `json:"base_url"`
	TLSPin      string    `json:"tls_pin"`
	Username    string    `json:"username"`
	HasPassword bool      `json:"has_password"`
	Version     string    `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func viewOf(in store.Integration) *IntegrationView {
	return &IntegrationView{
		ID: in.ID, Kind: in.Kind, Name: in.Name, BaseURL: in.BaseURL, TLSPin: in.TLSPin, Username: in.Username,
		HasPassword: in.SecretID != 0, Version: in.Version, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
	}
}

// NameView is the name of the controller as the UI shows it.
type NameView struct {
	Domain       string     `json:"domain"`
	Answer       string     `json:"answer"`
	Status       string     `json:"status"`
	StatusDetail string     `json:"status_detail"`
	VerifiedAt   *time.Time `json:"verified_at"`
	CheckedAt    *time.Time `json:"checked_at"`
}

// View is the answer of GET /dns.
type View struct {
	Candidates    []Candidate      `json:"candidates"`
	Integration   *IntegrationView `json:"integration"`
	Name          *NameView        `json:"name"`
	ControllerIP  string           `json:"controller_ip"`
	DefaultDomain string           `json:"default_domain"`
	// Local: the controller still runs on the PC.
	Local bool `json:"local"`
}

// ConnectRequest is the body of POST/PUT /dns/adguard. Password is used for
// the check and then stored encrypted; an empty password on PUT keeps the
// stored one.
type ConnectRequest struct {
	URL      string `json:"url"`
	TLSPin   string `json:"tls_pin"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ServerStatus is what AdGuard reported on connection.
type ServerStatus struct {
	Version      string   `json:"version"`
	Running      bool     `json:"running"`
	DNSPort      int      `json:"dns_port"`
	DNSAddresses []string `json:"dns_addresses"`
}

// ConnectResult is the answer of a successful connection.
type ConnectResult struct {
	Integration   *IntegrationView `json:"integration"`
	Server        ServerStatus     `json:"server"`
	Warnings      []string         `json:"warnings"`
	DefaultDomain string           `json:"default_domain"`
	ControllerIP  string           `json:"controller_ip"`
}

// PlanAction is one step the plan will take.
type PlanAction struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // add | update | delete | bind | unbind | verify
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Conflict is an existing record that blocks the plan.
type Conflict struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
	Owner  string `json:"owner"`
}

// Plan is what will be done, awaiting confirmation (plan_id + hash).
type Plan struct {
	PlanID    string       `json:"plan_id"`
	Hash      string       `json:"hash"`
	Action    string       `json:"action"`
	Domain    string       `json:"domain"`
	Answer    string       `json:"answer"`
	Actions   []PlanAction `json:"actions"`
	Conflicts []Conflict   `json:"conflicts"`
	Warnings  []string     `json:"warnings"`
	// NoOp: the record is already there; applying only checks and binds it.
	NoOp bool `json:"noop"`
}
