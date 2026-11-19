// Package types is the registry of official link types of Hestia (see
// docs/plugins/types.md): the contract of the data a provider gives a
// consumer ("binding") for every type, Go structures for plugins and the
// validator Hestia runs before a binding reaches the consumer.
//
// A plugin may introduce its own types named "<plugin-id>.<name>"; Hestia
// passes their bindings as they are (a JSON object, no secret fields).
package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
)

// Official type names.
const (
	HTTPServiceType = "http.service"
	CAIssuerType    = "ca.issuer"
	PostgresDBType  = "postgres.db"
	SMBShareType    = "smb.share"
	FSMediaType     = "fs.media"
	TLSCertType     = "tls.cert"
)

// Kinds of binding fields.
const (
	KindString = "string" // one line of text
	KindHost   = "host"   // host name or IP address
	KindPort   = "port"   // 1…65535
	KindURL    = "url"    // http(s) URL
	KindPEM    = "pem"    // PEM certificate(s)
	KindPath   = "path"   // absolute path
	KindEnum   = "enum"   // one of Enum
	KindSecret = "secret" // stored by Hestia; the consumer gets a reference
	KindCSR    = "csr"    // PEM "CERTIFICATE REQUEST"
	KindNames  = "names"  // array of DNS names
	KindIPs    = "ips"    // array of IP addresses
	KindTime   = "time"   // RFC 3339 time
	KindSHA256 = "sha256" // hex (64 characters) or "AA:BB:…"
)

// MaxNames bounds the dns and ips arrays of a request.
const MaxNames = 32

// MaxBinding is the largest binding Hestia accepts (bytes of JSON).
const MaxBinding = 64 << 10

// Field is a field of a binding.
type Field struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Required bool     `json:"required"`
	Enum     []string `json:"enum,omitempty"`
	Help     string   `json:"help,omitempty"`
}

// Type is an official link type.
type Type struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// Version of the contract; fields are only added within a version.
	Version int     `json:"version"`
	Fields  []Field `json:"fields"`
	// Client says what a provider with "client": true does on a device
	// ("" if the type has no client side).
	Client string `json:"client,omitempty"`
	// Request are the fields the consumer gives the provider before the
	// binding (link.prepare); a type with a request needs consumers that
	// implement link.prepare and a preview in link.plan.
	Request []Field `json:"request,omitempty"`
	// Renewable: the binding has not_before/not_after and Hestia renews the
	// link itself at 2/3 of its lifetime (link-renew).
	Renewable bool `json:"renewable,omitempty"`
}

var registry = []Type{
	{
		Name: HTTPServiceType, Title: "HTTP-сервис", Version: 1,
		Description: "Веб-сервис: адрес, по которому потребитель к нему обращается",
		Fields: []Field{
			{Name: "url", Kind: KindURL, Required: true, Help: "полный адрес, например http://10.10.10.21:8080/"},
			{Name: "host", Kind: KindHost, Required: true},
			{Name: "port", Kind: KindPort, Required: true},
			{Name: "scheme", Kind: KindEnum, Required: true, Enum: []string{"http", "https"}},
		},
		Client: "имя сервиса в /etc/hosts устройства",
	},
	{
		Name: CAIssuerType, Title: "Удостоверяющий центр", Version: 1,
		Description: "Домашний CA: корневой сертификат и способ выпуска",
		Fields: []Field{
			{Name: "ca_pem", Kind: KindPEM, Required: true},
			{Name: "sha256", Kind: KindSHA256, Help: "отпечаток ca_pem"},
			{Name: "acme_url", Kind: KindURL},
			{Name: "issue", Kind: KindEnum, Enum: []string{"rpc", "tls.cert"},
				Help: "tls.cert — сертификаты выдаются связью типа tls.cert с этим же экземпляром"},
		},
		Client: "установка корня в системное хранилище доверия устройства",
	},
	{
		Name: TLSCertType, Title: "Сертификат TLS", Version: 1,
		Description: "Сертификат сервера по запросу потребителя (CSR): закрытый ключ не покидает потребителя",
		Request: []Field{
			{Name: "csr_pem", Kind: KindCSR, Required: true, Help: "CERTIFICATE REQUEST (кроме предпросмотра)"},
			{Name: "dns", Kind: KindNames, Help: "DNS-имена, не больше 32"},
			{Name: "ips", Kind: KindIPs, Help: "IP-адреса, не больше 32"},
		},
		Fields: []Field{
			{Name: "cert_pem", Kind: KindPEM, Required: true, Help: "листовой сертификат"},
			{Name: "chain_pem", Kind: KindPEM, Help: "промежуточные сертификаты"},
			{Name: "ca_pem", Kind: KindPEM, Required: true, Help: "корень"},
			{Name: "ca_sha256", Kind: KindSHA256, Required: true, Help: "отпечаток корня"},
			{Name: "dns", Kind: KindNames, Required: true},
			{Name: "ips", Kind: KindIPs, Required: true},
			{Name: "serial", Kind: KindString, Required: true, Help: "hex"},
			{Name: "not_before", Kind: KindTime, Required: true},
			{Name: "not_after", Kind: KindTime, Required: true},
		},
		Renewable: true,
	},
	{
		Name: PostgresDBType, Title: "База PostgreSQL", Version: 1,
		Description: "База данных PostgreSQL и пользователь для потребителя",
		Fields: []Field{
			{Name: "host", Kind: KindHost, Required: true},
			{Name: "port", Kind: KindPort, Required: true},
			{Name: "database", Kind: KindString, Required: true},
			{Name: "user", Kind: KindString, Required: true},
			{Name: "password", Kind: KindSecret, Required: true},
		},
	},
	{
		Name: SMBShareType, Title: "Сетевая папка SMB", Version: 1,
		Description: "Шара Samba/SMB и учётная запись для подключения",
		Fields: []Field{
			{Name: "host", Kind: KindHost, Required: true},
			{Name: "share", Kind: KindString, Required: true},
			{Name: "user", Kind: KindString, Required: true},
			{Name: "password", Kind: KindSecret, Required: true},
			{Name: "vers", Kind: KindString, Help: "версия протокола для mount.cifs, например 3.0"},
		},
		Client: "монтирование шары на устройстве",
	},
	{
		Name: FSMediaType, Title: "Каталог с медиа", Version: 1,
		Description: "Каталог, видимый потребителю (источник — SMB или локальный диск)",
		Fields: []Field{
			{Name: "path", Kind: KindPath, Required: true},
		},
	},
}

// Official returns the official types (a copy).
func Official() []Type {
	out := make([]Type, len(registry))
	for i, t := range registry {
		out[i] = t
		out[i].Fields = slices.Clone(t.Fields)
		out[i].Request = slices.Clone(t.Request)
	}
	return out
}

// Lookup returns an official type.
func Lookup(name string) (Type, bool) {
	for _, t := range registry {
		if t.Name == name {
			return t, true
		}
	}
	return Type{}, false
}

// IsOfficial reports whether name is an official type.
func IsOfficial(name string) bool {
	_, ok := Lookup(name)
	return ok
}

// Prefixes returns the first segments of the official type names ("http",
// "ca", …): a plugin may not use them as its id.
func Prefixes() []string {
	var out []string
	for _, t := range registry {
		p, _, _ := strings.Cut(t.Name, ".")
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// SecretFields returns the names of the secret fields of a type.
func (t Type) SecretFields() []string {
	var out []string
	for _, f := range t.Fields {
		if f.Kind == KindSecret {
			out = append(out, f.Name)
		}
	}
	return out
}

// Error is a binding that does not follow its type.
type Error struct {
	Type  string
	Field string
	Msg   string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Type, e.Msg)
	}
	return fmt.Sprintf("%s: поле %s: %s", e.Type, e.Field, e.Msg)
}

// Decode parses a binding as a JSON object (numbers stay json.Number).
func Decode(raw json.RawMessage) (map[string]any, error) {
	if len(raw) > MaxBinding {
		return nil, errors.New("binding больше 64 КБ")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New("binding должен быть JSON-объектом")
	}
	if dec.More() {
		return nil, errors.New("binding должен быть одним JSON-объектом")
	}
	return m, nil
}

// Validate checks a binding of an official type as the provider sends it:
// secret fields are plain strings. With refs, secret fields must be
// references {"secret": "<name>"} instead (what the consumer receives).
func Validate(name string, raw json.RawMessage, refs bool) (map[string]any, error) {
	t, ok := Lookup(name)
	if !ok {
		return nil, &Error{Type: name, Msg: "неизвестный официальный тип"}
	}
	m, err := validateFields(name, t.Fields, raw, refs, "")
	if err != nil {
		return nil, err
	}
	if name == HTTPServiceType {
		u, _ := url.Parse(m["url"].(string))
		if u.Scheme != m["scheme"] {
			return nil, &Error{Type: name, Field: "scheme", Msg: "не совпадает со схемой url"}
		}
	}
	return m, nil
}

// validateFields checks an object against a list of fields; skip names a
// required field that may be missing (the preview of a request).
func validateFields(name string, fields []Field, raw json.RawMessage, refs bool, skip string) (map[string]any, error) {
	m, err := Decode(raw)
	if err != nil {
		return nil, &Error{Type: name, Msg: err.Error()}
	}
	for k := range m {
		if !slices.ContainsFunc(fields, func(f Field) bool { return f.Name == k }) {
			return nil, &Error{Type: name, Field: k, Msg: "поле не входит в контракт типа"}
		}
	}
	for _, f := range fields {
		v, present := m[f.Name]
		if !present || v == nil {
			if f.Required && f.Name != skip {
				return nil, &Error{Type: name, Field: f.Name, Msg: "обязательное поле"}
			}
			continue
		}
		if msg := checkField(f, v, refs); msg != "" {
			return nil, &Error{Type: name, Field: f.Name, Msg: msg}
		}
	}
	return m, nil
}

// ValidateRequest checks the request of a type with one (tls.cert). A
// preview (link.plan) must not carry the CSR, a full request must.
func ValidateRequest(name string, raw json.RawMessage, preview bool) (map[string]any, error) {
	t, ok := Lookup(name)
	if !ok || len(t.Request) == 0 {
		return nil, &Error{Type: name, Msg: "у типа нет запроса (request)"}
	}
	skip := ""
	if preview {
		skip = "csr_pem"
	}
	m, err := validateFields(name, t.Request, raw, false, skip)
	if err != nil {
		return nil, err
	}
	if name == TLSCertType {
		if _, has := m["csr_pem"]; preview && has {
			return nil, &Error{Type: name, Field: "csr_pem", Msg: "в предпросмотре запроса не бывает CSR"}
		}
		dns, _ := m["dns"].([]any)
		ips, _ := m["ips"].([]any)
		if len(dns)+len(ips) == 0 {
			return nil, &Error{Type: name, Field: "dns", Msg: "нужно хотя бы одно имя или IP-адрес"}
		}
	}
	return m, nil
}

func checkField(f Field, v any, refs bool) string {
	if f.Kind == KindSecret {
		if refs {
			r, ok := v.(map[string]any)
			s, _ := r["secret"].(string)
			if !ok || len(r) != 1 || s == "" {
				return `ожидается ссылка {"secret": "<имя>"}`
			}
			return ""
		}
		s, ok := v.(string)
		if !ok {
			return "ожидается строка (значение секрета)"
		}
		if s == "" || len(s) > 64<<10 {
			return "пустое или слишком длинное значение"
		}
		return ""
	}
	if f.Kind == KindNames || f.Kind == KindIPs {
		list, ok := v.([]any)
		if !ok {
			return "ожидается список строк"
		}
		if len(list) > MaxNames {
			return fmt.Sprintf("не больше %d значений", MaxNames)
		}
		seen := map[string]bool{}
		for _, x := range list {
			s, ok := x.(string)
			if !ok {
				return "ожидается список строк"
			}
			if f.Kind == KindNames && !validDNSName(s) {
				return fmt.Sprintf("%q: ожидается DNS-имя (строчные буквы, цифры, -, .)", s)
			}
			if f.Kind == KindIPs {
				ip := net.ParseIP(s)
				if ip == nil || ip.String() != s {
					return fmt.Sprintf("%q: ожидается IP-адрес в обычной записи", s)
				}
			}
			if seen[s] {
				return fmt.Sprintf("%q указано дважды", s)
			}
			seen[s] = true
		}
		return ""
	}
	if f.Kind == KindPort {
		n, ok := toInt(v)
		if !ok || n < 1 || n > 65535 {
			return "порт от 1 до 65535"
		}
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return "ожидается строка"
	}
	if len(s) > 8<<10 && f.Kind != KindPEM {
		return "слишком длинное значение"
	}
	switch f.Kind {
	case KindString:
		if s == "" || strings.ContainsAny(s, "\n\r\x00") {
			return "одна непустая строка"
		}
	case KindHost:
		if !validHost(s) {
			return "ожидается имя хоста или IP-адрес"
		}
	case KindURL:
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return "ожидается ссылка http(s)"
		}
	case KindPEM:
		if !strings.Contains(s, "-----BEGIN CERTIFICATE-----") || len(s) > 32<<10 {
			return "ожидается сертификат в формате PEM"
		}
	case KindPath:
		if !strings.HasPrefix(s, "/") || path.Clean(s) != s || strings.ContainsAny(s, "\n\r\x00") {
			return "ожидается абсолютный путь без .. и //"
		}
	case KindEnum:
		if !slices.Contains(f.Enum, s) {
			return "допустимо: " + strings.Join(f.Enum, ", ")
		}
	case KindCSR:
		if !strings.Contains(s, "-----BEGIN CERTIFICATE REQUEST-----") || len(s) > 16<<10 {
			return "ожидается запрос сертификата (CSR) в формате PEM"
		}
	case KindTime:
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return "ожидается время RFC 3339"
		}
	case KindSHA256:
		if NormalizeSHA256(s) == "" {
			return "ожидается SHA-256 (64 шестнадцатеричных знака)"
		}
	}
	return ""
}

// NormalizeSHA256 returns a fingerprint as 64 lowercase hex characters (it
// accepts "AA:BB:…" too); "" if it is not one.
func NormalizeSHA256(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, ":", ""))
	if len(s) != 64 {
		return ""
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return s
}

// validDNSName: lowercase LDH labels, no trailing dot, no wildcard.
func validDNSName(s string) bool {
	return s == strings.ToLower(s) && !strings.Contains(s, "*") && validHost(s) && net.ParseIP(s) == nil
}

func validHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		if x != float64(int64(x)) {
			return 0, false
		}
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

// ---- Go structures of the official types ----

// Secret is a secret field. A provider fills Value (Hestia stores it and
// replaces it by a reference); the consumer gets Ref and reads the value
// with Host.SecretGet(ctx, <consumer instance>, Ref).
type Secret struct {
	Value string
	Ref   string
}

// MarshalJSON writes the value (provider) or the reference.
func (s Secret) MarshalJSON() ([]byte, error) {
	if s.Ref != "" {
		return json.Marshal(map[string]string{"secret": s.Ref})
	}
	return json.Marshal(s.Value)
}

// UnmarshalJSON reads a plain value or a reference.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err == nil {
		*s = Secret{Value: v}
		return nil
	}
	var r struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return errors.New(`секрет: ожидается строка или {"secret": "<имя>"}`)
	}
	*s = Secret{Ref: r.Secret}
	return nil
}

// HTTPService is the binding of http.service.
type HTTPService struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
}

// CAIssuer is the binding of ca.issuer.
type CAIssuer struct {
	CAPEM   string `json:"ca_pem"`
	SHA256  string `json:"sha256,omitempty"`
	ACMEURL string `json:"acme_url,omitempty"`
	Issue   string `json:"issue,omitempty"`
}

// PostgresDB is the binding of postgres.db.
type PostgresDB struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password Secret `json:"password"`
}

// SMBShare is the binding of smb.share.
type SMBShare struct {
	Host     string `json:"host"`
	Share    string `json:"share"`
	User     string `json:"user"`
	Password Secret `json:"password"`
	Vers     string `json:"vers,omitempty"`
}

// FSMedia is the binding of fs.media.
type FSMedia struct {
	Path string `json:"path"`
}

// Marshal encodes a binding structure for LinkApply/LinkRefresh.
func Marshal(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return b, err
}
