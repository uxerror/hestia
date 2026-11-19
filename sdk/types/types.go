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
)

// Official type names.
const (
	HTTPServiceType = "http.service"
	CAIssuerType    = "ca.issuer"
	PostgresDBType  = "postgres.db"
	SMBShareType    = "smb.share"
	FSMediaType     = "fs.media"
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
)

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
		Description: "Домашний CA: корневой сертификат и способ выпуска (подробности — этап 2a-3)",
		Fields: []Field{
			{Name: "ca_pem", Kind: KindPEM, Required: true},
			{Name: "acme_url", Kind: KindURL},
			{Name: "issue", Kind: KindEnum, Required: true, Enum: []string{"rpc"}},
		},
		Client: "доверие к CA на устройстве",
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
	m, err := Decode(raw)
	if err != nil {
		return nil, &Error{Type: name, Msg: err.Error()}
	}
	for k := range m {
		if !slices.ContainsFunc(t.Fields, func(f Field) bool { return f.Name == k }) {
			return nil, &Error{Type: name, Field: k, Msg: "поле не входит в контракт типа"}
		}
	}
	for _, f := range t.Fields {
		v, present := m[f.Name]
		if !present || v == nil {
			if f.Required {
				return nil, &Error{Type: name, Field: f.Name, Msg: "обязательное поле"}
			}
			continue
		}
		if msg := checkField(f, v, refs); msg != "" {
			return nil, &Error{Type: name, Field: f.Name, Msg: msg}
		}
	}
	if name == HTTPServiceType {
		u, _ := url.Parse(m["url"].(string))
		if u.Scheme != m["scheme"] {
			return nil, &Error{Type: name, Field: "scheme", Msg: "не совпадает со схемой url"}
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
	}
	return ""
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
	ACMEURL string `json:"acme_url,omitempty"`
	Issue   string `json:"issue"`
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
