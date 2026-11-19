// Package plugins installs, runs and supervises Hestia plugins: separate
// processes in a systemd sandbox (or child processes in dev mode) that talk
// to the controller over JSON-RPC (sdk/rpc). Every call a plugin makes is
// checked against the permissions of its manifest and the target grants of
// the instance (see host.go).
package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/uxerror/hestia/internal/version"
	"github.com/uxerror/hestia/sdk"
)

var (
	reID        = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	rePortType  = regexp.MustCompile(`^[a-z][a-z0-9.-]+$`)
	reFieldName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
)

// Permissions is the closed list of protocol v1.
var Permissions = []string{sdk.PermTargetsRead, sdk.PermTargetsExec, sdk.PermDeployDocker, sdk.PermInventoryRead, sdk.PermNetOutbound}

// reservedIDs collide with API paths under /api/v1/plugins/.
var reservedIDs = []string{"authors", "catalog", "install", "instances", "packages", "plans", "targets"}

var fieldTypes = []string{sdk.FieldString, sdk.FieldText, sdk.FieldInt, sdk.FieldBool, sdk.FieldEnum, sdk.FieldSecret, sdk.FieldTarget}

// ParseManifest decodes and validates manifest.json. The author key is not
// checked here (a dev plugin may have none); packages check it on reading.
func ParseManifest(b []byte) (sdk.Manifest, error) {
	var m sdk.Manifest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return m, pkgErr("manifest.json не разбирается: %v", err)
	}
	if err := ValidateManifest(m); err != nil {
		return m, err
	}
	return m, nil
}

// ValidateManifest checks the semantics of a manifest.
func ValidateManifest(m sdk.Manifest) error {
	switch {
	case m.Protocol != sdk.Protocol:
		return pkgErr("плагин написан для протокола %d, Hestia поддерживает %d", m.Protocol, sdk.Protocol)
	case !reID.MatchString(m.ID):
		return pkgErr("неверный id плагина %q: строчные латинские буквы, цифры и дефис, 2–40 символов", m.ID)
	case slices.Contains(reservedIDs, m.ID):
		return pkgErr("id плагина %q зарезервирован", m.ID)
	case strings.TrimSpace(m.Name) == "" || len(m.Name) > 100:
		return pkgErr("у плагина нет имени (name) или оно длиннее 100 символов")
	case len(m.Description) > 1000:
		return pkgErr("описание плагина длиннее 1000 символов")
	case len(m.Author.Name) > 100:
		return pkgErr("имя автора длиннее 100 символов")
	}
	if v, ok := version.Parse(m.Version); !ok || !v.Tag() {
		return pkgErr("версия плагина %q должна быть вида vX.Y.Z", m.Version)
	}
	if m.MinHestia != "" {
		if _, ok := version.Parse(m.MinHestia); !ok {
			return pkgErr("min_hestia %q должна быть вида vX.Y.Z", m.MinHestia)
		}
	}
	if m.Homepage != "" {
		u, err := url.Parse(m.Homepage)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return pkgErr("homepage должна быть ссылкой http(s)")
		}
	}
	seen := map[string]bool{}
	for _, p := range m.Permissions {
		if !slices.Contains(Permissions, p) {
			return pkgErr("неизвестное право %q", p)
		}
		if seen[p] {
			return pkgErr("право %q указано дважды", p)
		}
		seen[p] = true
	}
	for _, list := range [][]sdk.Port{m.Provides, m.Requires} {
		for _, p := range list {
			if !rePortType.MatchString(p.Type) || len(p.Type) > 64 || len(p.Name) > 64 {
				return pkgErr("неверный тип связи %q в provides/requires", p.Type)
			}
		}
	}
	return validateSchema(m.Schema)
}

func validateSchema(s sdk.Schema) error {
	if len(s.Fields) > 64 {
		return pkgErr("в форме больше 64 полей")
	}
	names := map[string]sdk.Field{}
	for _, f := range s.Fields {
		if !reFieldName.MatchString(f.Name) {
			return pkgErr("неверное имя поля %q", f.Name)
		}
		if _, dup := names[f.Name]; dup {
			return pkgErr("поле %q указано дважды", f.Name)
		}
		names[f.Name] = f
		if !slices.Contains(fieldTypes, f.Type) {
			return pkgErr("поле %s: неизвестный тип %q", f.Name, f.Type)
		}
		if strings.TrimSpace(f.Label) == "" {
			return pkgErr("поле %s: нет подписи (label)", f.Name)
		}
		if f.Pattern != "" {
			if f.Type != sdk.FieldString && f.Type != sdk.FieldText {
				return pkgErr("поле %s: pattern допустим только для строк", f.Name)
			}
			if _, err := regexp.Compile("^(?:" + f.Pattern + ")$"); err != nil {
				return pkgErr("поле %s: неверный pattern", f.Name)
			}
		}
		if f.Min != nil && f.Max != nil && *f.Min > *f.Max {
			return pkgErr("поле %s: min больше max", f.Name)
		}
		if f.Type == sdk.FieldEnum && len(f.Options) == 0 {
			return pkgErr("поле %s: у enum нет вариантов (options)", f.Name)
		}
		if f.Type == sdk.FieldSecret && f.Default != nil {
			return pkgErr("поле %s: у секрета не может быть значения по умолчанию", f.Name)
		}
		if f.Default != nil && f.Type != sdk.FieldSecret && f.Type != sdk.FieldTarget {
			if msg := checkValue(f, f.Default); msg != "" {
				return pkgErr("поле %s: значение по умолчанию: %s", f.Name, msg)
			}
		}
	}
	for _, p := range s.Presets {
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Label) == "" {
			return pkgErr("у пресета нет name или label")
		}
		for k, v := range p.Values {
			f, ok := names[k]
			if !ok {
				return pkgErr("пресет %s: неизвестное поле %q", p.Name, k)
			}
			if f.Type == sdk.FieldSecret || f.Type == sdk.FieldTarget {
				return pkgErr("пресет %s: поле %s нельзя задавать пресетом", p.Name, k)
			}
			if msg := checkValue(f, v); msg != "" {
				return pkgErr("пресет %s, поле %s: %s", p.Name, k, msg)
			}
		}
	}
	return nil
}

// CheckMinHestia refuses a plugin that needs a newer Hestia. Unknown (dev)
// versions of Hestia accept everything.
func CheckMinHestia(m sdk.Manifest, hestiaVersion string) error {
	if m.MinHestia == "" {
		return nil
	}
	need, ok1 := version.Parse(m.MinHestia)
	have, ok2 := version.Parse(hestiaVersion)
	if ok1 && ok2 && version.Compare(have, need) < 0 {
		return pkgErr("плагину нужна Hestia %s или новее (сейчас %s)", m.MinHestia, hestiaVersion)
	}
	return nil
}

// checkValue validates a (non-secret, non-target) field value; "" means ok.
func checkValue(f sdk.Field, v any) string {
	switch f.Type {
	case sdk.FieldString, sdk.FieldText:
		s, ok := v.(string)
		if !ok {
			return "ожидается строка"
		}
		if f.MaxLen > 0 && len([]rune(s)) > f.MaxLen {
			return fmt.Sprintf("не длиннее %d символов", f.MaxLen)
		}
		if f.Type == sdk.FieldString && strings.ContainsAny(s, "\n\r") {
			return "одна строка"
		}
		if f.Pattern != "" && s != "" {
			re, err := regexp.Compile("^(?:" + f.Pattern + ")$")
			if err != nil || !re.MatchString(s) {
				return "значение не подходит по формату"
			}
		}
	case sdk.FieldInt:
		n, ok := toInt(v)
		if !ok {
			return "ожидается целое число"
		}
		if f.Min != nil && float64(n) < *f.Min {
			return fmt.Sprintf("не меньше %v", *f.Min)
		}
		if f.Max != nil && float64(n) > *f.Max {
			return fmt.Sprintf("не больше %v", *f.Max)
		}
	case sdk.FieldBool:
		if _, ok := v.(bool); !ok {
			return "ожидается да/нет"
		}
	case sdk.FieldEnum:
		s, ok := v.(string)
		if !ok {
			return "ожидается один из вариантов"
		}
		for _, o := range f.Options {
			if o.Value == s {
				return ""
			}
		}
		return "нет такого варианта"
	}
	return ""
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
