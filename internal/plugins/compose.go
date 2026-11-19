package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Compose is accepted as a JSON object: Docker compose reads JSON as YAML,
// and Hestia needs no YAML parser. The object is checked before anything is
// written to a target (see checkCompose) and rewritten with Hestia's labels.

// Labels Hestia puts on every service.
const (
	LabelPlugin   = "hestia.plugin"
	LabelInstance = "hestia.instance"
)

var reService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// composeErr is a rejected compose file (the message is for the plugin
// author and the user).
func composeErr(where, format string, args ...any) error {
	return badParams("compose: %s: %s", where, fmt.Sprintf(format, args...))
}

// preparedCompose is a checked compose file.
type preparedCompose struct {
	data     []byte   // compose.yaml to write (indented JSON)
	services []string // sorted
	ports    []int    // published TCP ports, sorted
}

// prepareCompose checks raw against the rules and adds the labels. dir is
// the project directory: bind mounts and file references must stay inside.
func prepareCompose(raw json.RawMessage, dir, pluginID string, instance int64) (*preparedCompose, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, badParams("compose: нужен JSON-объект compose-файла")
	}
	if len(raw) > maxCompose {
		return nil, badParams("compose: больше 256 КБ")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var top map[string]any
	if err := dec.Decode(&top); err != nil || top == nil {
		return nil, badParams("compose: нужен JSON-объект compose-файла (YAML не принимается)")
	}
	if dec.More() {
		return nil, badParams("compose: после объекта есть лишние данные")
	}
	c := &composeCheck{dir: dir}
	if err := c.top(top); err != nil {
		return nil, err
	}
	services := top["services"].(map[string]any)
	names := make([]string, 0, len(services))
	for name, v := range services {
		svc := v.(map[string]any)
		svc["labels"] = withLabels(svc["labels"], pluginID, instance)
		names = append(names, name)
	}
	sort.Strings(names)
	// The project name comes from -p; a "name" in the file would only confuse.
	delete(top, "name")
	data, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	ports := make([]int, 0, len(c.ports))
	for p := range c.ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return &preparedCompose{data: data, services: names, ports: ports}, nil
}

type composeCheck struct {
	dir   string
	ports map[int]bool
}

func (c *composeCheck) top(top map[string]any) error {
	if _, ok := top["include"]; ok {
		return composeErr("include", "запрещено (включаемые файлы Hestia не проверяет)")
	}
	svcs, ok := top["services"].(map[string]any)
	if !ok || len(svcs) == 0 {
		return composeErr("services", "нужен хотя бы один сервис")
	}
	if len(svcs) > 50 {
		return composeErr("services", "больше 50 сервисов")
	}
	c.ports = map[int]bool{}
	for name, v := range svcs {
		if !reService.MatchString(name) {
			return composeErr("services", "неверное имя сервиса %q", name)
		}
		svc, ok := v.(map[string]any)
		if !ok {
			return composeErr("services."+name, "ожидается объект")
		}
		if err := c.service("services."+name, svc); err != nil {
			return err
		}
	}
	if v, ok := top["volumes"]; ok && v != nil {
		vols, ok := v.(map[string]any)
		if !ok {
			return composeErr("volumes", "ожидается объект")
		}
		for name, d := range vols {
			if err := c.volumeDef("volumes."+name, d); err != nil {
				return err
			}
		}
	}
	for _, kind := range []string{"secrets", "configs"} {
		v, ok := top[kind]
		if !ok || v == nil {
			continue
		}
		defs, ok := v.(map[string]any)
		if !ok {
			return composeErr(kind, "ожидается объект")
		}
		for name, d := range defs {
			def, ok := d.(map[string]any)
			if !ok {
				return composeErr(kind+"."+name, "ожидается объект")
			}
			if f, ok := def["file"]; ok {
				if err := c.inside(kind+"."+name+".file", f); err != nil {
					return err
				}
			}
		}
	}
	if v, ok := top["networks"]; ok && v != nil {
		nets, ok := v.(map[string]any)
		if !ok {
			return composeErr("networks", "ожидается объект")
		}
		for name, d := range nets {
			def, _ := d.(map[string]any)
			if name == "host" || str(def["name"]) == "host" || str(def["driver"]) == "host" {
				return composeErr("networks."+name, "сеть хоста запрещена")
			}
		}
	}
	return nil
}

// forbiddenKeys may not appear in a service at all.
var forbiddenKeys = []struct{ key, why string }{
	{"cap_add", "дополнительные capabilities запрещены"},
	{"devices", "доступ к устройствам хоста запрещён"},
	{"device_cgroup_rules", "доступ к устройствам хоста запрещён"},
	{"gpus", "доступ к устройствам хоста запрещён"},
	{"security_opt", "изменение профилей безопасности запрещено"},
	{"userns_mode", "запрещено"},
	{"uts", "запрещено"},
	{"cgroup_parent", "запрещено"},
	{"volumes_from", "запрещено (тома чужих контейнеров)"},
	{"use_api_socket", "доступ к Docker API запрещён"},
	{"provider", "запрещено (запускает программы на хосте)"},
}

func (c *composeCheck) service(where string, svc map[string]any) error {
	for _, f := range forbiddenKeys {
		if v, ok := svc[f.key]; ok && !empty(v) {
			return composeErr(where+"."+f.key, "%s", f.why)
		}
	}
	if err := notTrue(where+".privileged", svc["privileged"]); err != nil {
		return err
	}
	if err := mode(where+".network_mode", svc["network_mode"], "bridge", "none", "default"); err != nil {
		return err
	}
	if err := mode(where+".pid", svc["pid"]); err != nil {
		return err
	}
	if err := mode(where+".ipc", svc["ipc"], "private", "shareable", "none"); err != nil {
		return err
	}
	if err := mode(where+".cgroup", svc["cgroup"], "private"); err != nil {
		return err
	}
	if v, ok := svc["volumes"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok {
			return composeErr(where+".volumes", "ожидается список")
		}
		for i, vol := range list {
			if err := c.serviceVolume(fmt.Sprintf("%s.volumes[%d]", where, i), vol); err != nil {
				return err
			}
		}
	}
	if v, ok := svc["env_file"]; ok && v != nil {
		var list []any
		switch x := v.(type) {
		case []any:
			list = x
		default:
			list = []any{x}
		}
		for i, e := range list {
			p := e
			if m, ok := e.(map[string]any); ok {
				p = m["path"]
			}
			if err := c.inside(fmt.Sprintf("%s.env_file[%d]", where, i), p); err != nil {
				return err
			}
		}
	}
	if v, ok := svc["build"]; ok && v != nil {
		if err := c.build(where+".build", v); err != nil {
			return err
		}
	}
	if v, ok := svc["extends"]; ok && v != nil {
		if m, ok := v.(map[string]any); ok {
			if _, ok := m["file"]; ok {
				return composeErr(where+".extends.file", "запрещено (внешние файлы Hestia не проверяет)")
			}
		}
	}
	for _, hook := range []string{"post_start", "pre_stop"} {
		list, _ := svc[hook].([]any)
		for i, h := range list {
			if m, ok := h.(map[string]any); ok {
				if err := notTrue(fmt.Sprintf("%s.%s[%d].privileged", where, hook, i), m["privileged"]); err != nil {
					return err
				}
			}
		}
	}
	if d, ok := svc["deploy"].(map[string]any); ok {
		if r, ok := d["resources"].(map[string]any); ok {
			if rv, ok := r["reservations"].(map[string]any); ok && !empty(rv["devices"]) {
				return composeErr(where+".deploy.resources.reservations.devices", "доступ к устройствам хоста запрещён")
			}
		}
	}
	if v, ok := svc["ports"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok {
			return composeErr(where+".ports", "ожидается список")
		}
		for i, p := range list {
			if err := c.port(fmt.Sprintf("%s.ports[%d]", where, i), p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *composeCheck) build(where string, v any) error {
	switch x := v.(type) {
	case string:
		return c.inside(where, x)
	case map[string]any:
		ctx := x["context"]
		if ctx == nil {
			ctx = "."
		}
		if err := c.inside(where+".context", ctx); err != nil {
			return err
		}
		if df, ok := x["dockerfile"]; ok {
			s := str(df)
			if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "$") || strings.Contains(s, "..") {
				return composeErr(where+".dockerfile", "только относительный путь внутри каталога проекта")
			}
		}
		if err := notTrue(where+".privileged", x["privileged"]); err != nil {
			return err
		}
		for _, k := range []string{"additional_contexts", "entitlements"} {
			if !empty(x[k]) {
				return composeErr(where+"."+k, "запрещено")
			}
		}
		if n, ok := x["network"]; ok && n != nil {
			if err := mode(where+".network", n, "default", "none"); err != nil {
				return err
			}
		}
		return nil
	}
	return composeErr(where, "ожидается строка или объект")
}

// serviceVolume checks a short ("src:dst:mode") or long ({type, source,
// target}) volume of a service.
func (c *composeCheck) serviceVolume(where string, v any) error {
	switch x := v.(type) {
	case string:
		if strings.Contains(x, "$") {
			return composeErr(where, "подстановка переменных в томах запрещена")
		}
		src, _, ok := strings.Cut(x, ":")
		if !ok {
			return nil // an anonymous volume
		}
		if isPathLike(src) {
			return c.bindSource(where, src)
		}
		return volumeName(where, src)
	case map[string]any:
		typ := str(x["type"])
		switch typ {
		case "bind":
			return c.bindSource(where+".source", x["source"])
		case "volume":
			if s, ok := x["source"]; ok && s != nil {
				return volumeName(where+".source", str(s))
			}
			return nil
		case "tmpfs":
			return nil
		}
		return composeErr(where+".type", "допустимы bind, volume, tmpfs")
	}
	return composeErr(where, "ожидается строка или объект")
}

func (c *composeCheck) volumeDef(where string, d any) error {
	if d == nil {
		return nil
	}
	def, ok := d.(map[string]any)
	if !ok {
		return composeErr(where, "ожидается объект")
	}
	if drv := str(def["driver"]); drv != "" && drv != "local" {
		return composeErr(where+".driver", "допустим только драйвер local")
	}
	if !empty(def["driver_opts"]) {
		return composeErr(where+".driver_opts", "запрещено (может подключить каталог хоста)")
	}
	return nil
}

func volumeName(where, s string) error {
	if s == "" || strings.ContainsAny(s, "/\\$~") {
		return composeErr(where, "неверное имя тома %q", s)
	}
	return nil
}

func isPathLike(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~")
}

// bindSource is a bind mount: inside the project, but neither the project
// directory itself nor compose.yaml or Hestia's own files (a container must
// not change what Hestia reads as root).
func (c *composeCheck) bindSource(where string, v any) error {
	if err := c.inside(where, v); err != nil {
		return err
	}
	p, _ := v.(string)
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.dir, p)
	}
	p = path.Clean(p)
	rel := strings.TrimPrefix(p, c.dir+"/")
	first, _, _ := strings.Cut(rel, "/")
	if p == c.dir || first == composeFile || strings.HasPrefix(first, ".hestia") {
		return composeErr(where, "монтировать каталог проекта целиком, compose.yaml и файлы .hestia* нельзя — используйте подкаталог, например ./data")
	}
	return nil
}

// inside checks that a path (absolute or relative to the project) stays in
// the project directory.
func (c *composeCheck) inside(where string, v any) error {
	s, ok := v.(string)
	if !ok || s == "" {
		return composeErr(where, "ожидается путь")
	}
	if strings.ContainsAny(s, "$~\x00") || strings.Contains(s, "://") {
		return composeErr(where, "путь %q: только путь внутри каталога проекта, без подстановок", s)
	}
	p := s
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.dir, p)
	}
	p = path.Clean(p)
	if p != c.dir && !strings.HasPrefix(p, c.dir+"/") {
		return composeErr(where, "путь %q вне каталога проекта %s", s, c.dir)
	}
	return nil
}

// port records the published TCP ports of a ports entry.
func (c *composeCheck) port(where string, v any) error {
	switch x := v.(type) {
	case json.Number:
		return nil // only the container port: nothing is published on a fixed port
	case string:
		if strings.Contains(x, "$") {
			return composeErr(where, "подстановка переменных в портах запрещена")
		}
		s, proto, _ := strings.Cut(x, "/")
		if proto != "" && proto != "tcp" {
			return nil
		}
		if strings.HasPrefix(s, "[") {
			i := strings.Index(s, "]:")
			if i < 0 {
				return composeErr(where, "неверный порт %q", x)
			}
			s = "0.0.0.0:" + s[i+2:]
		}
		parts := strings.Split(s, ":")
		var pub string
		switch len(parts) {
		case 1:
			return nil
		case 2:
			pub = parts[0]
		case 3:
			pub = parts[1]
		default:
			return composeErr(where, "неверный порт %q", x)
		}
		return c.addPorts(where, pub)
	case map[string]any:
		if p := str(x["protocol"]); p != "" && p != "tcp" {
			return nil
		}
		pub := x["published"]
		if pub == nil {
			return nil
		}
		s := str(pub)
		if strings.Contains(s, "$") {
			return composeErr(where, "подстановка переменных в портах запрещена")
		}
		return c.addPorts(where, s)
	}
	return composeErr(where, "ожидается строка или объект")
}

func (c *composeCheck) addPorts(where, pub string) error {
	if pub == "" {
		return nil
	}
	lo, hi, isRange := strings.Cut(pub, "-")
	a, err1 := strconv.Atoi(lo)
	b := a
	var err2 error
	if isRange {
		b, err2 = strconv.Atoi(hi)
	}
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || b < a || b-a > 1000 {
		return composeErr(where, "неверный опубликованный порт %q", pub)
	}
	for p := a; p <= b; p++ {
		c.ports[p] = true
	}
	return nil
}

// mode allows a "*_mode"-like value only from the list or "service:<name>".
func mode(where string, v any, allowed ...string) error {
	if v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return composeErr(where, "ожидается строка")
	}
	if s == "" || slices.Contains(allowed, s) {
		return nil
	}
	if name, ok := strings.CutPrefix(s, "service:"); ok && reService.MatchString(name) {
		return nil
	}
	return composeErr(where, "значение %q запрещено", s)
}

func notTrue(where string, v any) error {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		if !x {
			return nil
		}
	case string:
		if x == "false" {
			return nil
		}
	}
	return composeErr(where, "привилегированный режим запрещён")
}

func empty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	case string:
		return x == ""
	case bool:
		return !x
	}
	return false
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}

// withLabels returns the labels of a service as a map with Hestia's labels
// (any "hestia.*" label of the plugin is replaced).
func withLabels(v any, pluginID string, instance int64) map[string]any {
	out := map[string]any{}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			out[k] = val
		}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				k, val, _ := strings.Cut(s, "=")
				out[k] = val
			}
		}
	}
	for k := range out {
		if strings.HasPrefix(k, "hestia.") {
			delete(out, k)
		}
	}
	out[LabelPlugin] = pluginID
	out[LabelInstance] = strconv.FormatInt(instance, 10)
	return out
}
