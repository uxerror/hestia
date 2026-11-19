package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/caserver"
	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// Ports.
const (
	portTLS   = "tls"
	portTrust = "trust"
)

var _ sdk.Linker = (*caPlugin)(nil)

// constraints are the constraints names are checked against in a plan:
// those of the root when the CA answers, else those of the form (a CA
// being created in the same plan).
func (p *caPlugin) constraints(ctx context.Context, host *sdk.Host, inst sdk.Instance) (pki.Constraints, string, error) {
	if cl, err := p.client(ctx, host, inst); err == nil {
		var root caserver.RootInfo
		if err := cl.Do("GET", "/v1/root", nil, &root); err == nil {
			c, err := pki.ParseCertPEM([]byte(root.RootPEM))
			if err != nil {
				return pki.Constraints{}, "", err
			}
			return pki.ConstraintsOf(c), root.RootSHA256, nil
		}
	}
	if initMode(inst.Config) == "restore" {
		return pki.Constraints{}, "", errors.New("CA ожидает восстановления из резервной копии: сначала восстановите ключ")
	}
	zones, _, err := pki.ParseZones(zonesOf(inst.Config))
	if err != nil {
		return pki.Constraints{}, "", err
	}
	ranges, err := pki.ParseIPRanges(rangesOf(inst.Config))
	if err != nil {
		return pki.Constraints{}, "", err
	}
	return pki.Constraints{Zones: zones, IPRanges: ranges}, "", nil
}

func namesText(r types.TLSRequest) string { return strings.Join(r.Names(), ", ") }

func (p *caPlugin) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	host := sdk.HostFrom(ctx)
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	switch req.Port {
	case portTLS:
		if req.Action == sdk.ActionRemove {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Отозвать сертификаты связи (запись в журнале CA)",
				Detail: "Распространения отзыва (CRL/OCSP) нет: выданный сертификат действует до своего срока", Risk: sdk.RiskChange})
			return pl, nil
		}
		var r types.TLSRequest
		if err := json.Unmarshal(req.Request, &r); err != nil || len(r.Names()) == 0 {
			return pl, errors.New("нет предпросмотра запроса (имён) от потребителя")
		}
		c, _, err := p.constraints(ctx, host, req.Instance)
		if err != nil {
			return pl, err
		}
		if errs := pki.CheckNames(c, r.DNS, r.IPs); len(errs) > 0 {
			return pl, pki.NamesError(errs)
		}
		life := leafLifetime(req.Instance.Config)
		pl.Actions = append(pl.Actions, sdk.Action{
			Title:  fmt.Sprintf("Выпустить сертификат на %s сроком %s", namesText(r), lifeText(life)),
			Detail: "По CSR потребителя: его закрытый ключ к CA не попадает. Продление — автоматически на 2/3 срока.",
			Risk:   sdk.RiskChange,
		})
		return pl, nil
	case portTrust:
		if req.Device == nil {
			if req.Action == sdk.ActionRemove {
				return pl, nil
			}
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Передать корневой сертификат CA", Risk: sdk.RiskInfo})
			return pl, nil
		}
		return p.trustPlan(ctx, host, req)
	}
	return pl, fmt.Errorf("неизвестный порт %s", req.Port)
}

func lifeText(d time.Duration) string {
	if d < 24*time.Hour {
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	}
	return fmt.Sprintf("%d дней", int(d.Hours()/24))
}

func (p *caPlugin) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	host := job.Host()
	switch req.Port {
	case portTLS:
		return p.issue(ctx, host, req)
	case portTrust:
		if req.Device != nil {
			return nil, p.trustInstall(ctx, host, req, job)
		}
		return p.issuerBinding(ctx, host, req.Instance)
	}
	return nil, fmt.Errorf("неизвестный порт %s", req.Port)
}

func (p *caPlugin) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	host := sdk.HostFrom(ctx)
	switch req.Port {
	case portTLS:
		if len(req.Request) == 0 {
			return nil, errors.New("для нового сертификата нужен запрос (request) потребителя")
		}
		return p.issue(ctx, host, req)
	case portTrust:
		if req.Device != nil {
			return nil, nil
		}
		return p.issuerBinding(ctx, host, req.Instance)
	}
	return nil, fmt.Errorf("неизвестный порт %s", req.Port)
}

func ref(link int64) string { return fmt.Sprintf("link:%d", link) }

// issue asks the CA for a certificate by the consumer's CSR.
func (p *caPlugin) issue(ctx context.Context, host *sdk.Host, req sdk.LinkRequest) (json.RawMessage, error) {
	var r types.TLSRequest
	if err := json.Unmarshal(req.Request, &r); err != nil || r.CSRPEM == "" {
		return nil, errors.New("нет запроса сертификата (CSR) от потребителя")
	}
	cl, err := p.client(ctx, host, req.Instance)
	if err != nil {
		return nil, err
	}
	var out caserver.IssueResult
	err = cl.Do("POST", "/v1/issue", caserver.IssueRequest{CSRPEM: r.CSRPEM, DNS: r.DNS, IPs: r.IPs,
		LifetimeS: int64(leafLifetime(req.Instance.Config) / time.Second), Ref: ref(req.Link)}, &out)
	if err != nil {
		return nil, fmt.Errorf("выпуск: %w", err)
	}
	root, err := pki.ParseCertPEM([]byte(out.RootPEM))
	if err != nil {
		return nil, err
	}
	b := types.TLSCert{CertPEM: out.CertPEM, CAPEM: out.RootPEM, CASHA256: pki.Fingerprint(root.Raw), DNS: nonNil(r.DNS), IPs: nonNil(r.IPs),
		Serial: out.Serial, NotBefore: out.NotBefore, NotAfter: out.NotAfter}
	return json.Marshal(b)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// issuerBinding is the ca.issuer binding of a service link.
func (p *caPlugin) issuerBinding(ctx context.Context, host *sdk.Host, inst sdk.Instance) (json.RawMessage, error) {
	cl, err := p.client(ctx, host, inst)
	if err != nil {
		return nil, err
	}
	var root caserver.RootInfo
	if err := cl.Do("GET", "/v1/root", nil, &root); err != nil {
		return nil, err
	}
	return json.Marshal(types.CAIssuer{CAPEM: root.RootPEM, SHA256: root.RootSHA256, Issue: types.TLSCertType})
}

func (p *caPlugin) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	host := job.Host()
	switch req.Port {
	case portTLS:
		cl, err := p.client(ctx, host, req.Instance)
		if err != nil {
			return err
		}
		var list []caserver.Record
		if err := cl.Do("GET", "/v1/issued?active=1&ref="+url.QueryEscape(ref(req.Link)), nil, &list); err != nil {
			return err
		}
		for _, rec := range list {
			if err := cl.Do("POST", "/v1/revoke", map[string]string{"serial": rec.Serial, "reason": "связь удалена"}, nil); err != nil {
				return err
			}
			job.Logf("Отозван сертификат %s", rec.Serial)
		}
		return nil
	case portTrust:
		if req.Device != nil {
			return p.trustRemove(ctx, host, req, job)
		}
		return nil
	}
	return fmt.Errorf("неизвестный порт %s", req.Port)
}

func (p *caPlugin) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	host := sdk.HostFrom(ctx)
	switch req.Port {
	case portTLS:
		cl, err := p.client(ctx, host, req.Instance)
		if err != nil {
			return sdk.LinkStatus{State: sdk.StateUnknown, Detail: err.Error()}, nil
		}
		var list []caserver.Record
		if err := cl.Do("GET", "/v1/issued?active=1&ref="+url.QueryEscape(ref(req.Link)), nil, &list); err != nil {
			return sdk.LinkStatus{State: sdk.StateDown, Detail: "CA не отвечает: " + err.Error()}, nil
		}
		if len(list) == 0 {
			return sdk.LinkStatus{State: sdk.StateDown, Detail: "У связи нет действующего сертификата"}, nil
		}
		last := list[len(list)-1]
		return sdk.LinkStatus{State: sdk.StateOK, Detail: "Сертификат до " + last.NotAfter.Format("2006-01-02 15:04")}, nil
	case portTrust:
		if req.Device != nil {
			return p.trustStatus(ctx, host, req)
		}
		return sdk.LinkStatus{State: sdk.StateOK}, nil
	}
	return sdk.LinkStatus{State: sdk.StateUnknown}, nil
}

// ---- trust on devices ----

// Families of operating systems for the root store.
const (
	famDebian = "debian"
	famArch   = "arch"
	famAlpine = "alpine"
)

// osInfo reads /etc/os-release of the device: family and a name.
type osInfo struct {
	Family, ID, Name string
	HasUpdate        bool // update-ca-certificates is there (debian/alpine)
}

func parseOSRelease(s string) osInfo {
	var in osInfo
	like := ""
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			in.ID = strings.ToLower(v)
		case "ID_LIKE":
			like = strings.ToLower(v)
		case "PRETTY_NAME":
			in.Name = v
		case "HESTIA_HAS_UPDATE":
			in.HasUpdate = v == "1"
		}
	}
	words := append([]string{in.ID}, strings.Fields(like)...)
	for _, w := range words {
		switch w {
		case "debian", "ubuntu":
			in.Family = famDebian
		case "arch", "garuda", "manjaro", "endeavouros":
			in.Family = famArch
		case "alpine":
			in.Family = famAlpine
		}
		if in.Family != "" {
			break
		}
	}
	if in.Name == "" {
		in.Name = in.ID
	}
	return in
}

const osProbe = `cat /etc/os-release 2>/dev/null; command -v update-ca-certificates >/dev/null 2>&1 && echo HESTIA_HAS_UPDATE=1; true`

func (p *caPlugin) deviceOS(ctx context.Context, host *sdk.Host, req sdk.LinkRequest) (osInfo, error) {
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: osProbe, TimeoutS: execTimeout})
	if err != nil {
		return osInfo{}, err
	}
	in := parseOSRelease(res.Stdout)
	switch in.Family {
	case "":
		return in, fmt.Errorf("Не поддерживается: %s", in.ID)
	case famAlpine:
		if !in.HasUpdate {
			return in, errors.New("на устройстве нет пакета ca-certificates: выполните apk add ca-certificates и составьте план заново")
		}
	}
	return in, nil
}

// trustRecord is what the plugin remembers about a root installed on a
// device (removal works without a living CA).
type trustRecord struct {
	Family string `json:"family"`
	SHA256 string `json:"sha256"`
	PEM    string `json:"pem"`
}

func (p *caPlugin) trustFile(link int64) string {
	return filepath.Join(p.StateDir, fmt.Sprintf("trust-%d.json", link))
}

func debianPath(fp string) string {
	return "/usr/local/share/ca-certificates/hestia-root-" + fp[:16] + ".crt"
}

func (p *caPlugin) rootOf(ctx context.Context, host *sdk.Host, inst sdk.Instance) (caserver.RootInfo, error) {
	cl, err := p.client(ctx, host, inst)
	if err != nil {
		return caserver.RootInfo{}, err
	}
	var root caserver.RootInfo
	err = cl.Do("GET", "/v1/root", nil, &root)
	return root, err
}

func (p *caPlugin) trustPlan(ctx context.Context, host *sdk.Host, req sdk.LinkRequest) (sdk.Plan, error) {
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	name := req.Device.Name
	if req.Action == sdk.ActionRemove {
		rec, err := p.readTrust(req.Link)
		fp := "?"
		if err == nil {
			fp = pki.FingerprintColon(rec.SHA256)
		}
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Убрать корень Hestia (SHA-256 %s) из хранилища доверия %s", fp, name), Risk: sdk.RiskChange})
		return pl, nil
	}
	in, err := p.deviceOS(ctx, host, req)
	if err != nil {
		return pl, err
	}
	root, err := p.rootOf(ctx, host, req.Instance)
	if err != nil {
		return pl, fmt.Errorf("корень CA: %w", err)
	}
	pl.Actions = append(pl.Actions, sdk.Action{
		Title:  fmt.Sprintf("Установить корень Hestia (SHA-256 %s) в хранилище доверия %s (%s)", pki.FingerprintColon(root.RootSHA256), name, in.Name),
		Detail: installDetail(in.Family, root.RootSHA256),
		Risk:   sdk.RiskChange,
	})
	pl.Warnings = append(pl.Warnings, "Firefox и Chromium могут использовать своё хранилище; Docker-контейнеры на устройстве — свой образ.")
	pl.Data, _ = json.Marshal(trustRecord{Family: in.Family, SHA256: root.RootSHA256})
	return pl, nil
}

func installDetail(fam, fp string) string {
	if fam == famArch {
		return "trust anchor --store (p11-kit)"
	}
	return debianPath(fp) + " (0644) и update-ca-certificates"
}

func (p *caPlugin) trustInstall(ctx context.Context, host *sdk.Host, req sdk.LinkRequest, job *sdk.Job) error {
	var planned trustRecord
	if req.Plan != nil {
		_ = json.Unmarshal(req.Plan.Data, &planned)
	}
	root, err := p.rootOf(ctx, host, req.Instance)
	if err != nil {
		return fmt.Errorf("корень CA: %w", err)
	}
	if planned.SHA256 != "" && planned.SHA256 != root.RootSHA256 {
		return errors.New("корень CA изменился после плана — составьте план заново")
	}
	in, err := p.deviceOS(ctx, host, req)
	if err != nil {
		return err
	}
	if err := checkRootPEM(root.RootPEM); err != nil {
		return err
	}
	var cmd string
	switch in.Family {
	case famArch:
		cmd = `set -e; t=$(mktemp --suffix .crt); trap 'rm -f "$t"' EXIT; cat > "$t"; trust anchor --store "$t"`
	default:
		cmd = fmt.Sprintf(`set -e; f=%s; t="$f.hestia-new"; mkdir -p /usr/local/share/ca-certificates; rm -f "$t"; (umask 022; cat > "$t")
if [ -f "$f" ] && cmp -s "$t" "$f"; then rm -f "$t"; echo already; exit 0; fi
chmod 0644 "$t"; mv -f "$t" "$f"; update-ca-certificates >/dev/null`, debianPath(root.RootSHA256))
	}
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: cmd, Stdin: root.RootPEM, TimeoutS: 120})
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("установка корня: код %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	if strings.Contains(res.Stdout, "already") {
		job.Log("info", "Корень уже установлен")
	} else {
		job.Logf("Корень установлен (%s)", in.Name)
	}
	return p.writeTrust(req.Link, trustRecord{Family: in.Family, SHA256: root.RootSHA256, PEM: root.RootPEM})
}

// checkRootPEM: exactly one CA certificate, nothing else (it goes into a
// shell command and a system store).
func checkRootPEM(s string) error {
	c, err := pki.ParseCertPEM([]byte(s))
	if err != nil {
		return err
	}
	if !c.IsCA {
		return errors.New("корень CA — не сертификат CA")
	}
	b, rest := pem.Decode([]byte(s))
	if b == nil || strings.TrimSpace(string(rest)) != "" || strings.ContainsAny(s, "'\"$`\\") {
		return errors.New("корень CA в неожиданном формате")
	}
	return nil
}

func (p *caPlugin) writeTrust(link int64, rec trustRecord) error {
	if p.StateDir == "" {
		return nil
	}
	b, _ := json.Marshal(rec)
	return pki.WriteFileAtomic(p.trustFile(link), b, 0o600)
}

func (p *caPlugin) readTrust(link int64) (trustRecord, error) {
	var rec trustRecord
	b, err := os.ReadFile(p.trustFile(link))
	if err != nil {
		return rec, err
	}
	err = json.Unmarshal(b, &rec)
	return rec, err
}

func (p *caPlugin) trustRemove(ctx context.Context, host *sdk.Host, req sdk.LinkRequest, job *sdk.Job) error {
	rec, err := p.readTrust(req.Link)
	if errors.Is(err, os.ErrNotExist) {
		job.Log("warn", "Плагин не помнит, какой корень ставился на устройство — снимать нечего")
		return nil
	}
	if err != nil {
		return err
	}
	if !reHex64.MatchString(rec.SHA256) || checkRootPEM(rec.PEM) != nil {
		return errors.New("запись о корне на устройстве повреждена")
	}
	var cmd string
	if rec.Family == famArch {
		cmd = `set -e; t=$(mktemp --suffix .crt); trap 'rm -f "$t"' EXIT; cat > "$t"; trust anchor --remove "$t" || true`
	} else {
		cmd = fmt.Sprintf("set -e; rm -f %s; update-ca-certificates --fresh >/dev/null", debianPath(rec.SHA256))
	}
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: cmd, Stdin: rec.PEM, TimeoutS: 120})
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("удаление корня: код %d: %s", res.Code, strings.TrimSpace(res.Stderr))
	}
	job.Log("info", "Корень убран из хранилища доверия")
	_ = os.Remove(p.trustFile(req.Link))
	return nil
}

// bodyLine is a line of the base64 body of a PEM (system bundles keep the
// lines of the certificate as they are).
func bodyLine(pemText string) string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(pemText), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "-----") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)/2]
}

func (p *caPlugin) trustStatus(ctx context.Context, host *sdk.Host, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	rec, err := p.readTrust(req.Link)
	if err != nil {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "Плагин не помнит установленный корень"}, nil
	}
	line := bodyLine(rec.PEM)
	if line == "" || strings.ContainsAny(line, "'\"$`\\ ") {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "запись о корне повреждена"}, nil
	}
	cmd := fmt.Sprintf(`for f in /etc/ssl/certs/ca-certificates.crt /etc/ca-certificates/extracted/tls-ca-bundle.pem; do if [ -f "$f" ] && grep -qxF '%s' "$f"; then echo found; exit 0; fi; done; echo missing`, line)
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: cmd, TimeoutS: execTimeout})
	if err != nil {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: err.Error()}, nil
	}
	if strings.Contains(res.Stdout, "found") {
		return sdk.LinkStatus{State: sdk.StateOK, Detail: "Установлен в хранилище доверия"}, nil
	}
	return sdk.LinkStatus{State: sdk.StateDown, Detail: "Корень не найден в хранилище"}, nil
}
