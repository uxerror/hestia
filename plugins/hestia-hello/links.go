package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/types"
)

// hostsFile is edited on devices of "client" links.
const hostsFile = "/etc/hosts"

var reHostname = regexp.MustCompile(`^[a-z0-9.-]{1,63}$`)

// hello implements sdk.Linker: the port "web" (http.service) gives the
// address of whoami to a consumer (service links) and writes
// "<IP> <hostname> # hestia-link-<id>" into /etc/hosts of a device (client
// links).
var _ sdk.Linker = (*hello)(nil)

func marker(link int64) string { return fmt.Sprintf("# hestia-link-%d", link) }

// binding is the http.service data of the instance (its target's address).
func (h *hello) binding(ctx context.Context, host *sdk.Host, inst sdk.Instance) (types.HTTPService, error) {
	t, err := target(ctx, host, inst.ID, inst.Config.String("target"))
	if err != nil {
		return types.HTTPService{}, err
	}
	if t.Address == "" {
		return types.HTTPService{}, fmt.Errorf("у цели %s нет известного адреса", t.Name)
	}
	p := port(inst.Config)
	return types.HTTPService{URL: serviceURL(t, p), Host: t.Address, Port: int(p), Scheme: "http"}, nil
}

func hostname(cfg sdk.Config) (string, error) {
	n := cfg.String("hostname")
	if n == "" {
		n = "hello.home"
	}
	if !reHostname.MatchString(n) {
		return "", fmt.Errorf("неверное имя %q", n)
	}
	return n, nil
}

func deviceName(req sdk.LinkRequest) string {
	if req.Device == nil {
		return "устройство"
	}
	if req.Device.Name != "" {
		return req.Device.Name
	}
	return req.Device.ID
}

func (h *hello) LinkPlan(ctx context.Context, req sdk.LinkRequest) (sdk.Plan, error) {
	pl := sdk.Plan{Actions: []sdk.Action{}, Warnings: []string{}}
	host := sdk.HostFrom(ctx)
	switch req.Role {
	case sdk.RoleProvider:
		if req.Action == sdk.ActionRemove {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Отозвать адрес у «" + peerName(req) + "»", Risk: sdk.RiskInfo})
			return pl, nil
		}
		b, err := h.binding(ctx, host, req.Instance)
		if err != nil {
			return pl, err
		}
		pl.Actions = append(pl.Actions, sdk.Action{Title: "Выдать адрес " + b.URL + " для «" + peerName(req) + "»", Risk: sdk.RiskInfo})
		return pl, nil
	case sdk.RoleClient:
		name, err := hostname(req.Config)
		if err != nil {
			return pl, err
		}
		if req.Device == nil || req.Device.ID == "" {
			return pl, errors.New("нет устройства")
		}
		if req.Action == sdk.ActionRemove {
			pl.Actions = append(pl.Actions, sdk.Action{Title: "Убрать " + name + " из " + hostsFile, Detail: "на " + deviceName(req), Risk: sdk.RiskChange})
			return pl, nil
		}
		b, err := h.binding(ctx, host, req.Instance)
		if err != nil {
			return pl, err
		}
		pl.Actions = append(pl.Actions, sdk.Action{Title: fmt.Sprintf("Добавить «%s %s» в %s", b.Host, name, hostsFile),
			Detail: "на " + deviceName(req) + "; файл правится атомарно, остальные строки не меняются", Risk: sdk.RiskChange})
		pl.Data, _ = json.Marshal(map[string]string{"host": b.Host, "hostname": name})
		return pl, nil
	}
	return pl, fmt.Errorf("роль %s не поддерживается", req.Role)
}

func peerName(req sdk.LinkRequest) string {
	if req.Peer != nil && req.Peer.Name != "" {
		return req.Peer.Name
	}
	return "потребителя"
}

func (h *hello) LinkApply(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) (json.RawMessage, error) {
	host := job.Host()
	b, err := h.binding(ctx, host, req.Instance)
	if err != nil {
		return nil, err
	}
	raw, err := types.Marshal(b)
	if err != nil {
		return nil, err
	}
	if req.Role == sdk.RoleProvider {
		job.Logf("Адрес для «%s»: %s", peerName(req), b.URL)
		return raw, nil
	}
	if req.Role != sdk.RoleClient || req.Device == nil {
		return nil, fmt.Errorf("роль %s не поддерживается", req.Role)
	}
	name, err := hostname(req.Config)
	if err != nil {
		return nil, err
	}
	line := fmt.Sprintf("%s %s %s", b.Host, name, marker(req.Link))
	err = job.Run("Запись "+name+" в "+hostsFile+" на "+deviceName(req), func(ctx context.Context) error {
		return editHosts(ctx, host, req, line)
	})
	if err != nil {
		return nil, err
	}
	// The binding lets Hestia notice a new address (link.refresh).
	return raw, nil
}

func (h *hello) LinkRemove(ctx context.Context, req sdk.LinkRequest, job *sdk.Job) error {
	if req.Role != sdk.RoleClient {
		return nil // a consumer just stops using the address
	}
	if req.Device == nil {
		return errors.New("нет устройства")
	}
	return job.Run("Удаление записи из "+hostsFile+" на "+deviceName(req), func(ctx context.Context) error {
		return editHosts(ctx, job.Host(), req, "")
	})
}

// hostsScript replaces (or removes, line "") the line with the link's
// marker; the file is written through a temporary copy (mode and owner
// kept) and moved into place.
func hostsScript(link int64, line string) string {
	add := ""
	if line != "" {
		add = "printf '%s\\n' " + shellQuote(line) + ` >> "$tmp"` + "\n"
	}
	return fmt.Sprintf(`set -e
f=%s
tmp=$(mktemp "$f.hestia.XXXXXX")
trap 'rm -f "$tmp"' EXIT
cp -p "$f" "$tmp"
grep -v -E %s "$f" > "$tmp" || true
%smv -f "$tmp" "$f"
trap - EXIT
`, hostsFile, shellQuote(" "+regexp.QuoteMeta(marker(link))+"$"), add)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func editHosts(ctx context.Context, host *sdk.Host, req sdk.LinkRequest, line string) error {
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: hostsScript(req.Link, line), TimeoutS: 60})
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("%s: код %d: %s", hostsFile, res.Code, strings.TrimSpace(res.Stderr+" "+res.Stdout))
	}
	return nil
}

func (h *hello) LinkStatus(ctx context.Context, req sdk.LinkRequest) (sdk.LinkStatus, error) {
	host := sdk.HostFrom(ctx)
	b, err := h.binding(ctx, host, req.Instance)
	if err != nil {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: err.Error()}, nil
	}
	if req.Role == sdk.RoleProvider {
		code, _, err := h.get(ctx, b.URL)
		switch {
		case err != nil:
			return sdk.LinkStatus{State: sdk.StateDown, Detail: "whoami не отвечает"}, nil
		case code != http.StatusOK:
			return sdk.LinkStatus{State: sdk.StateDegraded, Detail: "ответ " + strconv.Itoa(code)}, nil
		}
		return sdk.LinkStatus{State: sdk.StateOK}, nil
	}
	if req.Device == nil {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "нет устройства"}, nil
	}
	name, err := hostname(req.Config)
	if err != nil {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: err.Error()}, nil
	}
	m := shellQuote(" " + regexp.QuoteMeta(marker(req.Link)) + "$")
	cmd := fmt.Sprintf("grep -E %s %s || echo missing; echo ---; getent hosts %s || true", m, hostsFile, shellQuote(name))
	res, err := host.Exec(ctx, sdk.ExecRequest{Instance: req.Instance.ID, Target: req.Device.ID, Cmd: cmd, TimeoutS: 30})
	if err != nil {
		return sdk.LinkStatus{State: sdk.StateUnknown, Detail: "устройство недоступно: " + err.Error()}, nil
	}
	entry, resolved, _ := strings.Cut(res.Stdout, "---")
	entry, resolved = strings.TrimSpace(entry), strings.TrimSpace(resolved)
	switch {
	case entry == "missing" || entry == "":
		return sdk.LinkStatus{State: sdk.StateDown, Detail: "записи " + name + " нет в " + hostsFile}, nil
	case !strings.HasPrefix(entry, b.Host+" "):
		return sdk.LinkStatus{State: sdk.StateDegraded, Detail: "в " + hostsFile + " старый адрес: " + entry}, nil
	case resolved == "":
		return sdk.LinkStatus{State: sdk.StateDegraded, Detail: name + " не резолвится"}, nil
	case !strings.HasPrefix(resolved, b.Host):
		return sdk.LinkStatus{State: sdk.StateDegraded, Detail: name + " резолвится в " + strings.Fields(resolved)[0]}, nil
	}
	return sdk.LinkStatus{State: sdk.StateOK, Detail: name + " → " + b.Host}, nil
}

func (h *hello) LinkRefresh(ctx context.Context, req sdk.LinkRequest) (json.RawMessage, error) {
	b, err := h.binding(ctx, sdk.HostFrom(ctx), req.Instance)
	if err != nil {
		return nil, err
	}
	return types.Marshal(b)
}
