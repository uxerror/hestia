package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AplTemplate is an entry of GET /nodes/{node}/aplinfo (downloadable appliance).
type AplTemplate struct {
	Template     string `json:"template"`
	Package      string `json:"package"`
	Section      string `json:"section"`
	Version      string `json:"version"`
	OS           string `json:"os"`
	Type         string `json:"type"`
	Architecture string `json:"architecture"`
}

// AplInfo lists the appliance templates the node can download.
func (c *Client) AplInfo(ctx context.Context, node string) ([]AplTemplate, error) {
	var r []AplTemplate
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/aplinfo", &r)
}

// Volume is an entry of GET /nodes/{node}/storage/{storage}/content.
type Volume struct {
	VolID   string `json:"volid"`
	Content string `json:"content"`
	Format  string `json:"format"`
	Size    int64  `json:"size"`
}

// StorageContent lists volumes of one content type ("vztmpl", "rootdir", …).
func (c *Client) StorageContent(ctx context.Context, node, storage, content string) ([]Volume, error) {
	var r []Volume
	q := url.Values{"content": {content}}
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/storage/"+url.PathEscape(storage)+"/content?"+q.Encode(), &r)
}

// NetIface is an entry of GET /nodes/{node}/network.
type NetIface struct {
	Iface   string `json:"iface"`
	Type    string `json:"type"`
	CIDR    string `json:"cidr"`
	Address string `json:"address"`
	Gateway string `json:"gateway"`
	Active  int    `json:"active"`
}

// Network lists the network devices of a node (bridges are the ones with
// type "bridge" or "OVSBridge").
func (c *Client) Network(ctx context.Context, node string) ([]NetIface, error) {
	var r []NetIface
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/network", &r)
}

// DownloadTemplate starts the download of an appliance template into a
// storage and returns the task id.
func (c *Client) DownloadTemplate(ctx context.Context, node, storage, template string) (string, error) {
	var upid string
	err := c.do(ctx, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/aplinfo",
		url.Values{"storage": {storage}, "template": {template}}, &upid)
	return upid, err
}

// DeleteVolume removes a volume ("local:vztmpl/x.tar.zst"). It returns the
// task id, or "" if the storage deleted it synchronously.
func (c *Client) DeleteVolume(ctx context.Context, node, storage, volid string) (string, error) {
	var upid string
	segs := strings.Split(volid, "/")
	for i := range segs {
		segs[i] = url.PathEscape(segs[i])
	}
	p := "/nodes/" + url.PathEscape(node) + "/storage/" + url.PathEscape(storage) + "/content/" + strings.Join(segs, "/")
	err := c.do(ctx, http.MethodDelete, p, nil, &upid)
	return upid, err
}

// CreateLXC creates a container; params are the POST /nodes/{node}/lxc fields.
func (c *Client) CreateLXC(ctx context.Context, node string, params url.Values) (string, error) {
	var upid string
	err := c.do(ctx, http.MethodPost, "/nodes/"+url.PathEscape(node)+"/lxc", params, &upid)
	return upid, err
}

func lxcPath(node string, vmid int) string {
	return "/nodes/" + url.PathEscape(node) + "/lxc/" + strconv.Itoa(vmid)
}

// StartLXC starts a container and returns the task id.
func (c *Client) StartLXC(ctx context.Context, node string, vmid int) (string, error) {
	var upid string
	err := c.do(ctx, http.MethodPost, lxcPath(node, vmid)+"/status/start", nil, &upid)
	return upid, err
}

// StopLXC stops a container immediately and returns the task id.
func (c *Client) StopLXC(ctx context.Context, node string, vmid int) (string, error) {
	var upid string
	err := c.do(ctx, http.MethodPost, lxcPath(node, vmid)+"/status/stop", nil, &upid)
	return upid, err
}

// DeleteLXC destroys a container with its disks and returns the task id.
func (c *Client) DeleteLXC(ctx context.Context, node string, vmid int) (string, error) {
	var upid string
	err := c.do(ctx, http.MethodDelete, lxcPath(node, vmid),
		url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, &upid)
	return upid, err
}

// LXCStatus returns the run state of a container ("running", "stopped").
func (c *Client) LXCStatus(ctx context.Context, node string, vmid int) (string, error) {
	var r struct {
		Status string `json:"status"`
	}
	err := c.get(ctx, lxcPath(node, vmid)+"/status/current", &r)
	return r.Status, err
}

// LXCConfig returns the configuration of a container as strings.
func (c *Client) LXCConfig(ctx context.Context, node string, vmid int) (map[string]string, error) {
	var raw map[string]any
	if err := c.get(ctx, lxcPath(node, vmid)+"/config", &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			out[k] = x
		case float64:
			out[k] = strconv.FormatFloat(x, 'f', -1, 64)
		}
	}
	return out, nil
}

// NetHWAddr returns the MAC address ("BC:24:11:…") from a container net0
// value such as "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:BC:4C:F6,ip=dhcp".
func NetHWAddr(net string) string {
	for _, kv := range strings.Split(net, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "hwaddr" {
			return strings.ToUpper(v)
		}
	}
	return ""
}

// IfaceIPv4 returns the IPv4 address (without prefix) of the named interface.
func IfaceIPv4(ifaces []Iface, name string) string {
	for _, i := range ifaces {
		if i.Name != name {
			continue
		}
		if ip, _, ok := strings.Cut(i.Inet, "/"); ok && ip != "" {
			return ip
		}
		return i.Inet
	}
	return ""
}

// Task is GET /nodes/{node}/tasks/{upid}/status.
type Task struct {
	Status     string `json:"status"` // running | stopped
	ExitStatus string `json:"exitstatus"`
	Type       string `json:"type"`
	UPID       string `json:"upid"`
}

// Running reports whether the task has not finished.
func (t Task) Running() bool { return t.Status != "stopped" }

// OK reports a finished task with exit status "OK" (warnings count as OK).
func (t Task) OK() bool {
	return t.Status == "stopped" && (t.ExitStatus == "OK" || strings.HasPrefix(t.ExitStatus, "WARNINGS"))
}

// TaskStatus returns the state of a task.
func (c *Client) TaskStatus(ctx context.Context, node, upid string) (Task, error) {
	var r Task
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(upid)+"/status", &r)
}

// TaskLine is one line of a task log.
type TaskLine struct {
	N int    `json:"n"`
	T string `json:"t"`
}

// TaskLog returns task log lines starting at line number start (1-based).
func (c *Client) TaskLog(ctx context.Context, node, upid string, start int) ([]TaskLine, error) {
	var r []TaskLine
	q := url.Values{"start": {strconv.Itoa(start)}, "limit": {"500"}}
	return r, c.get(ctx, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(upid)+"/log?"+q.Encode(), &r)
}

// TaskFailed is the error of a task that ended with a failure status.
type TaskFailed struct{ Exit, Last string }

func (e *TaskFailed) Error() string {
	if e.Last != "" {
		return fmt.Sprintf("задача Proxmox завершилась с ошибкой (%s): %s", e.Exit, e.Last)
	}
	return fmt.Sprintf("задача Proxmox завершилась с ошибкой (%s)", e.Exit)
}

// WaitTask polls a task until it finishes, passing new log lines to onLog.
// A failed task yields *TaskFailed. interval defaults to 1 s.
func (c *Client) WaitTask(ctx context.Context, node, upid string, interval time.Duration, onLog func(string)) error {
	if interval <= 0 {
		interval = time.Second
	}
	next := 0
	last := ""
	drain := func() {
		lines, err := c.TaskLog(ctx, node, upid, next)
		if err != nil {
			return
		}
		sort.Slice(lines, func(i, j int) bool { return lines[i].N < lines[j].N })
		for _, l := range lines {
			if l.N <= next {
				continue
			}
			next = l.N
			last = l.T
			if onLog != nil {
				onLog(l.T)
			}
		}
	}
	for {
		t, err := c.TaskStatus(ctx, node, upid)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) || ctx.Err() != nil {
				return err
			}
			// a transient network error: keep polling until the context ends
		} else {
			drain()
			if !t.Running() {
				if t.OK() {
					return nil
				}
				return &TaskFailed{Exit: t.ExitStatus, Last: last}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
