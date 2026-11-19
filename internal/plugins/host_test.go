package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// rawPlugin connects to the manager as a plugin of the database (without
// the SDK) so that the test controls every call.
type rawPlugin struct {
	conn *rpc.Conn
}

func installRow(t *testing.T, h *harness, id string, perms []string) string {
	t.Helper()
	tok := newToken()
	man := testManifest(newKey(t), func(m *sdk.Manifest) { m.ID = id; m.Permissions = perms })
	if err := h.st.SavePlugin(context.Background(), store.Plugin{ID: id, Version: "v0.1.0", AuthorKey: "k-" + id,
		Manifest: string(man), Source: store.PluginSourceFile, Enabled: true, TokenHash: HashToken(tok)},
		&store.PluginAuthor{Key: "k-" + id, Name: "a"}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func connectRaw(t *testing.T, h *harness, hello sdk.Hello) (*rawPlugin, error) {
	t.Helper()
	a, b := net.Pipe()
	h.m.attach(b, "")
	c := rpc.NewConn(a, func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
		return nil, rpc.Errorf(rpc.CodeMethodNotFound, "no")
	}, rpc.Options{})
	t.Cleanup(func() { _ = c.Close() })
	var w sdk.Welcome
	err := c.Call(context.Background(), sdk.MethodHello, hello, &w)
	return &rawPlugin{conn: c}, err
}

func (p *rawPlugin) call(method string, params any) (json.RawMessage, error) {
	var out json.RawMessage
	err := p.conn.Call(context.Background(), method, params, &out)
	return out, err
}

func wantDenied(t *testing.T, err error, substr string) {
	t.Helper()
	if !rpc.IsCode(err, rpc.CodePermission) || !strings.Contains(err.Error(), substr) {
		t.Fatalf("want permission denied (%s), got %v", substr, err)
	}
}

func TestHandshake(t *testing.T) {
	h := newHarness(t)
	tok := installRow(t, h, "demo", nil)

	_, err := connectRaw(t, h, sdk.Hello{Protocol: 2, ID: "demo", Version: "v0.1.0", Token: tok})
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != rpc.CodeProtocol || !strings.Contains(string(re.Data), `"max":1`) {
		t.Fatalf("protocol: %v", err)
	}
	for _, bad := range []sdk.Hello{
		{Protocol: 1, ID: "demo", Version: "v0.1.0", Token: "wrong"},
		{Protocol: 1, ID: "demo", Version: "v9.9.9", Token: tok},
		{Protocol: 1, ID: "other", Version: "v0.1.0", Token: tok},
	} {
		p, err := connectRaw(t, h, bad)
		if !rpc.IsCode(err, rpc.CodeProtocol) {
			t.Fatalf("%+v: %v", bad, err)
		}
		select { // the connection is dropped after the answer
		case <-p.conn.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("refused connection kept open")
		}
	}
	// Nothing but hello before the handshake.
	a, b := net.Pipe()
	h.m.attach(b, "")
	c := rpc.NewConn(a, nil, rpc.Options{})
	defer c.Close()
	if err := c.Call(context.Background(), sdk.MethodTargetList, sdk.InstanceRef{}, nil); !rpc.IsCode(err, rpc.CodeProtocol) {
		t.Fatalf("before hello: %v", err)
	}

	// A good hello; a reconnect replaces the first connection.
	p1, err := connectRaw(t, h, sdk.Hello{Protocol: 1, ID: "demo", Version: "v0.1.0", Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectRaw(t, h, sdk.Hello{Protocol: 1, ID: "demo", Version: "v0.1.0", Token: tok}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p1.conn.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("old connection not replaced")
	}
	// A disabled plugin cannot connect.
	_ = h.st.SetPluginEnabled(context.Background(), "demo", false)
	if _, err := connectRaw(t, h, sdk.Hello{Protocol: 1, ID: "demo", Version: "v0.1.0", Token: tok}); !rpc.IsCode(err, rpc.CodeProtocol) {
		t.Fatalf("disabled: %v", err)
	}
}

func TestHelloTimeout(t *testing.T) {
	h := newHarness(t)
	h.m.HelloTimeout = 100 * time.Millisecond
	a, b := net.Pipe()
	s := h.m.attach(b, "")
	defer a.Close()
	select {
	case <-s.conn.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("silent connection kept open")
	}
}

// grantSetup: plugins "demo" (with perms) and "other", instances of both,
// grants ssh:1 to demo's instance.
func grantSetup(t *testing.T, perms []string) (*harness, *rawPlugin, int64, int64) {
	h := newHarness(t)
	ctx := context.Background()
	tok := installRow(t, h, "demo", perms)
	installRow(t, h, "other", perms)
	mine := &store.PluginInstance{PluginID: "demo", Name: "mine", Config: `{"target":"ssh:1"}`}
	if err := h.st.CreateInstance(ctx, mine, []store.PluginGrant{{Kind: "ssh", Ref: "ssh:1"}}); err != nil {
		t.Fatal(err)
	}
	foreign := &store.PluginInstance{PluginID: "other", Name: "theirs", Config: `{}`}
	if err := h.st.CreateInstance(ctx, foreign, []store.PluginGrant{{Kind: "ssh", Ref: "ssh:2"}}); err != nil {
		t.Fatal(err)
	}
	p, err := connectRaw(t, h, sdk.Hello{Protocol: 1, ID: "demo", Version: "v0.1.0", Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	return h, p, mine.ID, foreign.ID
}

func TestTargetPermissions(t *testing.T) {
	all := []string{sdk.PermTargetsRead, sdk.PermTargetsExec}

	// No permissions at all.
	h, p, mine, _ := grantSetup(t, []string{})
	_, err := p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: mine, Target: "ssh:1", Cmd: "echo hi"})
	wantDenied(t, err, "targets.exec")
	_, err = p.call(sdk.MethodTargetPut, sdk.PutFileRequest{Instance: mine, Target: "ssh:1", Path: "/tmp/x", DataB64: ""})
	wantDenied(t, err, "targets.exec")
	_, err = p.call(sdk.MethodTargetList, sdk.InstanceRef{Instance: mine})
	wantDenied(t, err, "targets.read")
	_, err = p.call(sdk.MethodInventoryGet, struct{}{})
	wantDenied(t, err, "inventory.read")
	if len(h.exec.callList()) != 0 {
		t.Fatal("a refused call reached the target")
	}

	h, p, mine, foreign := grantSetup(t, all)
	// Not granted to the instance, although the plugin has the permission.
	_, err = p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: mine, Target: "ssh:2", Cmd: "echo hi"})
	wantDenied(t, err, "не выдана")
	_, err = p.call(sdk.MethodTargetPut, sdk.PutFileRequest{Instance: mine, Target: "lxc:1:pve1:100", Path: "/tmp/x"})
	wantDenied(t, err, "не выдана")
	// An instance of another plugin (with its own grant).
	_, err = p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: foreign, Target: "ssh:2", Cmd: "echo hi"})
	wantDenied(t, err, "другому плагину")
	_, err = p.call(sdk.MethodTargetList, sdk.InstanceRef{Instance: foreign})
	wantDenied(t, err, "другому плагину")
	// A missing instance.
	_, err = p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: 999, Target: "ssh:1", Cmd: "echo hi"})
	wantDenied(t, err, "не найден")
	if len(h.exec.callList()) != 0 {
		t.Fatal("a refused call reached the target")
	}

	// Granted: the call goes through.
	out, err := p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: mine, Target: "ssh:1", Cmd: "echo hi"})
	if err != nil || !strings.Contains(string(out), `"stdout":"hi\n"`) {
		t.Fatalf("%s %v", out, err)
	}
	// A failing command is a result, not an error.
	out, err = p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: mine, Target: "ssh:1", Cmd: "nope"})
	if err != nil || !strings.Contains(string(out), `"code":127`) {
		t.Fatalf("%s %v", out, err)
	}
	_, err = p.call(sdk.MethodTargetPut, sdk.PutFileRequest{Instance: mine, Target: "ssh:1", Path: "/tmp/f",
		DataB64: base64.StdEncoding.EncodeToString([]byte("data")), Mode: "0600"})
	if err != nil || h.exec.files["ssh:1:/tmp/f"] != "data" {
		t.Fatalf("%v %v", err, h.exec.files)
	}
	for _, bad := range []sdk.PutFileRequest{
		{Instance: mine, Target: "ssh:1", Path: "relative"},
		{Instance: mine, Target: "ssh:1", Path: "/tmp/../etc/x"},
		{Instance: mine, Target: "ssh:1", Path: "/tmp/x", Mode: "rwx"},
		{Instance: mine, Target: "ssh:1", Path: "/tmp/x", DataB64: "%%"},
	} {
		if _, err := p.call(sdk.MethodTargetPut, bad); !rpc.IsCode(err, rpc.CodeInvalidParams) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	if _, err := p.call(sdk.MethodTargetExec, sdk.ExecRequest{Instance: mine, Target: "ssh:1", Cmd: "  "}); !rpc.IsCode(err, rpc.CodeInvalidParams) {
		t.Fatal(err)
	}
	// target.list of the own instance (the target is not in the store: empty).
	out, err = p.call(sdk.MethodTargetList, sdk.InstanceRef{Instance: mine})
	if err != nil || string(out) != "[]" {
		t.Fatalf("%s %v", out, err)
	}
	// deploy.* needs deploy.docker (see deploy_test.go for every branch).
	if _, err := p.call(sdk.MethodDeployPlan, sdk.DeployRequest{Instance: mine, Target: "ssh:1", Project: "web"}); !rpc.IsCode(err, rpc.CodePermission) {
		t.Fatal(err)
	}
}

func TestSecretsAreScoped(t *testing.T) {
	h, p, mine, foreign := grantSetup(t, nil)
	ctx := context.Background()
	if _, err := p.call(sdk.MethodSecretPut, sdk.SecretRequest{Instance: mine, Name: "db.pass", Value: "s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	out, err := p.call(sdk.MethodSecretGet, sdk.SecretRequest{Instance: mine, Name: "db.pass"})
	if err != nil || string(out) != `{"value":"s3cr3t","exists":true}` {
		t.Fatalf("%s %v", out, err)
	}
	// Stored encrypted, bound to the namespace.
	row, err := h.st.GetSecretByPurpose(ctx, "plugin:demo:"+itoa(mine)+":db.pass")
	if err != nil || strings.Contains(string(row.Ciphertext), "s3cr3t") {
		t.Fatalf("%v", err)
	}
	// Foreign instance (another plugin): denied for every operation.
	for _, m := range []string{sdk.MethodSecretGet, sdk.MethodSecretPut, sdk.MethodSecretDelete} {
		_, err := p.call(m, sdk.SecretRequest{Instance: foreign, Name: "db.pass", Value: "x"})
		wantDenied(t, err, "другому плагину")
	}
	if _, err := p.call(sdk.MethodSecretGet, sdk.SecretRequest{Instance: mine, Name: "../x"}); !rpc.IsCode(err, rpc.CodeInvalidParams) {
		t.Fatal(err)
	}
	if _, err := p.call(sdk.MethodSecretDelete, sdk.SecretRequest{Instance: mine, Name: "db.pass"}); err != nil {
		t.Fatal(err)
	}
	out, _ = p.call(sdk.MethodSecretGet, sdk.SecretRequest{Instance: mine, Name: "db.pass"})
	if string(out) != `{"value":"","exists":false}` {
		t.Fatal(string(out))
	}
}

func TestJobCallsNeedOwnJob(t *testing.T) {
	_, p, _, _ := grantSetup(t, nil)
	for _, m := range []string{sdk.MethodJobStep, sdk.MethodJobStepDone, sdk.MethodJobLog} {
		if _, err := p.call(m, map[string]string{"job_id": "nope", "title": "x"}); !rpc.IsCode(err, rpc.CodeInvalidParams) {
			t.Fatalf("%s: %v", m, err)
		}
	}
	if _, err := p.call(sdk.MethodLog, sdk.LogLine{Level: "warn", Line: "hello"}); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
