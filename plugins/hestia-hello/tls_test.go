package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/sdktest"
	"github.com/uxerror/hestia/sdk/types"
)

func TestTLSLink(t *testing.T) {
	pl := &hello{StateDir: t.TempDir()}
	h := sdktest.New(t, manifest, pl)
	f := &fakeDeploy{exists: map[string]bool{}, targets: []sdk.TargetInfo{{ID: "ssh:1", Kind: "ssh", Name: "web", Address: "10.10.10.41"}}}
	f.install(h)
	ctx := context.Background()
	c := sdk.Config{"target": "ssh:1", "port": float64(8080), "message": "Привет", "tls_port": float64(8443), "tls_name": "hello.home"}
	inst := sdk.Instance{ID: 3, Name: "hello", Config: c}
	req := sdk.LinkRequest{Link: 12, Kind: sdk.LinkService, Role: sdk.RoleConsumer, Instance: inst, Port: portTLS, Type: types.TLSCertType, Action: sdk.ActionCreate}

	// Without a link: one service.
	if !strings.Contains(string(compose(8080, "x")), `"whoami"`) || strings.Contains(string(compose(8080, "x")), "whoami-tls") {
		t.Fatal(string(compose(8080, "x")))
	}
	plan, err := h.LinkPlan(ctx, req)
	if err != nil || string(plan.Request) != `{"dns":["hello.home"],"ips":["10.10.10.41"]}` || !strings.Contains(plan.Actions[0].Title, ":8443") {
		t.Fatalf("plan %s %+v %v", plan.Request, plan.Actions, err)
	}
	raw, err := h.LinkPrepare(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	var r types.TLSRequest
	_ = json.Unmarshal(raw, &r)
	if strings.Contains(string(raw), "PRIVATE") || r.CSRPEM == "" {
		t.Fatalf("request %s", raw)
	}
	pending := filepath.Join(pl.StateDir, pendingFile(12))
	if st, err := os.Stat(pending); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending %v %v", err, st)
	}
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	rootPEM, key, err := pki.NewRoot("t", pki.Constraints{Zones: []string{"home"}, IPRanges: []*net.IPNet{n}}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root, _ := pki.ParseCertPEM(rootPEM)
	is, err := pki.Issue(root, key, []byte(r.CSRPEM), r.DNS, r.IPs, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := types.TLSCert{CertPEM: string(is.CertPEM), CAPEM: string(rootPEM), CASHA256: pki.Fingerprint(root.Raw), DNS: r.DNS, IPs: r.IPs,
		Serial: is.Serial, NotBefore: is.NotBefore, NotAfter: is.NotAfter}
	req.Binding, _ = json.Marshal(b)
	req.JobID = "job-link"

	// A failing deploy keeps the pending key and changes nothing else.
	f.mu.Lock()
	f.upErr = errors.New("docker down")
	f.mu.Unlock()
	if _, err := h.LinkApply(ctx, req); err == nil {
		t.Fatal("apply with a failing deploy")
	}
	if _, err := os.Stat(filepath.Join(pl.StateDir, keyFile(12))); err == nil {
		t.Fatal("key moved although the deploy failed")
	}
	f.mu.Lock()
	f.upErr = nil
	f.mu.Unlock()
	if _, err := h.LinkApply(ctx, req); err != nil {
		t.Fatal(err)
	}
	up := f.ups[len(f.ups)-1]
	if up.JobID != "job-link" || !strings.Contains(string(up.Compose), "whoami-tls") || !strings.Contains(string(up.Compose), `"8443:8443"`) ||
		!strings.Contains(string(up.Compose), "./tls-key.pem:/tls/key.pem:ro") || len(up.Files) != 2 {
		t.Fatalf("deploy %s %v", up.Compose, up.Files)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(pl.StateDir, keyFile(12)))
	if string(up.Files[1].Data) != string(keyPEM) || !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("the key in the project files is not the prepared one")
	}
	if _, err := os.Stat(pending); err == nil {
		t.Fatal("pending key left")
	}
	// An update of the instance keeps the HTTPS service.
	if dr := pl.deployRequest(3, "ssh:1", c, "j"); !strings.Contains(string(dr.Compose), "whoami-tls") || len(dr.Files) != 2 {
		t.Fatalf("update without tls: %s", dr.Compose)
	}
	if dr := pl.deployRequest(4, "ssh:1", c, "j"); strings.Contains(string(dr.Compose), "whoami-tls") {
		t.Fatal("another instance got tls")
	}
	// Removal: deploy without whoami-tls, the keys go.
	rm := req
	rm.Action = sdk.ActionRemove
	if err := h.LinkRemove(ctx, rm); err != nil {
		t.Fatal(err)
	}
	if up := f.ups[len(f.ups)-1]; strings.Contains(string(up.Compose), "whoami-tls") || len(up.Files) != 0 {
		t.Fatalf("after remove %s", up.Compose)
	}
	if list, _ := filepath.Glob(filepath.Join(pl.StateDir, "tls-*")); len(list) != 0 {
		t.Fatalf("files left %v", list)
	}
}
