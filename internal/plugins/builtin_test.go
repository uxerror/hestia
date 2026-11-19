package plugins

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/tlsself"
	"github.com/uxerror/hestia/sdk"
)

func TestBuiltinHestiaHTTPS(t *testing.T) {
	e := newTLSEnv(t)
	ctx := context.Background()
	svc := &tlsself.Service{DataDir: t.TempDir(), Store: e.st, Addr: "127.0.0.1:0", InstanceID: "inst-test", Now: e.clock.now,
		Names: func(context.Context) ([]string, []string) { return []string{"hestia.home"}, []string{"10.10.10.30"} }}
	if err := svc.Init(ctx); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"instance_id": "inst-test"})
	})
	svc.SetHandler(svc.Middleware(mux))
	t.Cleanup(svc.Close)
	inst, err := e.m.StartBuiltin(ctx, tlsself.Manifest("v0.2.0"), svc.Plugin())
	if err != nil {
		t.Fatal(err)
	}
	e.waitConnected(BuiltinID)
	// Idempotent at the next start: the same instance.
	if again, err := e.m.BuiltinInstance(ctx); err != nil || again.ID != inst.ID || again.Name != BuiltinInstanceName {
		t.Fatalf("instance %+v %v", again, err)
	}

	// Hidden and untouchable.
	l, _ := e.m.List(ctx)
	for _, p := range l.Plugins {
		if p.ID == BuiltinID {
			t.Fatal("builtin listed among plugins")
		}
	}
	if _, err := e.m.SetEnabled(ctx, BuiltinID, false); err == nil {
		t.Fatal("builtin disabled")
	}
	if _, err := e.m.Remove(ctx, BuiltinID); err == nil {
		t.Fatal("builtin removed")
	}
	if _, err := e.m.ChangePlan(ctx, inst.ID, sdk.ActionRemove, nil); err == nil {
		t.Fatal("builtin instance removable")
	}
	if _, err := e.m.CreatePlan(ctx, BuiltinID, "x", nil); err == nil {
		t.Fatal("builtin instance created")
	}
	g, err := e.m.Graph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, gi := range g.Instances {
		if gi.ID == inst.ID {
			found = gi.Builtin && gi.Controller && len(gi.Requires) == 1 && gi.Requires[0].Optional
		}
	}
	if !found {
		t.Fatalf("graph %+v", g.Instances)
	}

	// Enable HTTPS: the same link plan as any link.
	pv, err := e.m.LinkPlan(ctx, LinkPlanRequest{Kind: sdk.LinkService, Provider: LinkEnd{Instance: e.provInst, Port: "tls"},
		Consumer: &LinkEnd{Instance: inst.ID, Port: tlsself.PortTLS}})
	if err != nil {
		t.Fatal(err)
	}
	if j := applyPlan(t, e.harness, pv, true); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if !svc.Active() || svc.Port() == 0 {
		t.Fatalf("HTTPS not on: %+v", svc.Info())
	}
	serial := func() string {
		c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", svc.Port()), &tls.Config{RootCAs: poolOfCA(e.prov.ca), ServerName: "hestia.home"})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
	}
	first := serial()
	link, err := e.m.BuiltinLink(ctx, tlsself.PortTLS)
	if err != nil || link.ExpiresAt == nil {
		t.Fatalf("link %+v %v", link, err)
	}
	// "Продлить сейчас": the served certificate changes without a restart.
	job, err := e.m.RenewLink(ctx, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	if j := e.wait(job.ID); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if s := serial(); s == first {
		t.Fatal("not renewed")
	}
	// Disable: the link removal closes the port.
	port := svc.Port()
	rp, err := e.m.LinkChangePlan(ctx, link.ID, sdk.ActionRemove)
	if err != nil {
		t.Fatal(err)
	}
	if j := applyPlan(t, e.harness, rp, true); j.Status != store.JobDone {
		t.Fatal(jobLog(j))
	}
	if svc.Active() {
		t.Fatal("HTTPS still on")
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		c.Close()
		t.Fatal("port still open")
	}
}

func poolOfCA(ca *testCA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}
