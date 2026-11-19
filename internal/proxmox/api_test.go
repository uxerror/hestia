package proxmox_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/proxmox"
)

func tlsServer(t *testing.T, wantAuth string) (host string, port int, fp string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api2/json/version":
			_, _ = w.Write([]byte(`{"data":{"version":"8.2.4","release":"8.2"}}`))
		case "/api2/json/nodes":
			_, _ = w.Write([]byte(`{"data":[{"node":"pve1","status":"online"},{"node":"pve2","status":"offline"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ = strconv.Atoi(p)
	fp, err := proxmox.FetchCertFP(context.Background(), h, port)
	if err != nil {
		t.Fatal(err)
	}
	return h, port, fp
}

func TestClientSendsTokenHeaderAndPinsCert(t *testing.T) {
	host, port, fp := tlsServer(t, "PVEAPIToken=hestia@pve!hestia=sekret")
	if strings.Count(fp, ":") != 31 {
		t.Fatalf("fp format %q", fp)
	}
	c := proxmox.NewClient(proxmox.ClientConfig{Host: host, Port: port, TokenID: proxmox.TokenID, Secret: "sekret", PinFP: fp})
	v, err := c.Version(context.Background())
	if err != nil || v != "8.2.4" {
		t.Fatalf("%q %v", v, err)
	}
	nodes, err := c.Nodes(context.Background())
	if err != nil || len(nodes) != 2 || nodes[0].Node != "pve1" {
		t.Fatalf("%+v %v", nodes, err)
	}
}

func TestClientRejectsChangedCertAndBadToken(t *testing.T) {
	host, port, fp := tlsServer(t, "PVEAPIToken=hestia@pve!hestia=sekret")
	bad := proxmox.NewClient(proxmox.ClientConfig{Host: host, Port: port, TokenID: proxmox.TokenID, Secret: "sekret", PinFP: "AA:BB"})
	if _, err := bad.Version(context.Background()); !errors.Is(err, proxmox.ErrCertChanged) {
		t.Fatalf("got %v", err)
	}
	wrong := proxmox.NewClient(proxmox.ClientConfig{Host: host, Port: port, TokenID: proxmox.TokenID, Secret: "other", PinFP: fp})
	if _, err := wrong.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "отклонил токен") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err2(wrong), "other") {
		t.Fatal("secret leaked in error")
	}
}

func err2(c *proxmox.Client) string {
	_, err := c.Nodes(context.Background())
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestFetchCertFPClosedPort(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if _, err := proxmox.FetchCertFP(context.Background(), "127.0.0.1", port); err == nil || !strings.Contains(err.Error(), "недоступен") {
		t.Fatalf("got %v", err)
	}
}

func TestParseMembers(t *testing.T) {
	cl, local, nodes, err := proxmox.ParseMembers([]byte(`{"nodename":"pve2","version":3,"cluster":{"name":"lab","version":2,"nodes":2,"quorate":1},
"nodelist":{"pve2":{"id":2,"online":1,"ip":"198.51.100.2"},"pve1":{"id":1,"online":0,"ip":"198.51.100.1"}}}`))
	if err != nil || cl != "lab" || local != "pve2" || len(nodes) != 2 || nodes[0].Name != "pve1" || nodes[0].Online || !nodes[1].Online {
		t.Fatalf("%q %q %+v %v", cl, local, nodes, err)
	}
	cl, _, nodes, _ = proxmox.ParseMembers([]byte(`{"nodename":"solo","version":1}`))
	if cl != "" || len(nodes) != 0 {
		t.Fatal(cl, nodes)
	}
}

func TestAPIErrorCarriesStatusAndServerMessage(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/status":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"data":null,"message":"Permission check failed (/, Sys.Audit)\n"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null,"message":"QEMU guest agent is not running\n"}`))
		}
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	defer srv.Close()
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	fp, _ := proxmox.FetchCertFP(context.Background(), h, port)
	c := proxmox.NewClient(proxmox.ClientConfig{Host: h, Port: port, TokenID: proxmox.TokenID, Secret: "s3cr3t", PinFP: fp})

	_, err := c.AgentInterfaces(context.Background(), "pve", 101)
	var ae *proxmox.APIError
	if !errors.As(err, &ae) || ae.Status != 500 || ae.Detail != "QEMU guest agent is not running" {
		t.Fatalf("%#v", err)
	}
	_, err = c.ClusterStatus(context.Background())
	if !errors.As(err, &ae) || ae.Status != 403 || !strings.Contains(err.Error(), "отклонил токен") || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("%v", err)
	}
}
