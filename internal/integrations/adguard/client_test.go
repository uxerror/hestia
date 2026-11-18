package adguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNormalizeFP(t *testing.T) {
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	want := "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF"
	for _, in := range []string{hex, strings.ToUpper(hex), want, strings.ToLower(want), " " + want + " "} {
		if got := NormalizeFP(in); got != want {
			t.Errorf("%q → %q", in, got)
		}
	}
	for _, in := range []string{"", "abc", hex + "00", strings.Repeat("zz", 32)} {
		if NormalizeFP(in) != "" {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestParseBase(t *testing.T) {
	for in, want := range map[string]string{
		"http://10.10.10.2:3000": "http://10.10.10.2:3000", "https://10.10.10.2/": "https://10.10.10.2", " http://adguard.lan ": "http://adguard.lan",
	} {
		if u, err := ParseBase(in); err != nil || u.String() != want {
			t.Errorf("%q → %v %v", in, u, err)
		}
	}
	for _, in := range []string{"", "10.10.10.2", "ftp://x", "http://", "http://u:p@10.10.10.2", "http://10.10.10.2/admin", "http://10.10.10.2?x=1", "http://10.10.10.2:0", "http://10.10.10.2:70000"} {
		if _, err := ParseBase(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestRedirectIsNotFollowedAndNothingLeaks(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/control/status", http.StatusFound)
	}))
	defer srv.Close()
	c, err := NewClient(Config{BaseURL: srv.URL, Username: "admin", Password: "pw-redirect-1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Status(context.Background())
	if err == nil || hits.Load() != 0 {
		t.Fatalf("redirect followed: %v, hits %d", err, hits.Load())
	}
	if strings.Contains(err.Error(), "pw-redirect-1") {
		t.Fatal("password in error")
	}
	res, err := Probe(context.Background(), srv.URL)
	if err != nil || res.StatusCode != 302 || !strings.HasPrefix(res.Location, other.URL) || res.Warning == "" {
		t.Fatalf("%+v %v", res, err)
	}
	if hits.Load() != 0 {
		t.Fatal("probe followed the redirect")
	}
}

func TestTransportErrorsCarryNoURLOrPassword(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, _ := NewClient(Config{BaseURL: url, Username: "admin", Password: "pw-transport-2"})
	_, err := c.RewriteList(context.Background())
	var ue *UnreachableError
	if !errors.As(err, &ue) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "pw-transport-2") || strings.Contains(err.Error(), url) || strings.Contains(err.Error(), "/control") {
		t.Fatalf("leak: %v", err)
	}
}

func TestErrorBodyIsMasked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, p, _ := r.BasicAuth()
		http.Error(w, "bad request from "+p, 400)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{BaseURL: srv.URL, Username: "admin", Password: "pw-echo-3"})
	err := c.RewriteAdd(context.Background(), "a.home", "10.10.10.1")
	if err == nil || strings.Contains(err.Error(), "pw-echo-3") {
		t.Fatalf("%v", err)
	}
}

func TestStatusRejectsOtherServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"hello":"world"}`)) }))
	defer srv.Close()
	c, _ := NewClient(Config{BaseURL: srv.URL})
	if _, err := c.Status(context.Background()); !errors.Is(err, ErrNotAdGuard) {
		t.Fatalf("%v", err)
	}
}
