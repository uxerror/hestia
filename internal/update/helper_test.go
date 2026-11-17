package update

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const remoteOrigin = "http://198.51.100.9"

func helperSrv(t *testing.T) (*Helper, *httptest.Server) {
	t.Helper()
	h, err := NewHelper(serverBin, "v0.2.0-3-gabc1234-dirty", remoteOrigin+"/")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	return h, srv
}

func get(t *testing.T, method, url, origin string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestHelperServesPayloadAndMeta(t *testing.T) {
	h, srv := helperSrv(t)
	if len(h.Nonce()) != 64 {
		t.Fatalf("nonce must be 32 bytes of hex: %q", h.Nonce())
	}
	resp, b := get(t, "GET", srv.URL+"/payload/"+h.Nonce(), remoteOrigin)
	if resp.StatusCode != 200 || string(b) != string(serverBin) || resp.Header.Get("Access-Control-Allow-Origin") != remoteOrigin {
		t.Fatalf("payload: %d cors=%q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
	}
	resp, b = get(t, "GET", srv.URL+"/payload/"+h.Nonce()+"/meta", remoteOrigin)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"dirty":true`) || !strings.Contains(string(b), `"version":"v0.2.0-3-gabc1234-dirty"`) ||
		!strings.Contains(string(b), `"sha256":"`) || !strings.Contains(string(b), `"size":`) {
		t.Fatalf("meta: %d %s", resp.StatusCode, b)
	}
}

func TestHelperRefusesStrangers(t *testing.T) {
	h, srv := helperSrv(t)
	for _, c := range []struct {
		name, path, origin string
		want               int
	}{
		{"wrong nonce", "/payload/" + strings.Repeat("0", 64), remoteOrigin, 404},
		{"no nonce", "/payload/", remoteOrigin, 404},
		{"root", "/", remoteOrigin, 404},
		{"api", "/api/v1/health", remoteOrigin, 404},
		{"other sub path", "/payload/" + h.Nonce() + "/x", remoteOrigin, 404},
		{"other origin", "/payload/" + h.Nonce(), "http://evil.example", 403},
		{"other port is another origin", "/payload/" + h.Nonce(), remoteOrigin + ":8080", 403},
		{"meta from another origin", "/payload/" + h.Nonce() + "/meta", "http://evil.example", 403},
	} {
		resp, _ := get(t, "GET", srv.URL+c.path, c.origin)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %d, want %d", c.name, resp.StatusCode, c.want)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "" && c.want != 200 {
			t.Errorf("%s: CORS header on a refusal", c.name)
		}
	}
	if resp, _ := get(t, "POST", srv.URL+"/payload/"+h.Nonce(), remoteOrigin); resp.StatusCode != 405 {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	// preflight
	resp, _ := get(t, "OPTIONS", srv.URL+"/payload/"+h.Nonce(), remoteOrigin)
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != remoteOrigin {
		t.Errorf("preflight: %d", resp.StatusCode)
	}
}

func TestHelperNoncesDiffer(t *testing.T) {
	a, _ := NewHelper(nil, "v1.0.0", remoteOrigin)
	b, _ := NewHelper(nil, "v1.0.0", remoteOrigin)
	if a.Nonce() == b.Nonce() {
		t.Fatal("nonces must be random")
	}
	if _, err := NewHelper(nil, "v1.0.0", "not a url"); err == nil {
		t.Fatal("bad remote URL")
	}
}

func TestOfferURLs(t *testing.T) {
	u := OfferURL("http://198.51.100.9/", "127.0.0.1:4321", "v0.2.0", "abc")
	frag := strings.TrimPrefix(u, "http://198.51.100.9/#/update/offer?")
	if frag == u {
		t.Fatalf("%s", u)
	}
	q, _ := url.ParseQuery(frag)
	if q.Get("from") != "http://127.0.0.1:4321" || q.Get("v") != "v0.2.0" || q.Get("n") != "abc" {
		t.Fatalf("%v", q)
	}
	if o := OlderURL("http://198.51.100.9", "v0.1.0"); !strings.Contains(o, "#/update/offer?") || !strings.Contains(o, "older=1") {
		t.Fatal(o)
	}
}
