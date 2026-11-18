package netscan

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func fastScanner(d Dialer) *Scanner {
	return &Scanner{Dialer: d, ProbeTimeout: 900 * time.Millisecond, BannerTimeout: 150 * time.Millisecond, ConnTimeout: 300 * time.Millisecond}
}

// fingerprintAll probes every recorded endpoint and returns the services by
// "ip:port".
func fingerprintAll(t *testing.T) (map[string]ServiceInfo, map[string]HostResult) {
	t.Helper()
	fx := loadFixtures(t)
	fn := startFixtureServers(t, fx)
	ports := map[netip.Addr][]int{}
	add := func(ip string, port int) {
		a := netip.MustParseAddr(ip)
		for _, p := range ports[a] {
			if p == port {
				return
			}
		}
		ports[a] = append(ports[a], port)
	}
	for _, h := range fx.HTTP {
		add(h.IP, h.Port)
	}
	for _, s := range fx.SSH {
		add(s.IP, s.Port)
	}
	var found []Discovery
	for a, p := range ports {
		found = append(found, Discovery{IP: a, Open: p})
	}
	sc := fastScanner(fn)
	sc.Resolver = fakeResolver{"10.10.10.12": {"git.lan."}}
	res, err := sc.Fingerprint(context.Background(), found, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	svcs := map[string]ServiceInfo{}
	hosts := map[string]HostResult{}
	for _, r := range res {
		hosts[r.IP.String()] = r
		for _, s := range r.Services {
			svcs[key(r.IP, s.Port)] = s
		}
	}
	return svcs, hosts
}

func TestRecognitionFromRecordedAnswers(t *testing.T) {
	svcs, _ := fingerprintAll(t)
	want := map[string]string{
		"10.10.10.1:80":     "mikrotik",
		"10.10.10.10:8006":  "proxmox-ve",
		"10.10.10.19:8007":  "proxmox-backup",
		"10.10.10.12:443":   "gitea",
		"10.10.10.17:81":    "npm",
		"10.10.10.15:9091":  "adguard",
		"10.10.10.15:80":    "web-server", // nginx redirecting to https
		"10.10.10.25:80":    "gotify",
		"10.10.10.33:3000":  "semaphore",
		"10.10.10.13:443":   "qui",
		"10.10.10.16:3000":  "docmost",
		"10.10.10.127:8080": "iris",
		"10.10.10.108:80":   "web-server", // Apache default page
		"10.10.10.23:80":    "web-server", // nginx default page
		"10.10.10.36:443":   "hpe-ilo",
		"10.10.10.40:9001":  "s3",
		"10.10.10.99:80":    "synology",
		"10.10.10.30:443":   "web-server", // nginx with a login redirect: nothing more is known
		"10.10.10.3:80":     "tplink",
		"10.10.10.38:3000":  "http", // 400 "Host validation failed": a web app, unknown
		"10.10.10.34:443":   "port", // recorded as a timeout
		"10.10.10.10:22":    "ssh",
		"10.10.10.33:22":    "ssh",
		"10.10.10.3:22":     "ssh",
		"10.10.10.36:22":    "hpe-ilo",
		"10.10.10.1:2222":   "mikrotik",
		"10.10.10.2:22":     "mikrotik",
	}
	for k, rule := range want {
		s, ok := svcs[k]
		if !ok {
			t.Errorf("%s: no service", k)
			continue
		}
		if s.Rule != rule {
			t.Errorf("%s: rule %q (%s), want %q", k, s.Rule, s.Name, rule)
		}
	}
	if len(svcs) != len(want) {
		t.Errorf("services: %d, want %d", len(svcs), len(want))
	}

	check := func(k string, f func(ServiceInfo) bool, what string) {
		t.Helper()
		if s := svcs[k]; !f(s) {
			t.Errorf("%s: %s: %+v", k, what, s)
		}
	}
	check("10.10.10.12:443", func(s ServiceInfo) bool { return s.Version == "1.25.4" && s.Category == CatDev }, "gitea version")
	check("10.10.10.25:80", func(s ServiceInfo) bool { return s.Version == "3.0.0" }, "gotify version")
	check("10.10.10.15:9091", func(s ServiceInfo) bool { return s.Name == "AdGuard Home" && s.Category == CatNetwork }, "adguard")
	check("10.10.10.15:80", func(s ServiceInfo) bool {
		return s.Name == "Веб-сервер nginx" && strings.Contains(s.Detail, "https://10.10.10.15/") && s.URL == "http://10.10.10.15/"
	}, "nginx redirect")
	check("10.10.10.108:80", func(s ServiceInfo) bool {
		return s.Name == "Веб-сервер Apache" && s.Detail == "страница по умолчанию"
	}, "apache")
	check("10.10.10.23:80", func(s ServiceInfo) bool {
		return s.Name == "Веб-сервер nginx" && s.Detail == "страница по умолчанию"
	}, "nginx")
	check("10.10.10.99:80", func(s ServiceInfo) bool {
		return strings.Contains(s.Detail, "5000") && strings.Contains(s.Detail, "5001")
	}, "synology ports")
	check("10.10.10.10:8006", func(s ServiceInfo) bool { return s.URL == "https://10.10.10.10:8006/" && s.Category == CatInfra }, "pve url")
	check("10.10.10.1:80", func(s ServiceInfo) bool { return s.URL == "http://10.10.10.1/" && s.Name == "MikroTik RouterOS" }, "mikrotik")
	check("10.10.10.40:9001", func(s ServiceInfo) bool { return s.Category == CatStorage && s.Status == 403 }, "s3")
	check("10.10.10.34:443", func(s ServiceInfo) bool {
		return s.Name == "Открытый порт 443" && s.URL == "" && strings.Contains(s.Detail, "не ответил")
	}, "timeout")
	check("10.10.10.38:3000", func(s ServiceInfo) bool { return s.Name == "HTTP" && s.Detail == "ответ 400" && s.Status == 400 }, "400")

	// SSH banners.
	check("10.10.10.10:22", func(s ServiceInfo) bool {
		return s.Version == "OpenSSH 10.0p2" && s.OS == "Debian 13" && s.Name == "SSH" && s.Proto == "ssh"
	}, "openssh debian")
	check("10.10.10.33:22", func(s ServiceInfo) bool { return s.Version == "OpenSSH 9.6p1" && s.OS == "Ubuntu" }, "openssh ubuntu")
	check("10.10.10.3:22", func(s ServiceInfo) bool { return s.Version == "Dropbear 2011.54" && s.OS == "" }, "dropbear")
	check("10.10.10.36:22", func(s ServiceInfo) bool { return s.Name == "HPE iLO" && s.Category == CatInfra }, "mpSSH")
	check("10.10.10.1:2222", func(s ServiceInfo) bool { return s.Name == "MikroTik RouterOS" && s.Detail == "SSH" }, "ROSSSH")
}

func TestCertificatesAndNamesFromRecordedAnswers(t *testing.T) {
	svcs, hosts := fingerprintAll(t)
	g := svcs["10.10.10.12:443"].Cert
	if g == nil || g.CN != "git.home" || g.Issuer != "MyHomeCA" || g.SelfSigned || len(g.SAN) != 1 || g.SAN[0] != "git.home" || g.NotAfter.IsZero() {
		t.Fatalf("gitea cert: %+v", g)
	}
	pbs := svcs["10.10.10.19:8007"].Cert
	if pbs == nil || !pbs.SelfSigned || pbs.CN != "pbs01.home" {
		t.Fatalf("pbs cert: %+v", pbs)
	}
	if svcs["10.10.10.1:80"].Cert != nil {
		t.Fatal("plain http has no cert")
	}

	// Names: PTR first, then the certificate; source is recorded.
	names := hosts["10.10.10.12"].Names
	got := map[string]string{}
	for _, n := range names {
		got[n.Name] = n.Source
	}
	if got["git.lan"] != "ptr" || got["git.home"] != "cert" {
		t.Fatalf("names: %+v", names)
	}
	// A useful title is a name; a default page or an error is not.
	if got2 := hosts["10.10.10.13"].Names; len(got2) == 0 {
		t.Fatal("no names for qui")
	}
	for _, n := range hosts["10.10.10.23"].Names {
		if n.Source == "title" {
			t.Fatalf("default page title taken as a name: %+v", n)
		}
	}
	var titled bool
	for _, n := range hosts["10.10.10.13"].Names {
		if n.Source == "title" && n.Name == "qui" {
			titled = true
		}
	}
	if !titled {
		t.Fatalf("qui title missing: %+v", hosts["10.10.10.13"].Names)
	}
}

func TestSecretsAreNotKept(t *testing.T) {
	svcs, _ := fingerprintAll(t)
	for k, s := range svcs {
		if len(s.Cookies) > 0 {
			for _, c := range s.Cookies {
				if strings.Contains(c, "=") {
					t.Errorf("%s: cookie value kept: %q", k, c)
				}
			}
		}
	}
	if c := svcs["10.10.10.12:443"].Cookies; len(c) != 2 || c[0] != "i_like_gitea" {
		t.Fatalf("gitea cookies: %v", c)
	}
}

func TestFollowupPathsAreFixedAndLimited(t *testing.T) {
	cases := []struct {
		f    Facts
		want []string
	}{
		{Facts{Location: "/login.html"}, []string{"/control/status"}},
		{Facts{Port: 8096}, []string{"/System/Info/Public"}},
		{Facts{Cookies: []string{"i_like_gitea"}}, []string{"/api/v1/version"}},
		{Facts{Port: 8123}, []string{"/manifest.json"}},
		{Facts{Port: 80, Title: "Welcome"}, nil},
		// two matches at most
		{Facts{Port: 8123, Title: "Jellyfin", Location: "/login.html", Cookies: []string{"i_like_gitea"}}, []string{"/control/status", "/System/Info/Public"}},
	}
	for _, c := range cases {
		got := extraPaths(&c.f)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%+v: %v, want %v", c.f, got, c.want)
		}
	}
}

func TestExtraPathServicesUseTheirAnswers(t *testing.T) {
	jf := &Facts{Port: 8096, Proto: "http", Status: 200, Extra: map[string]Extra{"/System/Info/Public": {Status: 200, Body: `{"ProductName":"Jellyfin Server","Version":"10.10.7"}`}}}
	if s := Identify(jf); s.Rule != "jellyfin" || s.Version != "10.10.7" {
		t.Fatalf("jellyfin: %+v", s)
	}
	ha := &Facts{Port: 8123, Proto: "http", Status: 200, Extra: map[string]Extra{"/manifest.json": {Status: 200, Body: `{"name":"Home Assistant"}`}}}
	if s := Identify(ha); s.Rule != "home-assistant" || s.Category != CatHome {
		t.Fatalf("ha: %+v", s)
	}
	ag := &Facts{Port: 3000, Proto: "http", Status: 200, Extra: map[string]Extra{"/control/status": {Status: 200, Body: `{"dns_addresses":["10.10.10.15"],"version":"v0.107.57"}`}}}
	if s := Identify(ag); s.Rule != "adguard" || s.Version != "v0.107.57" {
		t.Fatalf("adguard: %+v", s)
	}
	// A 404 on the extra path does not make it AdGuard.
	not := &Facts{Port: 3000, Proto: "http", Status: 302, Location: "/login.html", Extra: map[string]Extra{"/control/status": {Status: 404}}}
	if s := Identify(not); s.Rule == "adguard" {
		t.Fatalf("404 taken as adguard: %+v", s)
	}
	gt := &Facts{Port: 3000, Proto: "http", Status: 200, Extra: map[string]Extra{"/api/v1/version": {Status: 200, Body: `{"version":"1.22.3"}`}}}
	if s := Identify(gt); s.Rule != "gitea" || s.Version != "1.22.3" {
		t.Fatalf("gitea: %+v", s)
	}
}

func TestPortRules(t *testing.T) {
	for port, rule := range map[int]string{445: "smb", 139: "smb", 2049: "nfs", 5432: "postgres", 3306: "mysql", 6379: "redis",
		1883: "mqtt", 53: "dns", 1080: "socks", 4000: "nomachine", 8291: "mikrotik", 8728: "mikrotik", 10051: "zabbix", 3389: "rdp"} {
		f := &Facts{Port: port, Proto: "tcp", Hint: PortHint(port)}
		if s := Identify(f); s.Rule != rule {
			t.Errorf("port %d: %s, want %s", port, s.Rule, rule)
		}
	}
	if s := Identify(&Facts{Port: 10050, Proto: "tcp", Hint: PortHint(10050)}); s.Rule != "zabbix-agent" {
		t.Errorf("10050: %+v", s)
	}
	// 4000 answering HTTP is an app, not NoMachine.
	if s := Identify(&Facts{Port: 4000, Proto: "http", Status: 200}); s.Rule == "nomachine" {
		t.Errorf("http on 4000: %+v", s)
	}
	if s := Identify(&Facts{Port: 80, Proto: "http", Status: 200, Title: "Hestia"}); s.Rule != "hestia" {
		t.Errorf("hestia: %+v", s)
	}
	// An unknown port is just an open port.
	if s := Identify(&Facts{Port: 4242, Proto: "tcp", Hint: PortHint(4242)}); s.Rule != "port" || s.Name != "Открытый порт 4242" {
		t.Fatalf("%+v", s)
	}
	// A server that speaks first on an unknown banner port.
	if s := Identify(&Facts{Port: 21, Proto: "banner", Banner: "220 ProFTPD Server ready", Hint: PortHint(21)}); s.Rule != "ftp" || s.Detail != "220 ProFTPD Server ready" {
		t.Fatalf("%+v", s)
	}
}

func TestProbeGetsBannerFromSilentAndTalkingServers(t *testing.T) {
	fn := newFakeNet()
	fn.route("10.10.10.7", 21, listenBanner(t, "220 ProFTPD Server (Debian) ready\r\n"))
	fn.route("10.10.10.7", 9999, listenBanner(t, "")) // auto port that never speaks
	fn.route("10.10.10.7", 8765, listenBanner(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"))
	sc := fastScanner(fn)
	res, err := sc.Fingerprint(context.Background(), []Discovery{{IP: netip.MustParseAddr("10.10.10.7"), Open: []int{21, 8765, 9999}}}, nil, nil)
	if err != nil || len(res) != 1 {
		t.Fatal(err, res)
	}
	by := map[int]ServiceInfo{}
	for _, s := range res[0].Services {
		by[s.Port] = s
	}
	if by[21].Rule != "ftp" || !strings.HasPrefix(by[21].Detail, "220 ProFTPD") {
		t.Fatalf("ftp: %+v", by[21])
	}
	// An SSH server on an unusual port is still found: the banner is read after TLS fails.
	if by[8765].Rule != "ssh" || by[8765].OS != "Debian 12" || by[8765].Version != "OpenSSH 9.2p1" {
		t.Fatalf("ssh on 8765: %+v", by[8765])
	}
	if by[9999].Rule != "port" {
		t.Fatalf("silent: %+v", by[9999])
	}
}

func TestFingerprintCancel(t *testing.T) {
	fx := loadFixtures(t)
	fn := startFixtureServers(t, fx)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fastScanner(fn).Fingerprint(ctx, []Discovery{{IP: netip.MustParseAddr("10.10.10.10"), Open: []int{8006}}}, nil, nil)
	if err == nil {
		t.Fatal("cancelled fingerprint returned no error")
	}
}
