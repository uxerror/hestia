package netscan

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Rule recognises a service from the facts of a port. Rules are tried in
// order, from specific to general; the first match wins.
type Rule struct {
	ID       string
	Name     string
	Category string
	Match    func(f *Facts) bool
	// Version, OS and Detail are optional digests of the facts.
	Version func(f *Facts) string
	OS      func(f *Facts) string
	Detail  func(f *Facts) string
}

// ---- helpers over facts ----

func lc(s string) string { return strings.ToLower(s) }

func titleHas(f *Facts, sub string) bool { return strings.Contains(lc(f.Title), lc(sub)) }
func titleIs(f *Facts, t string) bool    { return strings.EqualFold(f.Title, t) }
func bodyHas(f *Facts, sub string) bool  { return strings.Contains(f.Body, sub) }
func serverHas(f *Facts, sub string) bool {
	return strings.Contains(lc(f.Server), lc(sub))
}
func hasCookie(f *Facts, name string) bool {
	for _, c := range f.Cookies {
		if c == name {
			return true
		}
	}
	return false
}
func isWeb(f *Facts) bool { return f.Proto == "http" || f.Proto == "https" }
func hasPort(f *Facts, p int) bool {
	for _, q := range f.OpenPorts {
		if q == p {
			return true
		}
	}
	return false
}

func port(p int) func(*Facts) bool { return func(f *Facts) bool { return f.Port == p } }

func always(*Facts) bool { return true }

// extraPaths lists the follow-up GETs a preliminary match asks for (at most 2).
func extraPaths(f *Facts) []string {
	var out []string
	add := func(p string) {
		if len(out) < 2 {
			out = append(out, p)
		}
	}
	if f.Location == "/login.html" { // AdGuard Home redirects to its login page
		add("/control/status")
	}
	if titleHas(f, "jellyfin") || f.Port == 8096 {
		add("/System/Info/Public")
	}
	if hasCookie(f, "i_like_gitea") || titleIs(f, "Gitea") {
		add("/api/v1/version")
	}
	if titleHas(f, "home assistant") || f.Port == 8123 {
		add("/manifest.json")
	}
	return out
}

var (
	reGiteaAsset = regexp.MustCompile(`index\.css\?v=([0-9][0-9A-Za-z.+-]*)`)
	reJSONVer    = regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)
	reDebSuffix  = regexp.MustCompile(`deb(\d+)`)
	reHTTPInput  = regexp.MustCompile(`id="(http|https)"[^>]*value="(\d+)"`)
)

func extraOK(f *Facts, path string) (Extra, bool) {
	e, ok := f.Extra[path]
	return e, ok && e.Status == 200
}

// ---- SSH banners ----

// sshSoftware splits "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4" into the
// software token and the comment.
func sshSoftware(banner string) (soft, comment string) {
	b := strings.TrimPrefix(banner, "SSH-")
	if i := strings.Index(b, "-"); i >= 0 {
		b = b[i+1:]
	}
	soft, comment, _ = strings.Cut(b, " ")
	return soft, comment
}

func sshVersion(f *Facts) string {
	soft, _ := sshSoftware(f.Banner)
	name, ver, _ := strings.Cut(soft, "_")
	if ver == "" {
		return name
	}
	if strings.EqualFold(name, "dropbear") {
		name = "Dropbear"
	}
	return name + " " + ver
}

func sshOS(f *Facts) string {
	_, c := sshSoftware(f.Banner)
	switch {
	case strings.HasPrefix(c, "Debian") || strings.HasPrefix(c, "Raspbian"):
		if m := reDebSuffix.FindStringSubmatch(c); m != nil {
			return "Debian " + m[1]
		}
		return "Debian"
	case strings.HasPrefix(c, "Ubuntu"):
		return "Ubuntu"
	case strings.HasPrefix(c, "FreeBSD"):
		return "FreeBSD"
	}
	return ""
}

func sshIs(f *Facts, soft string) bool {
	return f.Proto == ProtoSSH && strings.Contains(f.Banner, soft)
}

// ---- the rule table ----

// Rules is the table of known services.
var Rules = []Rule{
	// Hypervisors, backup, router, BMC.
	{ID: "proxmox-ve", Name: "Proxmox VE", Category: CatInfra,
		Match: func(f *Facts) bool {
			return isWeb(f) && (strings.HasPrefix(f.Server, "pve-api-daemon") || titleHas(f, "Proxmox Virtual Environment"))
		}},
	{ID: "proxmox-backup", Name: "Proxmox Backup Server", Category: CatInfra,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Proxmox Backup Server") }},
	{ID: "mikrotik", Name: "MikroTik RouterOS", Category: CatInfra,
		Match: func(f *Facts) bool {
			return sshIs(f, "ROSSSH") || f.Port == 8291 || f.Port == 8728 || f.Port == 8729 ||
				(isWeb(f) && (titleIs(f, "RouterOS") || bodyHas(f, "mikrotik_logo")))
		},
		Detail: func(f *Facts) string {
			switch {
			case f.Port == 8291:
				return "Winbox"
			case f.Port == 8728, f.Port == 8729:
				return "API"
			case f.Proto == ProtoSSH:
				return "SSH"
			}
			return "веб-интерфейс"
		}},
	{ID: "hpe-ilo", Name: "HPE iLO", Category: CatInfra,
		Match: func(f *Facts) bool {
			return sshIs(f, "mpSSH") || (isWeb(f) && (bodyHas(f, "js/iLO.js") || (bodyHas(f, "RpPageHeader") && bodyHas(f, "Hewlett Packard"))))
		},
		Detail: func(f *Facts) string {
			if f.Proto == ProtoSSH {
				return "SSH"
			}
			return "управление сервером"
		}},
	{ID: "synology", Name: "Synology DSM", Category: CatStorage,
		Match: func(f *Facts) bool {
			return isWeb(f) && (titleHas(f, "Synology") || serverHas(f, "synology") ||
				(bodyHas(f, `id="prefer_https"`) && bodyHas(f, "location.replace")))
		},
		Detail: func(f *Facts) string {
			var ports []string
			for _, m := range reHTTPInput.FindAllStringSubmatch(f.Body, -1) {
				ports = append(ports, m[1]+" "+m[2])
			}
			if len(ports) == 0 {
				return ""
			}
			return "перенаправляет на " + strings.Join(ports, ", ")
		}},
	// DNS filter, proxies.
	{ID: "adguard", Name: "AdGuard Home", Category: CatNetwork,
		Match: func(f *Facts) bool {
			e, ok := f.Extra["/control/status"]
			if !ok {
				return isWeb(f) && titleHas(f, "AdGuard Home")
			}
			return e.Status == 401 || (e.Status == 200 && (strings.Contains(e.Body, "dns_addresses") || strings.Contains(e.Body, "protection_enabled")))
		},
		Version: func(f *Facts) string {
			if e, ok := extraOK(f, "/control/status"); ok {
				if m := reJSONVer.FindStringSubmatch(e.Body); m != nil {
					return m[1]
				}
			}
			return ""
		}},
	{ID: "npm", Name: "Nginx Proxy Manager", Category: CatNetwork,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Nginx Proxy Manager") }},
	// Development, monitoring, home.
	{ID: "gitea", Name: "Gitea", Category: CatDev,
		Match: func(f *Facts) bool {
			if e, ok := extraOK(f, "/api/v1/version"); ok && reJSONVer.MatchString(e.Body) {
				return true
			}
			return isWeb(f) && (hasCookie(f, "i_like_gitea") || titleIs(f, "Gitea") || strings.HasSuffix(f.Title, " - Gitea"))
		},
		Version: func(f *Facts) string {
			if e, ok := extraOK(f, "/api/v1/version"); ok {
				if m := reJSONVer.FindStringSubmatch(e.Body); m != nil {
					return m[1]
				}
			}
			if m := reGiteaAsset.FindStringSubmatch(f.Body); m != nil {
				return m[1]
			}
			return ""
		}},
	{ID: "semaphore", Name: "Semaphore UI", Category: CatDev,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Semaphore") }},
	{ID: "docmost", Name: "Docmost", Category: CatOther,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Docmost") }},
	{ID: "zabbix-agent", Name: "Zabbix agent", Category: CatMonitoring, Match: port(10050)},
	{ID: "zabbix", Name: "Zabbix", Category: CatMonitoring,
		Match: func(f *Facts) bool { return f.Port == 10051 || (isWeb(f) && titleHas(f, "Zabbix")) },
		Detail: func(f *Facts) string {
			switch f.Port {
			case 10050:
				return "агент"
			case 10051:
				return "сервер"
			}
			return ""
		}},
	{ID: "gotify", Name: "Gotify", Category: CatMonitoring,
		Match: func(f *Facts) bool { return isWeb(f) && titleIs(f, "Gotify") },
		Version: func(f *Facts) string {
			if m := regexp.MustCompile(`"version":\{"version":"([^"]+)"`).FindStringSubmatch(f.Body); m != nil {
				return m[1]
			}
			return ""
		}},
	{ID: "grafana", Name: "Grafana", Category: CatMonitoring,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Grafana") }},
	{ID: "prometheus", Name: "Prometheus", Category: CatMonitoring,
		Match: func(f *Facts) bool {
			return isWeb(f) && (titleIs(f, "Prometheus Time Series Collection and Processing Server") || titleHas(f, "Prometheus"))
		}},
	{ID: "netdata", Name: "Netdata", Category: CatMonitoring,
		Match: func(f *Facts) bool { return isWeb(f) && (titleHas(f, "netdata") || f.Port == 19999 && f.Status == 200) }},
	{ID: "home-assistant", Name: "Home Assistant", Category: CatHome,
		Match: func(f *Facts) bool {
			if e, ok := extraOK(f, "/manifest.json"); ok && strings.Contains(e.Body, "Home Assistant") {
				return true
			}
			return isWeb(f) && titleHas(f, "Home Assistant")
		}},
	{ID: "homepage", Name: "Homepage", Category: CatHome,
		Match: func(f *Facts) bool { return isWeb(f) && titleIs(f, "Homepage") }},
	{ID: "portainer", Name: "Portainer", Category: CatInfra,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Portainer") }},
	{ID: "webmin", Name: "Webmin", Category: CatInfra,
		Match: func(f *Facts) bool { return isWeb(f) && (titleHas(f, "Webmin") || serverHas(f, "MiniServ")) }},
	{ID: "cockpit", Name: "Cockpit", Category: CatInfra,
		Match: func(f *Facts) bool { return isWeb(f) && (titleIs(f, "Cockpit") || bodyHas(f, "cockpit/static")) }},
	// Media and files.
	{ID: "qui", Name: "qui (qBittorrent)", Category: CatMedia,
		Match: func(f *Facts) bool { return isWeb(f) && titleIs(f, "qui") }},
	{ID: "qbittorrent", Name: "qBittorrent", Category: CatMedia,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "qBittorrent") }},
	{ID: "navidrome", Name: "Navidrome", Category: CatMedia,
		Match: func(f *Facts) bool { return isWeb(f) && titleHas(f, "Navidrome") }},
	{ID: "jellyfin", Name: "Jellyfin", Category: CatMedia,
		Match: func(f *Facts) bool {
			if e, ok := extraOK(f, "/System/Info/Public"); ok && strings.Contains(e.Body, "Jellyfin") {
				return true
			}
			return isWeb(f) && titleHas(f, "Jellyfin")
		},
		Version: func(f *Facts) string {
			if e, ok := extraOK(f, "/System/Info/Public"); ok {
				var v struct{ Version string }
				if json.Unmarshal([]byte(e.Body), &v) == nil {
					return v.Version
				}
			}
			return ""
		}},
	{ID: "plex", Name: "Plex", Category: CatMedia,
		Match: func(f *Facts) bool {
			return isWeb(f) && (titleIs(f, "Plex") || f.Headers.Get("X-Plex-Protocol") != "" || (f.Port == 32400 && titleHas(f, "plex")))
		}},
	{ID: "iris", Name: "Iris", Category: CatMedia,
		Match: func(f *Facts) bool { return isWeb(f) && titleIs(f, "Iris") }},
	{ID: "arr", Name: "", Category: CatMedia, // Sonarr, Radarr, Lidarr, Prowlarr: the name comes from the title
		Match: func(f *Facts) bool {
			if !isWeb(f) {
				return false
			}
			for _, n := range []string{"Sonarr", "Radarr", "Lidarr", "Prowlarr"} {
				if titleIs(f, n) {
					return true
				}
			}
			return false
		}},
	{ID: "s3", Name: "S3-хранилище (MinIO / RustFS)", Category: CatStorage,
		Match: func(f *Facts) bool {
			return isWeb(f) && (f.Headers.Get("X-Amz-Request-Id") != "" || (strings.Contains(f.Type, "xml") && bodyHas(f, "<Error><Code>")) || serverHas(f, "minio"))
		},
		Detail: func(f *Facts) string {
			if serverHas(f, "minio") {
				return "MinIO"
			}
			return "ответ S3 (Access Denied без ключа)"
		}},
	{ID: "syncthing", Name: "Syncthing", Category: CatStorage,
		Match: func(f *Facts) bool {
			return isWeb(f) && (titleHas(f, "Syncthing") || f.Port == 8384 && hasCookie(f, "CSRF-Token"))
		}},
	{ID: "tplink", Name: "TP-Link (веб-интерфейс роутера)", Category: CatNetwork,
		Match: func(f *Facts) bool { return isWeb(f) && bodyHas(f, "/webpages/login.html") }},
	{ID: "cups", Name: "CUPS / IPP", Category: CatOther,
		Match: func(f *Facts) bool { return f.Port == 631 || (isWeb(f) && titleHas(f, "CUPS")) }},

	// Plain TCP services by port.
	{ID: "smb", Name: "Samba / SMB", Category: CatStorage, Match: func(f *Facts) bool { return f.Port == 139 || f.Port == 445 },
		Detail: func(f *Facts) string {
			if f.Port == 139 {
				return "NetBIOS"
			}
			return ""
		}},
	{ID: "nfs", Name: "NFS", Category: CatStorage, Match: port(2049)},
	{ID: "postgres", Name: "PostgreSQL", Category: CatDB, Match: port(5432)},
	{ID: "mysql", Name: "MySQL / MariaDB", Category: CatDB, Match: port(3306)},
	{ID: "redis", Name: "Redis", Category: CatDB, Match: port(6379)},
	{ID: "mongodb", Name: "MongoDB", Category: CatDB, Match: port(27017)},
	{ID: "mssql", Name: "Microsoft SQL Server", Category: CatDB, Match: port(1433)},
	{ID: "memcached", Name: "Memcached", Category: CatDB, Match: port(11211)},
	{ID: "mqtt", Name: "MQTT", Category: CatHome, Match: port(1883)},
	{ID: "dns", Name: "DNS", Category: CatNetwork, Match: port(53)},
	{ID: "socks", Name: "SOCKS-прокси", Category: CatNetwork, Match: port(1080)},
	{ID: "openvpn", Name: "OpenVPN", Category: CatNetwork, Match: port(1194)},
	{ID: "wireguard", Name: "WireGuard", Category: CatNetwork, Match: port(51820)},
	// 4000 is also a common app port: only a non-HTTP listener is NoMachine.
	{ID: "nomachine", Name: "NoMachine", Category: CatRemote, Match: func(f *Facts) bool { return f.Port == 4000 && !isWeb(f) }},
	{ID: "ftp", Name: "FTP", Category: CatStorage, Match: func(f *Facts) bool {
		return f.Port == 21 || strings.HasPrefix(f.Banner, "220 ") && strings.Contains(lc(f.Banner), "ftp")
	}},
	{ID: "telnet", Name: "Telnet", Category: CatRemote, Match: port(23)},
	{ID: "rdp", Name: "RDP", Category: CatRemote, Match: port(3389)},
	{ID: "vnc", Name: "VNC", Category: CatRemote, Match: port(5900)},
	{ID: "airplay", Name: "AirPlay", Category: CatHome, Match: func(f *Facts) bool { return f.Port == 7000 && !isWeb(f) || f.Port == 7000 && f.Status == 403 }},
	{ID: "docker-api", Name: "Docker API", Category: CatInfra, Match: func(f *Facts) bool { return f.Port == 2375 || f.Port == 2376 }},

	// General.
	{ID: "ssh", Name: "SSH", Category: CatRemote,
		Match:   func(f *Facts) bool { return f.Proto == ProtoSSH },
		Version: sshVersion, OS: sshOS},
	{ID: "hestia", Name: "Hestia", Category: CatInfra, Match: func(f *Facts) bool { return isWeb(f) && titleIs(f, "Hestia") }},
	{ID: "web-server", Name: "", Category: CatOther, // "Веб-сервер nginx / Apache / OpenResty"
		Match: func(f *Facts) bool { return isWeb(f) && webServerName(f) != "" }},
	{ID: "http", Name: "HTTP", Category: CatOther, Match: func(f *Facts) bool { return f.Proto == "http" }},
	{ID: "https", Name: "HTTPS", Category: CatOther, Match: func(f *Facts) bool { return f.Proto == "https" }},
	{ID: "banner", Name: "TCP-сервис", Category: CatOther, Match: func(f *Facts) bool { return f.Proto == ProtoBanner && f.Banner != "" }},
	{ID: "port", Name: "", Category: CatOther, Match: always},
}

// webServerName returns "nginx", "Apache", … for a general web server.
func webServerName(f *Facts) string {
	s := lc(f.Server)
	for _, n := range []struct{ key, name string }{
		{"openresty", "OpenResty"}, {"nginx", "nginx"}, {"apache", "Apache"}, {"caddy", "Caddy"},
		{"lighttpd", "lighttpd"}, {"traefik", "Traefik"}, {"haproxy", "HAProxy"},
	} {
		if strings.Contains(s, n.key) {
			return n.name
		}
	}
	if titleHas(f, "Apache2") || titleHas(f, "Apache HTTP") {
		return "Apache"
	}
	if titleHas(f, "nginx") {
		return "nginx"
	}
	return ""
}

// Identify turns the facts of a port into a service by the first matching rule.
func Identify(f *Facts) ServiceInfo {
	var r *Rule
	for i := range Rules {
		if Rules[i].Match(f) {
			r = &Rules[i]
			break
		}
	}
	svc := ServiceInfo{
		Port: f.Port, Proto: f.Proto, Rule: r.ID, Name: r.Name, Category: r.Category,
		Title: f.Title, Server: f.Server, Status: f.Status, Location: f.Location, Cert: f.Cert,
	}
	if len(f.Cookies) > 0 {
		svc.Cookies = append([]string(nil), f.Cookies...)
	}
	if r.Version != nil {
		svc.Version = r.Version(f)
	}
	if r.OS != nil {
		svc.OS = r.OS(f)
	}
	if r.Detail != nil {
		svc.Detail = r.Detail(f)
	}
	switch r.ID {
	case "arr":
		svc.Name = f.Title
	case "web-server":
		svc.Name = "Веб-сервер " + webServerName(f)
		svc.Detail = webDetail(f)
	case "http", "https":
		svc.Detail = webDetail(f)
	case "banner":
		svc.Detail = f.Banner
	case "port":
		svc.Name = "Открытый порт " + strconv.Itoa(f.Port)
		svc.Detail = portDetail(f)
	}
	if svc.Detail == "" && r.ID != "ssh" && r.ID != "port" {
		if f.Banner != "" && f.Proto != ProtoSSH {
			svc.Detail = f.Banner
		}
	}
	if isWeb(f) {
		svc.URL = serviceURL(f.Proto, f.IP, f.Port)
	}
	return svc
}

func portDetail(f *Facts) string {
	switch {
	case f.Err != "" && f.Hint.Proto != ProtoNone:
		if f.Hint.Name != "" {
			return f.Hint.Name + ", не ответил на запрос"
		}
		return "не ответил на запрос"
	case f.Hint.Name != "":
		return f.Hint.Name
	}
	return ""
}

// webDetail summarises a generic web answer.
func webDetail(f *Facts) string {
	switch {
	case f.Status >= 300 && f.Status < 400 && f.Location != "":
		return "перенаправляет на " + f.Location
	case strings.Contains(lc(f.Title), "welcome to nginx") || strings.Contains(lc(f.Title), "default page"):
		return "страница по умолчанию"
	case f.Status >= 400:
		return "ответ " + strconv.Itoa(f.Status)
	}
	return f.Title
}

func serviceURL(scheme string, ip netip.Addr, port int) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s/", scheme, ip)
	}
	return fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
}
