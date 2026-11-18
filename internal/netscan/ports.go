package netscan

// Probe protocols of a port: what to expect when it is open.
const (
	ProtoHTTP   = "http"
	ProtoHTTPS  = "https"
	ProtoSSH    = "ssh"
	ProtoBanner = "banner" // the server speaks first (ftp, smtp, mysql, …)
	ProtoNone   = "none"   // do not probe: only report the port
	ProtoAuto   = "auto"   // unknown: try TLS, a banner, then plain HTTP
)

// PortInfo is a scanned port with a hint of what usually listens there.
type PortInfo struct {
	Port  int
	Name  string // short service name, may be empty
	Proto string
}

// Ports is the list of scanned TCP ports (the typical ports of home-lab
// services). Order does not matter: probing order is shuffled.
var Ports = []PortInfo{
	{21, "ftp", ProtoBanner}, {22, "ssh", ProtoSSH}, {23, "telnet", ProtoBanner}, {25, "smtp", ProtoBanner},
	{53, "dns", ProtoNone}, {80, "http", ProtoHTTP}, {81, "http", ProtoHTTP}, {88, "kerberos", ProtoNone},
	{110, "pop3", ProtoBanner}, {111, "rpcbind", ProtoNone}, {135, "msrpc", ProtoNone}, {139, "netbios", ProtoNone},
	{143, "imap", ProtoBanner}, {389, "ldap", ProtoNone}, {443, "https", ProtoHTTPS}, {445, "smb", ProtoNone},
	{465, "smtps", ProtoNone}, {548, "afp", ProtoNone}, {554, "rtsp", ProtoNone}, {587, "submission", ProtoBanner},
	{631, "ipp", ProtoHTTP}, {636, "ldaps", ProtoNone}, {873, "rsync", ProtoBanner}, {993, "imaps", ProtoNone},
	{995, "pop3s", ProtoNone}, {1080, "socks", ProtoNone}, {1194, "openvpn", ProtoNone}, {1433, "mssql", ProtoNone},
	{1521, "oracle", ProtoNone}, {1883, "mqtt", ProtoNone}, {1900, "upnp", ProtoHTTP}, {2000, "mikrotik-btest", ProtoNone},
	{2049, "nfs", ProtoNone}, {2222, "ssh-alt", ProtoSSH}, {2375, "docker", ProtoHTTP}, {2376, "docker-tls", ProtoHTTPS},
	{3000, "", ProtoAuto}, {3001, "", ProtoAuto}, {3128, "squid", ProtoNone}, {3260, "iscsi", ProtoNone},
	{3261, "", ProtoAuto}, {3306, "mysql", ProtoBanner}, {3389, "rdp", ProtoNone}, {3478, "stun", ProtoNone},
	{4000, "nomachine", ProtoNone}, {4040, "", ProtoAuto}, {4443, "", ProtoHTTPS}, {4533, "navidrome", ProtoHTTP},
	{5000, "", ProtoAuto}, {5001, "", ProtoAuto}, {5005, "", ProtoAuto}, {5050, "", ProtoAuto},
	{5060, "sip", ProtoNone}, {5201, "iperf", ProtoNone}, {5232, "", ProtoAuto}, {5357, "wsdapi", ProtoHTTP},
	{5432, "postgres", ProtoNone}, {5555, "", ProtoAuto}, {5601, "kibana", ProtoHTTP}, {5672, "amqp", ProtoNone},
	{5900, "vnc", ProtoBanner}, {5959, "", ProtoAuto}, {6052, "", ProtoAuto}, {6379, "redis", ProtoNone},
	{6443, "k8s", ProtoHTTPS}, {6767, "", ProtoAuto}, {6789, "", ProtoAuto}, {6881, "bittorrent", ProtoNone},
	{7000, "airplay", ProtoAuto}, {7070, "", ProtoAuto}, {7443, "", ProtoHTTPS}, {7878, "radarr", ProtoHTTP},
	{8000, "", ProtoAuto}, {8001, "", ProtoAuto}, {8006, "proxmox", ProtoHTTPS}, {8007, "pbs", ProtoHTTPS},
	{8008, "", ProtoAuto}, {8009, "", ProtoAuto}, {8053, "", ProtoAuto}, {8080, "http-alt", ProtoHTTP},
	{8081, "", ProtoHTTP}, {8082, "", ProtoHTTP}, {8083, "", ProtoHTTP}, {8084, "", ProtoHTTP},
	{8085, "", ProtoHTTP}, {8086, "influxdb", ProtoHTTP}, {8088, "", ProtoHTTP}, {8090, "", ProtoHTTP},
	{8091, "", ProtoHTTP}, {8096, "jellyfin", ProtoHTTP}, {8112, "deluge", ProtoHTTP}, {8123, "home-assistant", ProtoHTTP},
	{8180, "", ProtoHTTP}, {8181, "", ProtoHTTP}, {8200, "", ProtoAuto}, {8291, "winbox", ProtoNone},
	{8384, "syncthing", ProtoAuto}, {8443, "https-alt", ProtoHTTPS}, {8448, "", ProtoHTTPS}, {8500, "consul", ProtoHTTP},
	{8686, "lidarr", ProtoHTTP}, {8728, "routeros-api", ProtoNone}, {8729, "routeros-api-ssl", ProtoNone}, {8765, "", ProtoAuto},
	{8787, "", ProtoAuto}, {8800, "", ProtoAuto}, {8843, "", ProtoHTTPS}, {8880, "", ProtoHTTP},
	{8888, "", ProtoHTTP}, {8920, "jellyfin-tls", ProtoHTTPS}, {8989, "sonarr", ProtoHTTP}, {9000, "", ProtoAuto},
	{9001, "", ProtoAuto}, {9042, "cassandra", ProtoNone}, {9080, "", ProtoHTTP}, {9090, "prometheus", ProtoAuto},
	{9091, "", ProtoAuto}, {9092, "", ProtoAuto}, {9100, "node-exporter", ProtoHTTP}, {9117, "jackett", ProtoHTTP},
	{9200, "elasticsearch", ProtoHTTP}, {9443, "portainer", ProtoHTTPS}, {9696, "prowlarr", ProtoHTTP}, {9999, "", ProtoAuto},
	{10000, "webmin", ProtoAuto}, {10050, "zabbix-agent", ProtoNone}, {10051, "zabbix", ProtoNone}, {11211, "memcached", ProtoNone},
	{19999, "netdata", ProtoHTTP}, {25565, "minecraft", ProtoNone}, {27017, "mongodb", ProtoNone}, {32400, "plex", ProtoAuto},
	{51413, "bittorrent", ProtoNone}, {51820, "wireguard", ProtoNone},
}

var portIndex = func() map[int]PortInfo {
	m := make(map[int]PortInfo, len(Ports))
	for _, p := range Ports {
		m[p.Port] = p
	}
	return m
}()

// PortHint returns what is known about a port; unknown ports are "auto".
func PortHint(port int) PortInfo {
	if p, ok := portIndex[port]; ok {
		return p
	}
	return PortInfo{Port: port, Proto: ProtoAuto}
}
