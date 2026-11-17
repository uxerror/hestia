package selfinstall

import "fmt"

// Paths and names on the target.
const (
	PayloadName = "hestia-linux-amd64"
	binPath     = "/usr/local/bin/hestia"
	unitPath    = "/etc/systemd/system/hestia.service"
	dataPath    = "/var/lib/hestia"
	svcUser     = "hestia"
)

// unitText renders the systemd unit; port is the listen port.
func unitText(port int) string {
	return fmt.Sprintf(`[Unit]
Description=Hestia HomeLAN controller
After=network-online.target
Wants=network-online.target

[Service]
User=%[1]s
Group=%[1]s
ExecStart=%[2]s serve --listen :%[3]d --data %[4]s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=%[4]s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, svcUser, binPath, port, dataPath)
}
