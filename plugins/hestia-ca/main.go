// Command hestia-ca is HestiaCA: the root CA of Hestia. The CA itself (the
// key) runs as ca-server in a container on a target; this plugin deploys it,
// pins its API key and turns links into certificates (tls.cert, by the
// consumer's CSR) and trust on devices (ca.issuer).
package main

import (
	_ "embed"
	"os"
	"path/filepath"

	"github.com/uxerror/hestia/sdk"
)

//go:embed manifest.json
var manifest []byte

func main() {
	m, _ := sdk.ParseManifest(manifest)
	p := &caPlugin{Version: m.Version, StateDir: os.Getenv("STATE_DIRECTORY")}
	// The test address of the CA is honoured only in dev mode (a child of
	// `hestia serve --plugin-dev`, never under systemd).
	if os.Getenv(sdk.EnvSocket) == "" && os.Getenv(sdk.EnvToken) != "" {
		p.TestAddr = os.Getenv("HESTIA_CA_TEST_ADDR")
		if p.StateDir == "" {
			p.StateDir = filepath.Join(os.TempDir(), "hestia-ca-dev")
			_ = os.MkdirAll(p.StateDir, 0o700)
		}
	}
	sdk.Serve(manifest, p)
}
