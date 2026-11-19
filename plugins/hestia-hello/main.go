// Command hestia-hello is the demo plugin of Hestia and a template for
// plugin authors: it runs the whoami web service (traefik/whoami) in Docker
// on the chosen target through deploy.* and checks it over HTTP.
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
	h := &hello{StateDir: os.Getenv("STATE_DIRECTORY")}
	if h.StateDir == "" && os.Getenv(sdk.EnvSocket) == "" {
		// dev mode (a child of `hestia serve --plugin-dev`)
		h.StateDir = filepath.Join(os.TempDir(), "hestia-hello-dev")
	}
	sdk.Serve(manifest, h)
}
