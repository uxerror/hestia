// Command hestia-probe is a demo plugin of Hestia for links: it requires an
// http.service provider (for example hestia-hello), polls its URL from its
// own sandbox and shows the answer as the status of the instance. It has no
// targets and no Docker.
package main

import (
	_ "embed"

	"github.com/uxerror/hestia/sdk"
)

//go:embed manifest.json
var manifest []byte

func main() { sdk.Serve(manifest, newProbe()) }
