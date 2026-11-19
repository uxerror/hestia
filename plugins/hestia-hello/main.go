// Command hestia-hello is the demo plugin of Hestia and a template for
// plugin authors: it runs the whoami web service (traefik/whoami) in Docker
// on the chosen target through deploy.* and checks it over HTTP.
package main

import (
	_ "embed"

	"github.com/uxerror/hestia/sdk"
)

//go:embed manifest.json
var manifest []byte

func main() { sdk.Serve(manifest, &hello{}) }
