// Command hestia-hello is the demo plugin of Hestia and a template for
// plugin authors. In this version it only exercises the plugin framework:
// plan and apply write a greeting into /tmp/hestia-hello-<instance> on the
// chosen target through target.exec/target.put_file, status reads it back.
package main

import (
	_ "embed"

	"github.com/uxerror/hestia/sdk"
)

//go:embed manifest.json
var manifest []byte

func main() { sdk.Serve(manifest, &hello{}) }
