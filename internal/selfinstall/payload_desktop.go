//go:build desktop

package selfinstall

import (
	"embed"
	"io/fs"
)

// Only desktop builds carry the server binary: a server build embedding
// itself would grow with every build.
//
//go:embed payload
var payloadFS embed.FS

func embeddedBinary() ([]byte, bool) {
	b, err := fs.ReadFile(payloadFS, "payload/"+PayloadName)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

const desktopBuild = true
