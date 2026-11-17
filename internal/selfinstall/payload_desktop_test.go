//go:build desktop

package selfinstall_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hestia/internal/selfinstall"
)

// A desktop build compiled without payload/hestia-linux-amd64 must still
// work, but installing must fail with a clear message.
func TestDesktopWithoutPayload(t *testing.T) {
	if _, err := os.Stat(filepath.Join("payload", selfinstall.PayloadName)); err == nil {
		t.Skip("payload binary present in this checkout")
	}
	e := newEnv(t)
	e.svc.Binary = nil
	_, err := e.probe(selfinstall.ProbeRequest{})
	asErr(t, err, 422, "эта сборка не содержит серверного бинарника")
	if err != nil && !strings.Contains(err.Error(), "make desktop") {
		t.Fatalf("hint missing: %v", err)
	}
}
