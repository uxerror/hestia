//go:build !desktop

package desktop

import (
	"fmt"
	"net/http"
	"os"
)

// Available reports whether this binary was built with desktop support.
const Available = false

// Run is the stub used when built without -tags desktop.
func Run(_ http.Handler, _, _ string) int {
	fmt.Fprintln(os.Stderr, "собрано без desktop")
	return 2
}
