//go:build desktop

package desktop

import (
	"fmt"
	"net/http"
	"os"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// Available reports whether this binary was built with desktop support.
const Available = true

// Run opens the Hestia window; the asset handler is the same one `serve`
// uses, so no TCP port is opened. It returns the process exit code.
func Run(h http.Handler, title string) int {
	app := application.New(application.Options{
		Name:        "Hestia",
		Description: "Hestia HomeLAN",
		Assets:      application.AssetOptions{Handler: h},
	})
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  title,
		Width:  1200,
		Height: 800,
		URL:    "/",
	})
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка окна:", err)
		return 1
	}
	return 0
}
