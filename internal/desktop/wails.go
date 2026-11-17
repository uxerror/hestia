//go:build desktop

package desktop

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// Available reports whether this binary was built with desktop support.
const Available = true

// Run opens the Hestia window.
//
// The handler is served on a loopback port and the window loads it as an
// ordinary http:// page. Serving it through Wails' custom asset scheme does
// not work: WebKitGTK drops Set-Cookie on custom-scheme responses, so every
// request after login came back 401. Over loopback HTTP the session cookie,
// SSE and later the switch to a remote controller (just another URL) behave
// exactly as in a browser. It returns the process exit code.
func Run(h http.Handler, title string) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "не удалось открыть локальный порт:", err)
		return 1
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("local server", "err", err)
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	url := "http://" + ln.Addr().String() + "/"
	slog.Info("desktop", "url", url)

	app := application.New(application.Options{
		Name:        "Hestia",
		Description: "Hestia HomeLAN",
		Assets:      application.AssetOptions{Handler: h},
	})
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  title,
		Width:  1200,
		Height: 800,
		URL:    url,
	})
	if err := app.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка окна:", err)
		return 1
	}
	return 0
}
