// Command hestia is the Hestia HomeLAN controller: HTTP server and desktop app.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/uxerror/hestia/internal/api"
	"github.com/uxerror/hestia/internal/auth"
	"github.com/uxerror/hestia/internal/desktop"
	"github.com/uxerror/hestia/internal/dnsname"
	"github.com/uxerror/hestia/internal/inventory"
	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/netscan"
	"github.com/uxerror/hestia/internal/onboard"
	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/secrets"
	"github.com/uxerror/hestia/internal/selfinstall"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/internal/tlsself"
	"github.com/uxerror/hestia/internal/update"
	vers "github.com/uxerror/hestia/internal/version"
	"github.com/uxerror/hestia/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "desktop":
		return cmdDesktop(args[1:])
	case "healthcheck":
		return cmdHealthcheck(args[1:])
	case "tls":
		return cmdTLS(args[1:])
	case "version", "--version", "-v":
		fmt.Println("hestia", version)
		return 0
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Использование: hestia <команда>

  serve    [--listen :8080] [--https-listen :443] [--data ./data] [--plugin-dev <бинарник>]
                                                  HTTP-сервер (API + веб-интерфейс);
                                                  --plugin-dev запускает плагин дочерним
                                                  процессом без песочницы (разработка;
                                                  флаг можно повторять); --https-listen ""
                                                  запрещает HTTPS в этом запуске
  desktop  [--data ~/.local/share/hestia]         окно приложения

Если в каталоге данных есть remote.json, Hestia уже перенесена на сервер: база не
открывается, показывается экран «Hestia работает на <адрес>».
  healthcheck --url http://127.0.0.1:80 [--version X]
                                                  проверка здоровья (для скрипта обновления)
  tls status [--data /var/lib/hestia]             режим HTTPS, имена, сроки, отпечаток корня
                                                  (только файлы, без базы)
  tls reset  [--data /var/lib/hestia]             выключить HTTPS вручную (root или hestia),
                                                  затем: systemctl restart hestia
  version                                         версия
`)
}

// app bundles the long-lived components behind the shared handler.
type app struct {
	store   *store.Store
	runner  *jobs.Runner
	handler http.Handler
	stopInv context.CancelFunc
	inv     *inventory.Service
	net     *netscan.Manager
	dns     *dnsname.Service
	gate    *selfinstall.Gate
	plugins *plugins.Manager
	tls     *tlsself.Service    // serve mode only
	remote  *selfinstall.Remote // set when started in "moved" mode (no database)
}

func (a *app) close() {
	if a.store == nil { // moved mode: nothing was opened
		return
	}
	a.stopInv()
	if a.tls != nil {
		a.tls.Close()
	}
	a.plugins.Close()
	a.inv.Wait()
	a.net.Wait()
	a.dns.Wait()
	a.runner.Shutdown()
	_ = a.store.Close()
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	if v == "" {
		return errors.New("пустой путь")
	}
	*l = append(*l, v)
	return nil
}

// newApp builds the handler used by both serve and desktop.
func newApp(ctx context.Context, dataDir, mode string, pluginDev []string, githubAPI, httpsListen string) (*app, error) {
	// A moved controller never touches its (archived) database.
	rem, err := selfinstall.ReadRemote(dataDir)
	if err != nil {
		return nil, err
	}
	if rem != nil {
		gate := &selfinstall.Gate{}
		gate.SetMoved(*rem)
		return &app{handler: api.NewMoved(gate, web.Dist(), version), gate: gate, remote: rem}, nil
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("база данных: %w", err)
	}
	_ = st.SetSetting(ctx, store.SettingWrittenBy, version)
	// An update job handed over by the previous process is closed below, not
	// marked "interrupted".
	runner, err := jobs.NewRunner(ctx, st, update.Pending(dataDir))
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("задачи: %w", err)
	}
	sec, err := secrets.Open(st, dataDir)
	if err != nil {
		runner.Shutdown()
		_ = st.Close()
		return nil, fmt.Errorf("секреты: %w", err)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "controller"
	}
	id, err := sec.EnsureIdentity(ctx, hostname)
	if err != nil {
		runner.Shutdown()
		_ = st.Close()
		return nil, fmt.Errorf("SSH-ключ Hestia: %w", err)
	}
	instanceID, err := st.EnsureInstanceID(ctx)
	if err != nil {
		runner.Shutdown()
		_ = st.Close()
		return nil, fmt.Errorf("идентификатор экземпляра: %w", err)
	}
	ob := (&onboard.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init()
	inv := (&inventory.Service{Store: st, Secrets: sec, Runner: runner, Identity: id}).Init()
	ob.AfterChange = inv.RefreshQuiet
	invCtx, stopInv := context.WithCancel(ctx)
	inv.Start(invCtx)
	nm := (&netscan.Manager{Store: st, Runner: runner, Inventory: inv, Version: version}).Init()
	nm.Start(invCtx)
	if err := update.Finalize(ctx, st, dataDir, version); err != nil {
		slog.Warn("update.json", "err", err)
	}
	gate := &selfinstall.Gate{}
	si := (&selfinstall.Service{
		Store: st, Secrets: sec, Runner: runner, Identity: id, Gate: gate, DataDir: dataDir, Version: version,
		OnSwitched: stopInv,
	}).Init()
	dns := (&dnsname.Service{
		Store: st, Secrets: sec, Runner: runner, Hosts: nm, InstanceID: instanceID,
		Local: func(ctx context.Context) bool {
			state, err := si.State(ctx)
			return err == nil && state.State == "local"
		},
	}).Init()
	dns.Start(invCtx)
	up := (&update.Service{Store: st, Runner: runner, DataDir: dataDir, Version: version, Self: si,
		GitHub: &update.GitHub{BaseURL: githubAPI}}).Init()
	up.CleanTemp()
	up.StartChecks(invCtx)
	pm := (&plugins.Manager{
		Store: st, Secrets: sec, Runner: runner, Identity: id, Version: version, DataDir: dataDir, Mode: mode,
		Inventory: inv, Netscan: nm, GitHub: &update.GitHub{BaseURL: githubAPI}, CatalogChecks: true,
		Location: func(ctx context.Context) (*selfinstall.Location, error) {
			state, err := si.State(ctx)
			return state.Location, err
		},
		Open: func(ctx context.Context, loc selfinstall.Location) (plugins.Shell, error) {
			return si.OpenShell(ctx, loc)
		},
	}).Init()
	pm.Start()
	var tlsSvc *tlsself.Service
	if mode == "serve" {
		tlsSvc = &tlsself.Service{
			DataDir: dataDir, Store: st, Addr: httpsListen, InstanceID: instanceID, Version: version,
			Names: func(ctx context.Context) (dnsNames, ips []string) {
				if u := dns.PublicURL(ctx); u != "" {
					dnsNames = append(dnsNames, strings.TrimPrefix(u, "http://"))
				}
				if state, err := si.State(ctx); err == nil && state.Location != nil && net.ParseIP(state.Location.IP) != nil {
					ips = append(ips, net.ParseIP(state.Location.IP).String())
				}
				return dnsNames, ips
			},
			PeerZones: func(ctx context.Context, iid int64) []string { return instanceZones(ctx, st, iid) },
		}
		if err := tlsSvc.Init(ctx); err != nil {
			pm.Close()
			stopInv()
			runner.Shutdown()
			_ = st.Close()
			return nil, fmt.Errorf("HTTPS: %w", err)
		}
		if _, err := pm.StartBuiltin(ctx, tlsself.Manifest(version), tlsSvc.Plugin()); err != nil {
			pm.Close()
			stopInv()
			runner.Shutdown()
			_ = st.Close()
			return nil, fmt.Errorf("встроенный компонент Hestia: %w", err)
		}
	}
	for _, p := range pluginDev {
		if err := pm.StartDev(p); err != nil {
			pm.Close()
			stopInv()
			runner.Shutdown()
			_ = st.Close()
			return nil, fmt.Errorf("--plugin-dev %s: %w", p, err)
		}
		slog.Warn("dev-плагин запущен без песочницы", "path", p)
	}
	h := api.New(api.Config{
		Store: st, Auth: auth.New(st), Runner: runner, Onboard: ob, Inventory: inv, Netscan: nm, DNS: dns, Identity: id,
		Selfinstall: si, Gate: gate, Update: up, Plugins: pm, TLS: tlsSvc, InstanceID: instanceID,
		Web: web.Dist(), Mode: mode, Version: version,
	})
	if tlsSvc != nil {
		tlsSvc.SetHandler(h)
		tlsSvc.Start()
	}
	return &app{store: st, runner: runner, handler: h, stopInv: stopInv, inv: inv, net: nm, dns: dns, gate: gate, plugins: pm, tls: tlsSvc}, nil
}

// instanceZones are the DNS zones in the configuration of a provider
// instance ("zones": "home,home.arpa"; nil if it has none).
func instanceZones(ctx context.Context, st *store.Store, iid int64) []string {
	in, err := st.GetInstance(ctx, iid)
	if err != nil {
		return nil
	}
	var cfg map[string]any
	if json.Unmarshal([]byte(in.Config), &cfg) != nil {
		return nil
	}
	z, _ := cfg["zones"].(string)
	var out []string
	for _, p := range strings.Split(z, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdTLS(args []string) int {
	if len(args) == 0 || (args[0] != "status" && args[0] != "reset") {
		fmt.Fprintln(os.Stderr, "использование: hestia tls status|reset [--data /var/lib/hestia]")
		return 2
	}
	fs := flag.NewFlagSet("tls "+args[0], flag.ContinueOnError)
	data := fs.String("data", "/var/lib/hestia", "каталог данных")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	var err error
	if args[0] == "status" {
		err = tlsself.StatusReport(os.Stdout, *data, time.Now())
	} else {
		err = tlsself.Reset(os.Stdout, *data, time.Now())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	return 0
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "адрес для прослушивания")
	data := fs.String("data", "./data", "каталог данных")
	var pluginDev stringList
	fs.Var(&pluginDev, "plugin-dev", "запустить плагин дочерним процессом без песочницы (разработка; можно повторять)")
	githubAPI := fs.String("github-api", update.DefaultAPI, "адрес API GitHub для обновлений и каталога плагинов (для тестов)")
	httpsListen := fs.String("https-listen", ":443", "адрес HTTPS (открывается, когда HTTPS включён связью с HestiaCA; пусто — HTTPS запрещён)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := newApp(ctx, *data, "serve", pluginDev, *githubAPI, *httpsListen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	defer a.close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	// No WriteTimeout: SSE streams are long-lived.
	srv := &http.Server{Handler: a.handler, ReadHeaderTimeout: 10 * time.Second}
	slog.Info("hestia слушает", "addr", ln.Addr().String(), "version", version)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			return 1
		}
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = srv.Close() // drop lingering SSE connections
	}
	return 0
}

func cmdDesktop(args []string) int {
	fs := flag.NewFlagSet("desktop", flag.ContinueOnError)
	data := fs.String("data", defaultDesktopData(), "каталог данных")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !desktop.Available {
		return desktop.Run(nil, "", "") // prints the stub message, exit code 2
	}
	a, err := newApp(context.Background(), *data, "desktop", nil, update.DefaultAPI, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	defer a.close()
	start := ""
	if a.remote != nil {
		// Moved: open the remote controller directly if it answers; otherwise
		// the window shows the local "moved" screen, which can retry.
		ctx, cancel := context.WithTimeout(context.Background(), 4*selfinstall.CheckTimeout)
		if rem, ok := selfinstall.ResolveStart(ctx, *data, *a.remote, selfinstall.StartOptions{}); ok {
			start = rem.URL
			if u, stop := offerUpdate(ctx, rem, version); u != "" {
				start = u
				defer stop()
			}
		}
		cancel()
	}
	return desktop.Run(a.handler, "Hestia", start)
}

func defaultDesktopData() string {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "hestia")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./data"
	}
	return filepath.Join(home, ".local", "share", "hestia")
}

// offerUpdate compares the controller's version with this app's. If the app
// is newer it starts the loopback helper that hands out the embedded binary
// and returns the update screen to open; if the app is older it returns the
// screen with the notice. stop shuts the helper down.
func offerUpdate(ctx context.Context, rem selfinstall.Remote, appVersion string) (string, func()) {
	remoteVer, err := healthVersion(ctx, rem.URL, selfinstall.CheckTimeout)
	if err != nil {
		return "", nil
	}
	switch {
	case vers.Offer(remoteVer, appVersion):
		payload, err := selfinstall.PayloadBinary()
		if err != nil {
			return "", nil // this build has no binary to offer
		}
		h, err := update.NewHelper(payload, appVersion, rem.URL)
		if err != nil {
			return "", nil
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", nil
		}
		srv := &http.Server{Handler: h.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		return update.OfferURL(rem.URL, ln.Addr().String(), appVersion, h.Nonce()), func() { _ = srv.Close() }
	case vers.Offer(appVersion, remoteVer):
		return update.OlderURL(rem.URL, appVersion), func() {}
	}
	return "", nil
}
