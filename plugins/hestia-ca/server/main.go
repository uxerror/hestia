// Command ca-server is the CA service of HestiaCA. It runs in a container on
// the CA target (image hestia.local/hestia-ca/ca-server, built by Hestia
// from this binary): the root key lives only in /data.
//
//	ca-server serve [--listen :9443] [--data /data]   API (HTTPS, token from HESTIA_CA_TOKEN_SHA256)
//	ca-server api-pin [--data /data]                  sha256 of the API key (SPKI)
//	ca-server root-sha256 [--data /data]              fingerprint of the root
//	ca-server health [--addr 127.0.0.1:9443] [--data /data]
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/uxerror/hestia/plugins/hestia-ca/caserver"
)

// version is set at build time.
var version = "v0.1.0"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "использование: ca-server serve|api-pin|root-sha256|health|version")
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	data := fs.String("data", "/data", "каталог данных CA")
	listen := fs.String("listen", ":9443", "адрес API")
	addr := fs.String("addr", "127.0.0.1:9443", "адрес API для health")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "serve":
		return serve(*listen, *data)
	case "api-pin":
		pin, err := caserver.APIPin(*data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			return 1
		}
		fmt.Println(pin)
	case "root-sha256":
		fp, err := caserver.RootSHA256(*data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			return 1
		}
		fmt.Println(fp)
	case "health":
		if err := caserver.HealthCheck(*addr, *data, 5*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			return 1
		}
		fmt.Println("ok")
	case "version":
		fmt.Println("ca-server", version)
	default:
		fmt.Fprintf(os.Stderr, "неизвестная команда %q\n", args[0])
		return 2
	}
	return 0
}

func serve(listen, data string) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	leaf := caserver.DefaultLeafMax
	if v := os.Getenv("HESTIA_CA_LEAF_MAX"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			fmt.Fprintln(os.Stderr, "ошибка: HESTIA_CA_LEAF_MAX — длительность Go, например 2160h")
			return 2
		}
		leaf = d
	}
	s := &caserver.Server{Dir: data, TokenSHA: os.Getenv("HESTIA_CA_TOKEN_SHA256"), LeafMax: leaf, Version: version, Log: log}
	if s.TokenSHA == "" {
		log.Warn("ca-server: HESTIA_CA_TOKEN_SHA256 не задан — все вызовы, кроме health, будут отклонены")
	}
	if _, err := s.APICert(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	log.Info("ca-server слушает", "addr", ln.Addr().String(), "version", version)
	if err := s.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	return 0
}
