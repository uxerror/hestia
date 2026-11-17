package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// cmdHealthcheck is used by the upgrade script: exit 0 when the controller at
// --url answers /api/v1/health with status "ok" (and, with --version, with
// exactly that version), 1 otherwise.
func cmdHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:80", "адрес контроллера")
	want := fs.String("version", "", "ожидаемая версия (необязательно)")
	timeout := fs.Duration("timeout", 3*time.Second, "таймаут запроса")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	got, err := healthVersion(context.Background(), *url, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "не здоров:", err)
		return 1
	}
	if *want != "" && got != *want {
		fmt.Fprintf(os.Stderr, "версия %q, ожидалась %q\n", got, *want)
		return 1
	}
	fmt.Println("ok", got)
	return 0
}

func healthVersion(ctx context.Context, base string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/health", nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ответ %s", resp.Status)
	}
	var h struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h); err != nil {
		return "", err
	}
	if h.Status != "ok" {
		return "", fmt.Errorf("status=%q", h.Status)
	}
	return h.Version, nil
}
