package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/uxerror/hestia/plugins/hestia-ca/caserver"
	"github.com/uxerror/hestia/plugins/hestia-ca/pki"
	"github.com/uxerror/hestia/sdk"
)

var _ sdk.Actioner = (*caPlugin)(nil)

// Action runs a button of the instance. The passphrase and the backup are
// passed to the CA and kept nowhere (not in the log, the state or errors).
func (p *caPlugin) Action(ctx context.Context, req sdk.ActionRequest, job *sdk.Job) (sdk.ActionResult, error) {
	host := job.Host()
	cl, err := p.client(ctx, host, req.Instance)
	if err != nil {
		return sdk.ActionResult{}, err
	}
	switch req.Action {
	case "root":
		var root caserver.RootInfo
		if err := cl.Do("GET", "/v1/root", nil, &root); err != nil {
			return sdk.ActionResult{}, err
		}
		return sdk.ActionResult{Download: &sdk.Download{Name: "hestia-root-" + root.RootSHA256[:8] + ".crt",
			MIME: "application/x-x509-ca-cert", Data: []byte(root.RootPEM)}}, nil
	case "backup":
		pass := req.Params.String("passphrase")
		if len([]rune(pass)) < pki.MinPassphrase {
			return sdk.ActionResult{}, fmt.Errorf("пароль файла — не короче %d символов", pki.MinPassphrase)
		}
		var out struct {
			Backup string `json:"backup"`
		}
		if err := cl.Do("POST", "/v1/export", map[string]string{"passphrase": pass}, &out); err != nil {
			return sdk.ActionResult{}, sanitize(err)
		}
		var root caserver.RootInfo
		if err := cl.Do("GET", "/v1/root", nil, &root); err != nil {
			return sdk.ActionResult{}, err
		}
		date := p.now().Format("2006-01-02")
		if p.StateDir != "" {
			_ = pki.WriteFileAtomic(p.backupFile(req.Instance.ID), []byte(date+"\n"), 0o600)
		}
		job.Log("info", "Резервная копия ключа CA выдана")
		return sdk.ActionResult{Message: "Храните файл и пароль отдельно от Hestia: с ними можно выпускать сертификаты для вашей сети.",
			Download: &sdk.Download{Name: fmt.Sprintf("hestia-ca-%s-%s.json", root.RootSHA256[:8], date), MIME: "application/json", Data: []byte(out.Backup)}}, nil
	case "restore":
		var out struct {
			RootSHA256 string `json:"root_sha256"`
		}
		err := cl.Do("POST", "/v1/init", caserver.InitRequest{Mode: "import", Backup: req.Params.String("backup"), Passphrase: req.Params.String("passphrase")}, &out)
		if err != nil {
			return sdk.ActionResult{}, sanitize(err)
		}
		job.Log("info", "Ключ CA восстановлен из резервной копии")
		return sdk.ActionResult{Message: "Корень восстановлен: SHA-256 " + pki.FingerprintColon(out.RootSHA256)}, nil
	}
	return sdk.ActionResult{}, fmt.Errorf("нет действия %s", req.Action)
}

// sanitize keeps only the message of a CA error (never a request body).
func sanitize(err error) error {
	var ae *caserver.APIError
	if errors.As(err, &ae) {
		return errors.New(ae.Msg)
	}
	return errors.New("CA не ответил")
}
