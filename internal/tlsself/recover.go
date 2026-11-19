package tlsself

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/uxerror/hestia/sdk/types"
)

// Recovery without the database (`hestia tls status|reset`): they read and
// change only files under the data directory, so that root never creates
// database files owned by root.

// ServiceUser is the system user of the controller (unit of 02d).
const ServiceUser = "hestia"

// currentUser is replaced in tests.
var currentUser = func() (uid int, name string) {
	uid = os.Geteuid()
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return uid, name
}

// StatusReport prints the state of HTTPS from the files.
func StatusReport(w io.Writer, dataDir string, now time.Time) error {
	dir := filepath.Join(dataDir, DirName)
	if _, err := os.Stat(filepath.Join(dataDir, ResetMarker)); err == nil {
		fmt.Fprintln(w, "Маркер tls-reset: есть — после перезапуска HTTPS будет выключен")
	}
	b, err := os.ReadFile(filepath.Join(dir, fileState))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "HTTPS: выключен (нет "+filepath.Join(dir, fileState)+")")
		return nil
	}
	if err != nil {
		return err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s: %w", fileState, err)
	}
	fmt.Fprintf(w, "HTTPS: %s (связь %d)\n", st.Mode, st.Link)
	fmt.Fprintf(w, "Имена: %s\n", strings.Join(append(append([]string{}, st.DNS...), st.IPs...), ", "))
	fmt.Fprintf(w, "Сертификат: серийный %s, %s — %s", st.Serial, st.NotBefore.UTC().Format(time.RFC3339), st.NotAfter.UTC().Format(time.RFC3339))
	if !now.Before(st.NotAfter) {
		fmt.Fprint(w, " (истёк)")
	}
	fmt.Fprintln(w)
	if ca, err := os.ReadFile(filepath.Join(dir, fileCA)); err == nil {
		if c, err := types.ParseCert(string(ca)); err == nil {
			fmt.Fprintf(w, "Корень: %s\nSHA-256: %s\n", c.Subject.String(), colon(types.CertSHA256(c.Raw)))
		}
	}
	return nil
}

func colon(h string) string {
	var parts []string
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, strings.ToUpper(h[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// Reset turns HTTPS off by hand: tls/ moves to tls.off-<ts> and the marker
// tells the next start to set the mode "off" (the database is not touched).
// Only root or the service user may run it.
func Reset(w io.Writer, dataDir string, now time.Time) error {
	uid, name := currentUser()
	if uid != 0 && name != ServiceUser {
		return fmt.Errorf("запустите от root или от пользователя %s (sudo / pct exec)", ServiceUser)
	}
	st, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("каталог данных: %w", err)
	}
	dir := filepath.Join(dataDir, DirName)
	if _, err := os.Stat(dir); err == nil {
		dst := filepath.Join(dataDir, fmt.Sprintf("%s.off-%d", DirName, now.Unix()))
		if err := os.Rename(dir, dst); err != nil {
			return err
		}
		fmt.Fprintln(w, "Файлы сертификата перенесены в "+dst)
	}
	marker := filepath.Join(dataDir, ResetMarker)
	if err := os.WriteFile(marker, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return err
	}
	// The controller (user hestia) removes the marker at start.
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && uid == 0 {
		_ = os.Chown(marker, int(sys.Uid), int(sys.Gid))
	}
	fmt.Fprintln(w, "HTTPS будет выключен при следующем запуске. Выполните: systemctl restart hestia")
	return nil
}
