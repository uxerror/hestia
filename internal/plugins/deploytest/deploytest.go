// Package deploytest is a fake deploy target for tests: an in-process SSH
// server (sshxtest) that runs every command with the local /bin/sh, with
// fake docker, apt-get, ss, systemctl and pct first in PATH. Absolute paths
// the deploy code uses (/opt/hestia, /etc/os-release, /etc/hosts) are moved under a
// temporary root. Nothing real is installed or started.
package deploytest

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/uxerror/hestia/internal/sshx/sshxtest"
)

// Fake programs; $FAKE is the state directory, $ROOT stands for /.
var bins = map[string]string{
	"getent": `#!/bin/sh
# Only "getent hosts <name>" from $ROOT/etc/hosts (never the real resolver).
[ "$1" = hosts ] || exit 2
[ -f "$ROOT/etc/hosts" ] || exit 2
while read -r ip rest; do
  for n in $rest; do [ "$n" = "#" ] && break; [ "$n" = "$2" ] && { echo "$ip       $2"; exit 0; }; done
done < "$ROOT/etc/hosts"
exit 2
`,
	"apt-get": `#!/bin/sh
echo "apt-get $*" >> "$FAKE/apt.log"
if [ -f "$FAKE/fail-apt" ]; then echo "E: fake apt failure" >&2; exit 100; fi
if [ "$1" = install ]; then mkdir -p "$FAKE/dockerbin" && cp "$FAKE/docker.tpl" "$FAKE/dockerbin/docker" && chmod 0755 "$FAKE/dockerbin/docker"; rm -f "$FAKE/no-compose"; echo "Setting up docker.io"; fi
exit 0
`,
	"ss": `#!/bin/sh
cat "$FAKE/ss" 2>/dev/null
exit 0
`,
	"systemctl": `#!/bin/sh
echo "systemctl $*" >> "$FAKE/systemctl.log"
exit 0
`,
	"pct": `#!/bin/sh
echo "pct $*" >> "$FAKE/pct.log"
case "$1" in
exec) shift 3; exec "$@";;
set|reboot) if [ -f "$FAKE/fail-pct" ]; then echo "pct: fake failure" >&2; exit 2; fi; exit 0;;
esac
echo "pct: unknown $1" >&2
exit 2
`,
}

const dockerBin = `#!/bin/sh
echo "docker $*" >> "$FAKE/docker.log"
# Images: $FAKE/images.list has "<ref> <hestia.sha256 label>" lines.
case "$1" in
image)
  case "$2" in
  inspect)
    for a; do ref=$a; done
    [ -f "$FAKE/images.list" ] || exit 1
    while read -r r l; do [ "$r" = "$ref" ] && { echo "$l"; exit 0; }; done < "$FAKE/images.list"
    exit 1;;
  ls)
    [ -f "$FAKE/images.list" ] && while read -r r l; do echo "$r"; done < "$FAKE/images.list"
    exit 0;;
  rm)
    shift 2
    for r; do
      echo "$r" >> "$FAKE/image-rm.log"
      : > "$FAKE/images.new"
      [ -f "$FAKE/images.list" ] && while read -r x l; do [ "$x" = "$r" ] || echo "$x $l" >> "$FAKE/images.new"; done < "$FAKE/images.list"
      mv "$FAKE/images.new" "$FAKE/images.list"
    done
    exit 0;;
  esac;;
import)
  sha=
  for a; do ref=$a; case "$a" in "LABEL hestia.sha256="*) sha=${a#LABEL hestia.sha256=}; sha=${sha%% *};; esac; done
  cat > "$FAKE/import.tgz"
  echo "$*" >> "$FAKE/import.log"
  echo "$ref $sha" >> "$FAKE/images.list"
  echo "sha256:fake"
  exit 0;;
ps)
  cat "$FAKE/ps-plugin" 2>/dev/null
  exit 0;;
esac
[ "$1" = compose ] || { echo "fake docker: $*" >&2; exit 1; }
shift
proj=
while [ $# -gt 0 ]; do
  case "$1" in
  -p) proj="$2"; shift 2;;
  -f) shift 2;;
  *) break;;
  esac
done
case "$1" in
version)
  if [ -f "$FAKE/no-compose" ]; then echo "docker: 'compose' is not a docker command." >&2; exit 1; fi
  echo 2.26.1;;
up)
  if [ -f "$FAKE/fail-up" ]; then echo "Error response from daemon: fake failure"; exit 1; fi
  cp compose.yaml "$FAKE/up-$proj.yaml"
  echo "$proj" >> "$FAKE/up.log"
  state=running; [ -f "$FAKE/state" ] && state=$(cat "$FAKE/state")
  port=$(cat "$FAKE/port" 2>/dev/null || echo 8080)
  svc=$(cat "$FAKE/service" 2>/dev/null || echo app)
  printf '{"Name":"%s-%s-1","Service":"%s","State":"%s","Status":"Up 1 second","Health":"","ExitCode":0,"Publishers":[{"URL":"0.0.0.0","TargetPort":80,"PublishedPort":%s,"Protocol":"tcp"}]}\n' "$proj" "$svc" "$svc" "$state" "$port" > "$FAKE/ps-$proj"
  echo "Container $proj-$svc-1 Started";;
ps)
  cat "$FAKE/ps-$proj" 2>/dev/null; exit 0;;
down)
  rm -f "$FAKE/ps-$proj"
  echo "$proj $*" >> "$FAKE/down.log"
  echo "Container $proj removed";;
*)
  echo "fake compose: $*" >&2; exit 1;;
esac
`

// tools are the only real programs the fake target can run: PATH holds the
// fakes and links to these, never /usr/bin, so a real docker, apt-get or
// pct on the test machine can never be reached.
var tools = []string{"sh", "cat", "cp", "mv", "rm", "mkdir", "chmod", "wc", "sha256sum", "cut", "true", "false",
	"printf", "echo", "sleep", "test", "ls", "grep", "mktemp"}

// Target is the fake target.
type Target struct {
	Srv  *sshxtest.Server
	Dir  string // state of the fakes ($FAKE)
	Root string // stands for / of the target for /opt/hestia and /etc/os-release

	t     testing.TB
	bin   string
	tools string
	mu    sync.Mutex
	cmds  []string
}

// New starts the server; logins as root with key are accepted.
func New(t testing.TB, key ssh.PublicKey) *Target {
	t.Helper()
	dir := t.TempDir()
	tg := &Target{Dir: filepath.Join(dir, "fake"), Root: filepath.Join(dir, "root"), bin: filepath.Join(dir, "bin"),
		tools: filepath.Join(dir, "tools"), t: t}
	for _, d := range []string{tg.Dir, tg.Root + "/etc", tg.Root + "/opt/hestia", tg.bin, tg.tools} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range tools {
		p, err := exec.LookPath(name)
		if err != nil {
			continue // a shell builtin is enough
		}
		if err := os.Symlink(p, filepath.Join(tg.tools, name)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range bins {
		if err := os.WriteFile(filepath.Join(tg.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tg.Dir, "docker.tpl"), []byte(dockerBin), 0o644); err != nil {
		t.Fatal(err)
	}
	tg.SetOS("debian", "", "Debian GNU/Linux 13 (trixie)")
	tg.write(filepath.Join(tg.Root, "etc", "hosts"), "127.0.0.1 localhost\n")
	tg.InstallDocker()
	srv := sshxtest.New(t)
	want := string(key.Marshal())
	srv.KeyAuth = func(u string, k ssh.PublicKey) bool { return u == "root" && string(k.Marshal()) == want }
	srv.Handler = tg.handle
	tg.Srv = srv
	return tg
}

func (tg *Target) rewrite(cmd string) string {
	cmd = strings.ReplaceAll(cmd, "/opt/hestia", tg.Root+"/opt/hestia")
	cmd = strings.ReplaceAll(cmd, "/etc/hosts", tg.Root+"/etc/hosts")
	return strings.ReplaceAll(cmd, "/etc/os-release", tg.Root+"/etc/os-release")
}

func (tg *Target) handle(user, cmd string, stdin []byte) (string, string, int) {
	tg.mu.Lock()
	tg.cmds = append(tg.cmds, cmd)
	tg.mu.Unlock()
	if user != "root" {
		return "", "fake target: root only", 255
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", tg.rewrite(cmd))
	c.Env = []string{"PATH=" + tg.bin + ":" + tg.Dir + "/dockerbin:" + tg.tools, "FAKE=" + tg.Dir, "ROOT=" + tg.Root, "LC_ALL=C"}
	c.Dir = tg.Dir
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		return "", err.Error(), 255
	}
	return out.String(), errb.String(), code
}

// SetOS writes /etc/os-release.
func (tg *Target) SetOS(id, like, pretty string) {
	body := "ID=" + id + "\nID_LIKE=" + like + "\nPRETTY_NAME=\"" + pretty + "\"\n"
	tg.write(filepath.Join(tg.Root, "etc", "os-release"), body)
}

// InstallDocker puts the fake docker into PATH; RemoveDocker takes it away.
func (tg *Target) InstallDocker() {
	b, _ := os.ReadFile(filepath.Join(tg.Dir, "docker.tpl"))
	_ = os.MkdirAll(filepath.Join(tg.Dir, "dockerbin"), 0o755)
	tg.write(filepath.Join(tg.Dir, "dockerbin", "docker"), string(b))
	_ = os.Chmod(filepath.Join(tg.Dir, "dockerbin", "docker"), 0o755)
}

// RemoveDocker removes the fake docker.
func (tg *Target) RemoveDocker() { _ = os.RemoveAll(filepath.Join(tg.Dir, "dockerbin")) }

// Flag creates (on) or removes a state file such as "fail-up", "no-compose",
// "fail-apt", "fail-pct".
func (tg *Target) Flag(name string, on bool) {
	if on {
		tg.write(filepath.Join(tg.Dir, name), "1\n")
	} else {
		_ = os.Remove(filepath.Join(tg.Dir, name))
	}
}

// Set writes a state file ("ss", "state", "port", "service").
func (tg *Target) Set(name, content string) { tg.write(filepath.Join(tg.Dir, name), content) }

// Log returns a log of the fakes ("docker.log", "apt.log", "pct.log",
// "down.log", "up.log").
func (tg *Target) Log(name string) string {
	b, _ := os.ReadFile(filepath.Join(tg.Dir, name))
	return string(b)
}

// File reads a file of the target by its real path ("/opt/hestia/…");
// ok is false if it does not exist.
func (tg *Target) File(path string) (string, bool) {
	b, err := os.ReadFile(tg.rewrite(path))
	return string(b), err == nil
}

// WriteFile creates a file of the target by its real path.
func (tg *Target) WriteFile(path, content string) {
	p := tg.rewrite(path)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tg.write(p, content)
}

// Commands returns every command the server ran.
func (tg *Target) Commands() []string {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return append([]string(nil), tg.cmds...)
}

func (tg *Target) write(p, content string) {
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		tg.t.Fatal(err)
	}
}
