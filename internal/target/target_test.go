package target_test

import (
	"context"
	"errors"
	"io/fs"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/uxerror/hestia/internal/sshx"
	"github.com/uxerror/hestia/internal/sshx/sshxtest"
	"github.com/uxerror/hestia/internal/target"
)

// fakeFS interprets just the commands package target emits.
type fakeFS struct {
	mu    sync.Mutex
	files map[string]string
	cmds  []string
}

var (
	reCat   = regexp.MustCompile(`^cat '([^']*)'$`)
	rePut   = regexp.MustCompile(`^cat > '([^']*)' && `)
	reMkdir = regexp.MustCompile(`^mkdir -p '([^']*)' && chmod 700 '([^']*)'$`)
)

func (f *fakeFS) handle(user, cmd string, stdin []byte) (string, string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, cmd)
	switch {
	case cmd == `printf '%s\n' "$HOME"`:
		return "/home/bob\n", "", 0
	case reMkdir.MatchString(cmd):
		return "", "", 0
	case reCat.MatchString(cmd):
		p := reCat.FindStringSubmatch(cmd)[1]
		v, ok := f.files[p]
		if !ok {
			return "", "cat: " + p + ": No such file or directory\n", 1
		}
		return v, "", 0
	case rePut.MatchString(cmd):
		f.files[rePut.FindStringSubmatch(cmd)[1]] = string(stdin)
		return "", "", 0
	}
	return "", "unknown command", 127
}

func newTarget(t *testing.T, files map[string]string) (*target.SSH, *fakeFS) {
	t.Helper()
	fk := &fakeFS{files: files}
	s := sshxtest.New(t)
	s.PasswordAuth = func(string, string) bool { return true }
	s.Handler = fk.handle
	cl, err := sshx.Dial(context.Background(), sshx.Config{Host: s.Host, Port: s.Port, User: "bob", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	return target.NewSSH(cl), fk
}

func TestQuote(t *testing.T) {
	if got := target.Quote(`it's $x`); got != `'it'\''s $x'` {
		t.Fatal(got)
	}
}

func TestGetMissingIsNotExist(t *testing.T) {
	tg, _ := newTarget(t, map[string]string{})
	if _, err := tg.Get(context.Background(), "/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

const keyA = "ssh-ed25519 AAAAkeyA hestia@box"

func TestAddRemoveAuthorizedKey(t *testing.T) {
	ctx := context.Background()
	tg, fk := newTarget(t, map[string]string{"/home/bob/.ssh/authorized_keys": "ssh-rsa OTHER bob@pc"})
	path, err := target.AuthorizedKeysPath(ctx, tg)
	if err != nil || path != "/home/bob/.ssh/authorized_keys" {
		t.Fatalf("%q %v", path, err)
	}
	added, err := target.AddAuthorizedKey(ctx, tg, path, keyA)
	if err != nil || !added {
		t.Fatalf("%v %v", added, err)
	}
	if got := fk.files[path]; got != "ssh-rsa OTHER bob@pc\n"+keyA+"\n" {
		t.Fatalf("file: %q", got)
	}
	// Idempotent, even with another comment.
	added, err = target.AddAuthorizedKey(ctx, tg, path, "ssh-ed25519 AAAAkeyA other-comment")
	if err != nil || added {
		t.Fatalf("second add: %v %v", added, err)
	}
	if err := target.RemoveAuthorizedKey(ctx, tg, path, keyA); err != nil {
		t.Fatal(err)
	}
	if got := fk.files[path]; got != "ssh-rsa OTHER bob@pc\n" {
		t.Fatalf("after remove: %q", got)
	}
	// Removing again / from a missing file is fine.
	if err := target.RemoveAuthorizedKey(ctx, tg, path, keyA); err != nil {
		t.Fatal(err)
	}
	if err := target.RemoveAuthorizedKey(ctx, tg, "/no/file", keyA); err != nil {
		t.Fatal(err)
	}
}

func TestAddCreatesFileAndHandlesMissingNewline(t *testing.T) {
	ctx := context.Background()
	tg, fk := newTarget(t, map[string]string{})
	if added, err := target.AddAuthorizedKey(ctx, tg, "/home/bob/.ssh/authorized_keys", keyA); err != nil || !added {
		t.Fatal(added, err)
	}
	if fk.files["/home/bob/.ssh/authorized_keys"] != keyA+"\n" {
		t.Fatal(fk.files)
	}
	fk.files["/x"] = "ssh-rsa OTHER"
	_, _ = target.AddAuthorizedKey(ctx, tg, "/x", keyA)
	if !strings.HasPrefix(fk.files["/x"], "ssh-rsa OTHER\nssh-ed25519") {
		t.Fatalf("%q", fk.files["/x"])
	}
}

func TestParsers(t *testing.T) {
	if got := target.ParseOSRelease("NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"); got != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatal(got)
	}
	free := "              total        used        free      shared  buff/cache   available\nMem:     8000000000  1000000000  5000000000   100000000  2000000000  6500000000\nSwap:             0           0           0\n"
	tot, av := target.ParseFree(free)
	if tot != 8000000000 || av != 6500000000 {
		t.Fatal(tot, av)
	}
	df := "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 100000 40000 60000 40% /\n/dev/sdb1 200000 1000 199000 1% /mnt/data disk\n"
	d := target.ParseDF(df)
	if len(d) != 2 || d[0].Mount != "/" || d[0].Size != 100000 || d[0].Used != 40000 {
		t.Fatalf("%+v", d)
	}
}
