package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uxerror/hestia/internal/store"
)

func newSvc(t *testing.T) (*Service, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc, err := Open(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, dir
}

func TestKeyFileCreatedWith0600AndReused(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateKey(dir)
	if err != nil || len(k1) != 32 {
		t.Fatalf("%v %d", err, len(k1))
	}
	st, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	k2, _ := LoadOrCreateKey(dir)
	if !bytes.Equal(k1, k2) {
		t.Fatal("key changed between starts")
	}
	// A loosened mode is tightened again.
	_ = os.Chmod(filepath.Join(dir, KeyFile), 0o644)
	if _, err := LoadOrCreateKey(dir); err != nil {
		t.Fatal(err)
	}
	st, _ = os.Stat(filepath.Join(dir, KeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode not tightened: %v", st.Mode())
	}
	// A truncated key file is rejected, not silently replaced.
	_ = os.WriteFile(filepath.Join(dir, KeyFile), []byte("short"), 0o600)
	if _, err := LoadOrCreateKey(dir); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestPutGetRoundTripAndNoPlaintextInDB(t *testing.T) {
	svc, st, _ := newSvc(t)
	ctx := context.Background()
	id, err := svc.Put(ctx, PurposeAPIToken, []byte("super-secret-token"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, id)
	if err != nil || string(got) != "super-secret-token" {
		t.Fatalf("%q %v", got, err)
	}
	row, _ := st.GetSecret(ctx, id)
	if bytes.Contains(row.Ciphertext, []byte("super-secret")) {
		t.Fatal("plaintext in ciphertext")
	}
	// Same plaintext twice → different nonce and ciphertext.
	id2, _ := svc.Put(ctx, PurposeAPIToken, []byte("super-secret-token"))
	row2, _ := st.GetSecret(ctx, id2)
	if bytes.Equal(row.Nonce, row2.Nonce) || bytes.Equal(row.Ciphertext, row2.Ciphertext) {
		t.Fatal("nonce reused")
	}
}

func TestWrongKeyAndTamperingFail(t *testing.T) {
	svc, st, _ := newSvc(t)
	ctx := context.Background()
	id, _ := svc.Put(ctx, PurposeAPIToken, []byte("x"))

	other, err := New(st, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(ctx, id); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: %v", err)
	}
	// Changing the purpose in the DB breaks authentication (purpose is AAD).
	if _, err := st.DB().Exec(`UPDATE secrets SET purpose = 'ssh_key' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, id); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("purpose swap: %v", err)
	}
	if _, err := New(st, []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := svc.Get(ctx, 9999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestIdentityStableAcrossRestartsAndNeverRegenerated(t *testing.T) {
	svc, st, dir := newSvc(t)
	ctx := context.Background()
	a, err := svc.EnsureIdentity(ctx, "box")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.AuthorizedKey, "ssh-ed25519 ") || !strings.HasSuffix(a.AuthorizedKey, " hestia@box") || !strings.HasPrefix(a.Fingerprint, "SHA256:") {
		t.Fatalf("%+v", a)
	}
	svc2, _ := Open(st, dir) // same master key
	b, err := svc2.EnsureIdentity(ctx, "box")
	if err != nil || a.Fingerprint != b.Fingerprint {
		t.Fatalf("identity changed: %v", err)
	}
	// Lost master key: error, no new identity.
	lost, _ := New(st, bytes.Repeat([]byte{9}, 32))
	if _, err := lost.EnsureIdentity(ctx, "box"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v", err)
	}
	var n int
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM secrets WHERE purpose = ?`, PurposeSSHKey).Scan(&n)
	if n != 1 {
		t.Fatalf("%d ssh keys", n)
	}
}

func TestMask(t *testing.T) {
	got := Mask("pw=hunter2 token=abc hunter2", "hunter2", "", "abc")
	if got != "pw=*** token=*** ***" {
		t.Fatal(got)
	}
}
