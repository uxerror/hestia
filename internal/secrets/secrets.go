// Package secrets encrypts secrets at rest (AES-256-GCM) with a master key
// kept in a 0600 file next to the database, and owns the controller's own
// SSH identity (one ed25519 key per controller).
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"hestia/internal/store"
)

// Purposes of stored secrets.
const (
	PurposeSSHKey   = "ssh_key"
	PurposeAPIToken = "proxmox_api_token"
)

// KeyFile is the master key file name inside the data directory.
const KeyFile = "master.key"

const keySize = 32

// ErrDecrypt means the ciphertext does not authenticate: wrong master key or
// corrupted data.
var ErrDecrypt = errors.New("не удалось расшифровать секрет: неверный мастер-ключ или повреждённые данные")

// LoadOrCreateKey reads <dir>/master.key, creating 32 random bytes with mode
// 0600 on first start. A key file with a wider mode is tightened to 0600.
func LoadOrCreateKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, KeyFile)
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != keySize {
			return nil, fmt.Errorf("мастер-ключ %s повреждён: %d байт вместо %d", path, len(b), keySize)
		}
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0o600 {
			if err := os.Chmod(path, 0o600); err != nil {
				return nil, err
			}
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

// Service encrypts and stores secrets in the database.
type Service struct {
	store *store.Store
	aead  cipher.AEAD
}

// New creates a Service with a 32-byte master key.
func New(st *store.Store, key []byte) (*Service, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("мастер-ключ должен быть %d байт", keySize)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Service{store: st, aead: aead}, nil
}

// Open loads (or creates) the master key in dir and returns a Service.
func Open(st *store.Store, dir string) (*Service, error) {
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	return New(st, key)
}

// Put encrypts plain and stores it; the purpose is bound to the ciphertext.
func (s *Service) Put(ctx context.Context, purpose string, plain []byte) (int64, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	ct := s.aead.Seal(nil, nonce, plain, []byte(purpose))
	return s.store.InsertSecret(ctx, purpose, nonce, ct)
}

// Get decrypts the secret with the given id.
func (s *Service) Get(ctx context.Context, id int64) ([]byte, error) {
	row, err := s.store.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.open(row)
}

// Delete removes a secret.
func (s *Service) Delete(ctx context.Context, id int64) error {
	return s.store.DeleteSecret(ctx, id)
}

func (s *Service) open(row store.SecretRow) ([]byte, error) {
	if len(row.Nonce) != s.aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := s.aead.Open(nil, row.Nonce, row.Ciphertext, []byte(row.Purpose))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Identity is the controller's SSH identity.
type Identity struct {
	Signer        ssh.Signer
	AuthorizedKey string // "ssh-ed25519 AAAA… hestia@host", one line without newline
	Fingerprint   string // SHA256:…
}

// EnsureIdentity loads the controller's ed25519 key, generating it on first
// start. An existing key that cannot be decrypted is an error: a second key
// is never generated silently.
func (s *Service) EnsureIdentity(ctx context.Context, hostname string) (Identity, error) {
	row, err := s.store.GetSecretByPurpose(ctx, PurposeSSHKey)
	switch {
	case err == nil:
		pemBytes, err := s.open(row)
		if err != nil {
			return Identity{}, err
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return Identity{}, fmt.Errorf("SSH-ключ Hestia повреждён: %w", err)
		}
		return identityOf(signer, hostname), nil
	case !errors.Is(err, store.ErrNotFound):
		return Identity{}, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "hestia@"+hostname)
	if err != nil {
		return Identity{}, err
	}
	if _, err := s.Put(ctx, PurposeSSHKey, pem.EncodeToMemory(blk)); err != nil {
		return Identity{}, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return Identity{}, err
	}
	return identityOf(signer, hostname), nil
}

func identityOf(signer ssh.Signer, hostname string) Identity {
	pub := signer.PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " hestia@" + hostname
	return Identity{Signer: signer, AuthorizedKey: line, Fingerprint: ssh.FingerprintSHA256(pub)}
}

// Mask replaces every non-empty secret occurring in s with "***" so command
// output and errors can be logged without leaking credentials.
func Mask(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "***")
		}
	}
	return s
}
