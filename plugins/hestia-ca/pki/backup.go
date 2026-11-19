package pki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// BackupFormat and BackupVersion identify the backup file.
const (
	BackupFormat  = "hestia-ca-backup"
	BackupVersion = 1
	BackupKDF     = "pbkdf2-sha256"
)

// BackupIter is the PBKDF2 iteration count of new backups.
const BackupIter = 600000

// MinPassphrase is the minimum passphrase length (in characters) on export.
const MinPassphrase = 12

// maxImportIter bounds the work an imported file may demand.
const maxImportIter = 10_000_000

// maxBackupSize bounds the backup file accepted by ImportBackup.
const maxBackupSize = 64 << 10

// minImportIter is the minimum iteration count accepted on import; tests
// lower it to keep runtime small.
var minImportIter = 100000

// errDecrypt is the only error for anything that fails authentication.
var errDecrypt = errors.New("неверный пароль или повреждённый файл")

type backupFile struct {
	Format     string `json:"format"`
	V          int    `json:"v"`
	RootPEM    string `json:"root_pem"`
	RootSHA256 string `json:"root_sha256"`
	KDF        string `json:"kdf"`
	Iter       int    `json:"iter"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	CT         string `json:"ct"`
	Created    string `json:"created"`
}

// ExportBackup encrypts the CA key with a passphrase (PBKDF2-SHA256 +
// AES-256-GCM, root_sha256 as additional data) and returns the backup JSON.
// iter <= 0 means BackupIter.
func ExportBackup(rootPEM []byte, key crypto.Signer, passphrase string, iter int, now time.Time) ([]byte, error) {
	if utf8.RuneCountInString(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("пароль резервной копии — не короче %d символов", MinPassphrase)
	}
	if iter <= 0 {
		iter = BackupIter
	}
	root, err := ParseCertPEM(rootPEM)
	if err != nil {
		return nil, err
	}
	if !KeyMatches(root, key) {
		return nil, errors.New("ключ не соответствует корневому сертификату")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, errors.New("ключ не кодируется в PKCS#8")
	}
	rootSHA := Fingerprint(root.Raw)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := backupAEAD(passphrase, salt, iter)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, der, []byte(rootSHA))
	clear(der)
	b64 := base64.StdEncoding.EncodeToString
	return json.MarshalIndent(backupFile{
		Format:     BackupFormat,
		V:          BackupVersion,
		RootPEM:    string(encodeCert(root.Raw)),
		RootSHA256: rootSHA,
		KDF:        BackupKDF,
		Iter:       iter,
		Salt:       b64(salt),
		Nonce:      b64(nonce),
		CT:         b64(ct),
		Created:    now.UTC().Format(time.RFC3339),
	}, "", "  ")
}

// ImportBackup decrypts a backup and checks that the key belongs to the root
// and the root is a leaf-only CA. Errors never contain the passphrase or key.
func ImportBackup(data []byte, passphrase string) (rootPEM []byte, key *ecdsa.PrivateKey, err error) {
	if len(data) > maxBackupSize {
		return nil, nil, errors.New("файл резервной копии слишком большой")
	}
	var f backupFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, errors.New("это не резервная копия HestiaCA (не JSON)")
	}
	if f.Format != BackupFormat {
		return nil, nil, errors.New("это не резервная копия HestiaCA")
	}
	if f.V != BackupVersion {
		return nil, nil, fmt.Errorf("версия резервной копии %d не поддерживается", f.V)
	}
	if f.KDF != BackupKDF {
		return nil, nil, errors.New("алгоритм ключа резервной копии не поддерживается")
	}
	if f.Iter < minImportIter || f.Iter > maxImportIter {
		return nil, nil, errors.New("недопустимое число итераций в резервной копии")
	}
	root, err := ParseCertPEM([]byte(f.RootPEM))
	if err != nil {
		return nil, nil, errors.New("корневой сертификат в резервной копии повреждён")
	}
	if Fingerprint(root.Raw) != f.RootSHA256 {
		return nil, nil, errDecrypt
	}
	if !root.BasicConstraintsValid || !root.IsCA || root.MaxPathLen != 0 || !root.MaxPathLenZero {
		return nil, nil, errors.New("сертификат в резервной копии — не корень HestiaCA (нужен CA с MaxPathLen 0)")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, nil, errors.New("корневой сертификат в резервной копии не самоподписан")
	}
	dec := base64.StdEncoding.DecodeString
	salt, err1 := dec(f.Salt)
	nonce, err2 := dec(f.Nonce)
	ct, err3 := dec(f.CT)
	if err1 != nil || err2 != nil || err3 != nil || len(salt) < 8 {
		return nil, nil, errDecrypt
	}
	aead, err := backupAEAD(passphrase, salt, f.Iter)
	if err != nil {
		return nil, nil, errDecrypt
	}
	if len(nonce) != aead.NonceSize() {
		return nil, nil, errDecrypt
	}
	der, err := aead.Open(nil, nonce, ct, []byte(f.RootSHA256))
	if err != nil {
		return nil, nil, errDecrypt
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	clear(der)
	if err != nil {
		return nil, nil, errors.New("ключ в резервной копии не разбирается")
	}
	ec, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("ключ в резервной копии — не ECDSA")
	}
	if !KeyMatches(root, ec) {
		return nil, nil, errors.New("ключ в резервной копии не соответствует корневому сертификату")
	}
	return encodeCert(root.Raw), ec, nil
}

func backupAEAD(passphrase string, salt []byte, iter int) (cipher.AEAD, error) {
	k, err := pbkdf2.Key(sha256.New, passphrase, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	clear(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
