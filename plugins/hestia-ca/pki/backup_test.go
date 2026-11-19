package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

const testIter = 1000

const testPass = "correct horse battery"

func init() { minImportIter = testIter }

func exportTest(t *testing.T, ca testCA) []byte {
	t.Helper()
	b, err := ExportBackup(ca.pem, ca.key, testPass, testIter, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBackupRoundTrip(t *testing.T) {
	ca := newTestCA(t, "home", DefaultIPRanges)
	data := exportTest(t, ca)
	var f map[string]any
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"format", "v", "root_pem", "root_sha256", "kdf", "iter", "salt", "nonce", "ct", "created"} {
		if _, ok := f[k]; !ok {
			t.Errorf("field %s missing", k)
		}
	}
	if f["format"] != "hestia-ca-backup" || f["kdf"] != "pbkdf2-sha256" || f["v"] != 1.0 || f["root_sha256"] != Fingerprint(ca.cert.Raw) || f["created"] != "2026-11-20T12:00:00Z" {
		t.Errorf("header %v", f)
	}
	keyPEM, _ := EncodeKeyPEM(ca.key)
	if bytes.Contains(data, []byte(testPass)) || bytes.Contains(data, keyPEM) || bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatal("backup leaks the passphrase or key")
	}
	root, key, err := ImportBackup(data, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, ca.pem) || !key.Equal(ca.key) {
		t.Fatal("round trip differs")
	}
	if _, err := ExportBackup(ca.pem, ca.key, "short", testIter, testNow); err == nil {
		t.Error("short passphrase accepted")
	}
	other := newTestCA(t, "home", "")
	if _, err := ExportBackup(ca.pem, other.key, testPass, testIter, testNow); err == nil {
		t.Error("foreign key exported")
	}
}

func checkImportErr(t *testing.T, what string, data []byte, pass string, ca testCA) {
	t.Helper()
	_, _, err := ImportBackup(data, pass)
	if err == nil {
		t.Errorf("%s: import succeeded", what)
		return
	}
	keyPEM, _ := EncodeKeyPEM(ca.key)
	msg := err.Error()
	if strings.Contains(msg, testPass) || strings.Contains(msg, pass) && pass != "" || strings.Contains(msg, string(keyPEM)) {
		t.Errorf("%s: error leaks secrets: %s", what, msg)
	}
}

func TestBackupRejects(t *testing.T) {
	ca := newTestCA(t, "home", "")
	data := exportTest(t, ca)

	_, _, err := ImportBackup(data, "wrong passphrase!")
	if err == nil || err.Error() != "неверный пароль или повреждённый файл" {
		t.Errorf("wrong passphrase: %v", err)
	}
	checkImportErr(t, "wrong passphrase", data, "wrong passphrase!", ca)

	var f backupFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	edit := func(mod func(*backupFile)) []byte {
		g := f
		mod(&g)
		b, _ := json.Marshal(g)
		return b
	}
	b64 := base64.StdEncoding
	for _, field := range []string{"salt", "nonce", "ct"} {
		var src string
		switch field {
		case "salt":
			src = f.Salt
		case "nonce":
			src = f.Nonce
		case "ct":
			src = f.CT
		}
		raw, _ := b64.DecodeString(src)
		for i := range raw {
			c := bytes.Clone(raw)
			c[i] ^= 0x01
			enc := b64.EncodeToString(c)
			data := edit(func(g *backupFile) {
				switch field {
				case "salt":
					g.Salt = enc
				case "nonce":
					g.Nonce = enc
				case "ct":
					g.CT = enc
				}
			})
			if _, _, err := ImportBackup(data, testPass); err == nil || err.Error() != "неверный пароль или повреждённый файл" {
				t.Fatalf("%s byte %d corrupted: %v", field, i, err)
			}
		}
	}

	other := newTestCA(t, "home", "")
	otherData := exportTest(t, other)
	var g backupFile
	_ = json.Unmarshal(otherData, &g)
	// Key of another root under this root's header: AAD mismatch.
	checkImportErr(t, "key of another root", edit(func(h *backupFile) { h.CT, h.Nonce, h.Salt = g.CT, g.Nonce, g.Salt }), testPass, ca)
	// Root swapped (with matching sha) but ciphertext for the old root.
	checkImportErr(t, "root swapped", edit(func(h *backupFile) { h.RootPEM, h.RootSHA256 = g.RootPEM, g.RootSHA256 }), testPass, ca)
	checkImportErr(t, "root pem without sha", edit(func(h *backupFile) { h.RootPEM = g.RootPEM }), testPass, ca)
	checkImportErr(t, "format", edit(func(h *backupFile) { h.Format = "other" }), testPass, ca)
	checkImportErr(t, "version", edit(func(h *backupFile) { h.V = 2 }), testPass, ca)
	checkImportErr(t, "kdf", edit(func(h *backupFile) { h.KDF = "scrypt" }), testPass, ca)
	checkImportErr(t, "low iter", edit(func(h *backupFile) { h.Iter = 10 }), testPass, ca)
	checkImportErr(t, "iter changed", edit(func(h *backupFile) { h.Iter = testIter + 1 }), testPass, ca)
	checkImportErr(t, "not json", []byte("-----BEGIN PRIVATE KEY-----"), testPass, ca)
	checkImportErr(t, "empty", nil, testPass, ca)
}

func TestBackupRejectsNonLeafOnlyRoot(t *testing.T) {
	// A root that may sign intermediates is refused even with a valid key.
	key := ecKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "wide"},
		NotBefore: testNow, NotAfter: testNow.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wide := testCA{pem: encodeCert(der), key: key}
	data := exportTest(t, wide)
	if _, _, err := ImportBackup(data, testPass); err == nil || !strings.Contains(err.Error(), "MaxPathLen 0") {
		t.Fatalf("wide root: %v", err)
	}
}
