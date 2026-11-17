// Command hestia-release creates the release key and signs/verifies release
// assets. It is a maintainer tool and is not part of the Hestia binary.
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"hestia/internal/update"
)

func main() { os.Exit(run(os.Args[1:])) }

func usage() {
	fmt.Fprint(os.Stderr, `Использование: hestia-release <команда>

  keygen [--out ~/.config/hestia/release.key] [--pub internal/update/release.pub]
         создать ключ релиза (отказ, если файл уже есть)
  sign   [--key ~/.config/hestia/release.key] <dir>
         посчитать SHA256SUMS и подписать его
  verify [--pub internal/update/release.pub] <dir>
         проверить релиз тем же кодом, что и контроллер
`)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = keygen(args[1:])
	case "sign":
		err = sign(args[1:])
	case "verify":
		err = verify(args[1:])
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		return 1
	}
	return 0
}

func defaultKey() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "hestia", "release.key")
	}
	return "release.key"
}

const defaultPub = "internal/update/release.pub"

func keygen(args []string) error {
	fs_ := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs_.String("out", defaultKey(), "файл закрытого ключа")
	pubPath := fs_.String("pub", defaultPub, "файл публичного ключа")
	if err := fs_.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s уже существует — ключ не перезаписывается", *out)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	pub, priv, err := update.GenerateKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return err
	}
	// O_EXCL: never overwrite a key that appeared in the meantime.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(update.EncodePrivateKey(priv)); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	enc := update.EncodePublicKey(pub)
	if err := os.WriteFile(*pubPath, []byte(enc+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Println("закрытый ключ:", *out)
	fmt.Println("публичный ключ записан в", *pubPath)
	fmt.Println(enc)
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return update.ParsePrivateKey(b)
}

func sign(args []string) error {
	fs_ := flag.NewFlagSet("sign", flag.ContinueOnError)
	key := fs_.String("key", defaultKey(), "файл закрытого ключа")
	if err := fs_.Parse(args); err != nil {
		return err
	}
	if fs_.NArg() != 1 {
		return errors.New("укажите каталог с файлами релиза")
	}
	priv, err := loadKey(*key)
	if err != nil {
		return err
	}
	if err := update.SignDir(priv, fs_.Arg(0)); err != nil {
		return err
	}
	fmt.Println("подписано:", filepath.Join(fs_.Arg(0), update.SumsName))
	return nil
}

func verify(args []string) error {
	fs_ := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubPath := fs_.String("pub", defaultPub, "файл публичного ключа")
	if err := fs_.Parse(args); err != nil {
		return err
	}
	if fs_.NArg() != 1 {
		return errors.New("укажите каталог с файлами релиза")
	}
	b, err := os.ReadFile(*pubPath)
	if err != nil {
		return err
	}
	pub, err := update.ParsePublicKey(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	if err := update.VerifyDir(pub, fs_.Arg(0)); err != nil {
		return err
	}
	fmt.Println("релиз в порядке: подпись и контрольные суммы верны")
	return nil
}
