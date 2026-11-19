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

	"github.com/uxerror/hestia/internal/plugins"
	"github.com/uxerror/hestia/internal/update"
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

  plugin-keygen [--out ~/.config/hestia/plugins.key] [--pub internal/plugins/official.pub]
         создать ключ подписи плагинов (то же, что keygen; сторонний автор
         указывает --pub для своего файла)
  plugin-pack [--key ~/.config/hestia/plugins.key] --dir build/plugins/<id>
              [--src plugins/<id>] [--out dist/plugins]
         собрать и подписать <id>-<версия>-linux-amd64.hpkg: plugin из --dir,
         manifest.json, icon.svg, README.md из --dir или --src
  plugin-verify [--pub internal/plugins/official.pub] <file.hpkg>
         проверить пакет тем же кодом, что и контроллер
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
	case "plugin-keygen":
		err = keygenWith(args[1:], defaultPluginKey(), defaultOfficialPub)
	case "plugin-pack":
		err = pluginPack(args[1:])
	case "plugin-verify":
		err = pluginVerify(args[1:])
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

func keygen(args []string) error { return keygenWith(args, defaultKey(), defaultPub) }

func keygenWith(args []string, defKey, defPub string) error {
	fs_ := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs_.String("out", defKey, "файл закрытого ключа")
	pubPath := fs_.String("pub", defPub, "файл публичного ключа")
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

const defaultOfficialPub = "internal/plugins/official.pub"

func defaultPluginKey() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "hestia", "plugins.key")
	}
	return "plugins.key"
}

func pluginPack(args []string) error {
	fs_ := flag.NewFlagSet("plugin-pack", flag.ContinueOnError)
	key := fs_.String("key", defaultPluginKey(), "файл закрытого ключа автора")
	dir := fs_.String("dir", "", "каталог со сборкой плагина (файл plugin)")
	src := fs_.String("src", "", "каталог с manifest.json, icon.svg, README.md (по умолчанию plugins/<имя --dir>)")
	out := fs_.String("out", "dist/plugins", "куда положить пакет")
	if err := fs_.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("укажите --dir с собранным плагином")
	}
	if *src == "" {
		*src = *dir
		if _, err := os.Stat(filepath.Join(*dir, plugins.FileManifest)); err != nil {
			*src = filepath.Join("plugins", filepath.Base(filepath.Clean(*dir)))
		}
	}
	priv, err := loadKey(*key)
	if err != nil {
		return err
	}
	data, m, err := plugins.PackDir(priv, *dir, *src)
	if err != nil {
		return err
	}
	// The package must pass the controller's own checks.
	if _, err := plugins.ReadPackage(data, ""); err != nil {
		return fmt.Errorf("пакет не пройдёт проверку Hestia: %w", err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	path := filepath.Join(*out, plugins.PackName(m))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Println("пакет:", path)
	return nil
}

func pluginVerify(args []string) error {
	fs_ := flag.NewFlagSet("plugin-verify", flag.ContinueOnError)
	pubPath := fs_.String("pub", defaultOfficialPub, "публичный ключ официальных плагинов")
	if err := fs_.Parse(args); err != nil {
		return err
	}
	if fs_.NArg() != 1 {
		return errors.New("укажите файл .hpkg")
	}
	if b, err := os.ReadFile(*pubPath); err == nil {
		plugins.OfficialPub = strings.TrimSpace(string(b))
	}
	data, err := os.ReadFile(fs_.Arg(0))
	if err != nil {
		return err
	}
	p, err := plugins.ReadPackage(data, "")
	if err != nil {
		return err
	}
	kind := "сторонний"
	if p.Official {
		kind = "официальный"
	}
	fmt.Printf("пакет в порядке: %s %s, автор %s (%s)\nотпечаток ключа: %s\nправа: %s\nsha256: %s\n",
		p.Manifest.ID, p.Manifest.Version, p.Manifest.Author.Name, kind, plugins.Fingerprint(p.Manifest.Author.Key),
		strings.Join(p.Manifest.Permissions, ", "), p.SHA256)
	return nil
}
