VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export GOMAXPROCS ?= 4

.PHONY: web server payload desktop test vet release plugin plugin-publish

web:
	@if [ -f web/package.json ]; then cd web && npm ci && npm run build; else echo "web/package.json нет — пропуск"; fi

server:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o build/bin/hestia ./cmd/hestia

# The desktop build carries the static linux/amd64 server binary (used to
# install Hestia on a server). It is built without the desktop tag, so it does
# not embed itself; the old copy is removed first for the same reason.
payload:
	rm -f internal/selfinstall/payload/hestia-linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o internal/selfinstall/payload/hestia-linux-amd64 ./cmd/hestia

desktop: payload
	go build -tags desktop,gtk3 -ldflags '$(LDFLAGS)' -o build/bin/hestia-desktop ./cmd/hestia

test:
	go test -race -count=1 ./...

# release builds, signs and publishes VERSION (a tag on HEAD), e.g.
#   make release VERSION=v0.1.0
# It needs the release key (hestia-release keygen) and `gh auth login`; without
# gh authentication it stops before publishing and leaves the files in dist/.
# dist/plugins (plugin packages) lives next to the release files and is kept.
RELEASE_ASSETS = dist/hestia-linux-amd64 dist/hestia-desktop-linux-amd64 dist/SHA256SUMS dist/SHA256SUMS.sig

release:
	@case "$(VERSION)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "VERSION=vX.Y.Z обязателен"; exit 1;; esac
	@test -z "$$(git status --porcelain)" || { echo "рабочее дерево не чистое"; exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse '$(VERSION)^{commit}')" || { echo "HEAD не совпадает с тегом $(VERSION)"; exit 1; }
	go vet ./... && go test -race -count=1 ./...
	mkdir -p dist && find dist -maxdepth 1 -type f -delete
	$(MAKE) web server payload VERSION=$(VERSION)
	cp build/bin/hestia dist/hestia-linux-amd64
	$(MAKE) desktop VERSION=$(VERSION)
	cp build/bin/hestia-desktop dist/hestia-desktop-linux-amd64
	go run ./cmd/hestia-release sign dist
	go run ./cmd/hestia-release verify dist
	@if gh auth status >/dev/null 2>&1; then \
		gh release create $(VERSION) $(RELEASE_ASSETS) --verify-tag --notes-from-tag || gh release create $(VERSION) $(RELEASE_ASSETS) --verify-tag --generate-notes; \
	else echo "gh не авторизован: релиз собран в dist/, публикация пропущена"; fi

# ---- plugins ----
# PLUGIN_KEY signs official plugins and the catalog (hestia-release
# plugin-keygen); a third-party author passes their own key.
PLUGIN_KEY ?= $(HOME)/.config/hestia/plugins.key
PLUGIN_PKG = dist/plugins/$(ID)-$(VERSION)-linux-amd64.hpkg
CATALOG_TAG = plugins-catalog

define plugin_args
	@test -n "$(ID)" && test -d plugins/$(ID) || { echo "ID=<id> обязателен (каталог plugins/<id>)"; exit 1; }
	@case "$(VERSION)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "VERSION=vX.Y.Z обязателен (как в plugins/$(ID)/manifest.json)"; exit 1;; esac
endef

# plugin builds and signs a plugin package, e.g.
#   make plugin ID=hestia-hello VERSION=v0.3.0
#   make plugin ID=hestia-probe VERSION=v0.1.0
# VERSION must match manifest.json (plugin-pack checks it).
plugin:
	$(plugin_args)
	mkdir -p build/plugins/$(ID) dist/plugins
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o build/plugins/$(ID)/plugin ./plugins/$(ID)
	go run ./cmd/hestia-release plugin-pack --key '$(PLUGIN_KEY)' --dir build/plugins/$(ID) --src plugins/$(ID) --out dist/plugins --version $(VERSION)
	go run ./cmd/hestia-release plugin-verify $(PLUGIN_PKG)

# plugin-publish tags HEAD as plugin/<id>/<version> (clean tree only), adds the
# package to the catalog (index.json from the release, if there is one) and
# uploads the package, index.json and index.json.sig to the release
# "plugins-catalog" (created as a pre-release, so it never becomes "latest"
# for the Hestia update check). Only on the maintainer's word.
plugin-publish:
	$(plugin_args)
	@test -z "$$(git status --porcelain)" || { echo "рабочее дерево не чистое"; exit 1; }
	@gh auth status >/dev/null 2>&1 || { echo "gh не авторизован (gh auth login)"; exit 1; }
	$(MAKE) plugin ID=$(ID) VERSION=$(VERSION)
	@if git rev-parse -q --verify 'refs/tags/plugin/$(ID)/$(VERSION)' >/dev/null; then \
		test "$$(git rev-parse 'plugin/$(ID)/$(VERSION)^{commit}')" = "$$(git rev-parse HEAD)" || { echo "тег plugin/$(ID)/$(VERSION) указывает не на HEAD"; exit 1; }; \
	else git tag -a 'plugin/$(ID)/$(VERSION)' -m '$(ID) $(VERSION)' HEAD; fi
	git push origin 'refs/tags/plugin/$(ID)/$(VERSION)'
	@gh release view $(CATALOG_TAG) >/dev/null 2>&1 || \
		gh release create $(CATALOG_TAG) --prerelease --latest=false --title 'Каталог плагинов Hestia' \
			--notes 'Официальные плагины Hestia: index.json (подписан ключом плагинов) и пакеты .hpkg.'
	rm -f dist/plugins/index.json dist/plugins/index.json.sig
	@if gh release view $(CATALOG_TAG) --json assets -q '.assets[].name' | grep -qx index.json; then \
		gh release download $(CATALOG_TAG) -p index.json -D dist/plugins; fi
	go run ./cmd/hestia-release catalog-add --index dist/plugins/index.json --key '$(PLUGIN_KEY)' $(PLUGIN_PKG)
	gh release upload $(CATALOG_TAG) $(PLUGIN_PKG) dist/plugins/index.json dist/plugins/index.json.sig --clobber
