VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export GOMAXPROCS ?= 4

.PHONY: web server payload desktop test vet release

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
release:
	@case "$(VERSION)" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "VERSION=vX.Y.Z обязателен"; exit 1;; esac
	@test -z "$$(git status --porcelain)" || { echo "рабочее дерево не чистое"; exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse '$(VERSION)^{commit}')" || { echo "HEAD не совпадает с тегом $(VERSION)"; exit 1; }
	go vet ./... && go test -race -count=1 ./...
	mkdir -p dist && $(RM) dist/*
	$(MAKE) web server payload VERSION=$(VERSION)
	cp build/bin/hestia dist/hestia-linux-amd64
	$(MAKE) desktop VERSION=$(VERSION)
	cp build/bin/hestia-desktop dist/hestia-desktop-linux-amd64
	go run ./cmd/hestia-release sign dist
	go run ./cmd/hestia-release verify dist
	@if gh auth status >/dev/null 2>&1; then \
		gh release create $(VERSION) dist/* --verify-tag --notes-from-tag || gh release create $(VERSION) dist/* --verify-tag --generate-notes; \
	else echo "gh не авторизован: релиз собран в dist/, публикация пропущена"; fi
