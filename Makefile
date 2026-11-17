VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export GOMAXPROCS ?= 4

.PHONY: web server payload desktop test vet

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

vet:
	go vet ./...
	go vet -tags desktop,gtk3 ./...
