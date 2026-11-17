VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export GOMAXPROCS ?= 4

.PHONY: web server desktop test vet

web:
	@if [ -f web/package.json ]; then cd web && npm ci && npm run build; else echo "web/package.json нет — пропуск"; fi

server:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o build/bin/hestia ./cmd/hestia

desktop:
	go build -tags desktop,gtk3 -ldflags '$(LDFLAGS)' -o build/bin/hestia-desktop ./cmd/hestia

test:
	go test -race -count=1 ./...

vet:
	go vet ./...
	go vet -tags desktop,gtk3 ./...
