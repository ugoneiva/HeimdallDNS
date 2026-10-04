VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build web web-dev release snapshot test bench run clean

# O painel compilado (internal/webui/dist) vai no repositório: "make build"
# funciona sem Node. Depois de mexer em web/, rode "make web".
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/heimdalldns ./cmd/heimdalldns

web:
	cd web && npm ci && npm run build

# Painel com recarga automática; a API vem de um heimdalldns rodando local.
web-dev:
	cd web && HEIMDALL_API=http://127.0.0.1:8053 npm run dev

# Binários estáticos para servidores e Raspberry Pi.
release:
	for arch in amd64 arm64 arm; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o bin/heimdalldns-linux-$$arch ./cmd/heimdalldns; \
	done

# Pacotes .deb, .rpm e Arch e os .tar.gz em dist/, sem publicar (precisa do
# goreleaser: go install github.com/goreleaser/goreleaser/v2@latest).
snapshot:
	goreleaser release --snapshot --clean --skip=docker,sign,sbom

test:
	go vet ./...
	go test -race ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

# Roda local sem root, numa porta alta.
run: build
	./bin/heimdalldns -config heimdalldns.example.yaml -listen 127.0.0.1:25353 -data-dir ./data

clean:
	rm -rf bin data dist
