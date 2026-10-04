VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build release test bench run clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/heimdalldns ./cmd/heimdalldns

# Binários estáticos para servidores e Raspberry Pi.
release:
	for arch in amd64 arm64 arm; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o bin/heimdalldns-linux-$$arch ./cmd/heimdalldns; \
	done

test:
	go vet ./...
	go test -race ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

# Roda local sem root, numa porta alta.
run: build
	./bin/heimdalldns -config heimdalldns.example.yaml -listen 127.0.0.1:25353 -data-dir ./data

clean:
	rm -rf bin data
