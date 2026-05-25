BINARY  := nginx-gen
PREFIX  ?= /usr/local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -trimpath -ldflags="-s -w -X main.toolVersion=$(VERSION)"

.PHONY: all build test vet race clean install

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BINARY) ./cmd/nginx

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
