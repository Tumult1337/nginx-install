BINARY  := nginx-gen
PREFIX  ?= /usr/local
GOFLAGS := -trimpath -ldflags="-s -w"

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
