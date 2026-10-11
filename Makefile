BINARY  := tpm2-kira-vault
PREFIX  ?= /usr
UNITDIR ?= /usr/lib/systemd/system

.PHONY: build test test-integration vet fmt install clean

build:
	CGO_ENABLED=0 go build -trimpath -o $(BINARY) .

test:
	go test ./...

# Needs swtpm.
test-integration:
	go test -count=1 -tags integration ./...

vet:
	go vet ./...
	go vet -tags integration ./...

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

install: build
	install -Dm0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -Dm0644 packaging/tpm2-kira-vault.service $(DESTDIR)$(UNITDIR)/tpm2-kira-vault.service

clean:
	rm -f $(BINARY)
