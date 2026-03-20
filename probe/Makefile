BINARY := vaso-probe
VERSION := $(shell git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all clean test

all: dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 dist/$(BINARY)-darwin-amd64 dist/$(BINARY)-darwin-arm64

dist/$(BINARY)-linux-amd64:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $@ .

dist/$(BINARY)-linux-arm64:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $@ .

dist/$(BINARY)-darwin-amd64:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $@ .

dist/$(BINARY)-darwin-arm64:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $@ .

test:
	go test ./...

clean:
	rm -rf dist/
