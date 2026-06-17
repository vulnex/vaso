BINARY := vaso-probe
# Pin the embedded version to package.json (not `git describe`) so the build is
# independent of tag/commit state: the binary hashed into checksums.json and the
# binary uploaded as a release asset are byte-identical regardless of when, in
# the release sequence, `make checksums` runs.
VERSION := $(shell node -p "require('../package.json').version" 2>/dev/null || git describe --tags --always 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all clean test checksums

all: dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 dist/$(BINARY)-darwin-amd64 dist/$(BINARY)-darwin-arm64

# Release artifacts: a SHA256SUMS asset (for the release page) plus
# ../probe/checksums.json, which ships in the npm package so the runtime fetcher
# verifies a downloaded probe against a digest baked into the CLI version.
# Run during release prep on the SAME binaries you upload as release assets.
checksums: all
	cd dist && shasum -a 256 $(BINARY)-* > SHA256SUMS
	node ../scripts/gen-probe-checksums.mjs

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
