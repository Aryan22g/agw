.PHONY: help build test test-python lint fmt vet clean \
        gym gym-sweep gym-contained site dist test-linux conformance image-agw fmt-check staticcheck vulncheck

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/Aryan22g/agw/internal/buildinfo.Version=$(VERSION) \
           -X github.com/Aryan22g/agw/internal/buildinfo.Commit=$(COMMIT) \
           -X github.com/Aryan22g/agw/internal/buildinfo.Date=$(DATE)

# The binaries people install.
DIST_BINS      := agw agw-verify ags
DIST_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

build: ## Build all binaries into ./bin
	@mkdir -p bin
	@for b in agw agw-verify ags ags-signd agw-gym; do \
	  go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$$b ./cmd/$$b || exit 1; done
	@echo "Built into bin/: agw agw-verify ags ags-signd agw-gym ($(VERSION))"

dist: ## Cross-compile release archives and SHA256SUMS into ./dist
	@rm -rf dist && mkdir -p dist
	@for p in $(DIST_PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=""; [ $$os = windows ] && ext=.exe; \
	  dir=dist/agw_$(VERSION)_$${os}_$${arch}; mkdir -p $$dir; \
	  for b in $(DIST_BINS); do \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
	      -o $$dir/$$b$$ext ./cmd/$$b || exit 1; \
	  done; \
	  cp readme.md $$dir/README.md; \
	  tar -C dist -czf $$dir.tar.gz $$(basename $$dir) && rm -rf $$dir; \
	done
	@cd dist && (command -v sha256sum >/dev/null && sha256sum *.tar.gz || shasum -a 256 *.tar.gz) > SHA256SUMS
	@cat dist/SHA256SUMS

test: ## Run all tests
	go test ./...

test-python: ## Run the Python SDK conformance suite against the Go corpus
	python3 sdks/python/tests/test_conformance.py

vet: ## Run go vet
	go vet ./...
	GOOS=linux go vet ./...

fmt-check: ## Fail if any file is not gofmt-clean
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

staticcheck: ## Static analysis (install: go install honnef.co/go/tools/cmd/staticcheck@latest)
	GOOS=linux staticcheck ./...
	@# Off Linux, the containment code's fields are used only by files that do
	@# not build there, so "unused" is a false positive on the host.
	staticcheck -checks inherit,-U1000 ./...

vulncheck: ## Known-vulnerability scan (install: go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

conformance: ## Evidence and AGS1 conformance: corpus, independent verifier, differential search
	go test -count=1 ./internal/gateway/audit/ ./pkg/ags1/vectors/ ./cmd/agw-verify/
	AGW_DIFF_ITERATIONS=$${AGW_DIFF_ITERATIONS:-5000} go test -count=1 -run Differential ./cmd/agw-verify/
	@command -v node >/dev/null && node site/test/conformance.mjs || echo "node not installed: skipped the JavaScript verifier"

site: ## Serve the launch site locally on :8765
	python3 -m http.server 8765 --bind 127.0.0.1 --directory site

test-linux: ## Full suite on Linux as root in Docker, including the containment tests (for macOS)
	docker run --rm --privileged -v "$(CURDIR)":/src -w /src \
	  -v agw-gomod:/go/pkg/mod -v agw-gocache:/root/.cache/go-build golang:1.26 \
	  bash -c 'apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 nftables procps python3 >/dev/null && go test -race -count=1 ./... && ./scripts/killswitch-e2e.sh'

image-agw: ## Build the agw container image
	docker build -f Dockerfile.agw --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) -t agw:$(VERSION) -t agw:latest .

fmt: ## Format all Go source
	gofmt -w .

lint: fmt-check vet staticcheck ## Everything CI checks before the tests

gym: ## Run the adversarial gym once against a generated world
	go run ./cmd/agw-gym run

gym-sweep: ## Run the gym over many generated worlds, reporting only failures
	go run ./cmd/agw-gym sweep --runs 50

gym-contained: ## Run the gym under real network isolation (Docker, slower)
	./gym/contained.sh

clean: ## Remove build output
	rm -rf bin dist
