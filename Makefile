# wafgo — build, test and release helpers.
BINARY      := wafgo
PKG         := github.com/miglen/wafgo
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X $(PKG).Version=$(VERSION)
GOFLAGS     := -trimpath
WAFW00F_SRC ?= ../wafw00f   # checkout of EnableSecurity/wafw00f for `make generate`

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the wafgo binary
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/wafgo

.PHONY: install
install: ## Install wafgo into GOBIN
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/wafgo

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: race
race: ## Run tests with the race detector
	go test -race ./...

.PHONY: cover
cover: ## Run tests and open a coverage report
	go test -coverprofile=cover.out ./...
	go tool cover -func=cover.out | tail -1

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format the code
	gofmt -w .

.PHONY: lint
lint: vet ## Lint (vet + gofmt check)
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "run 'make fmt'"; exit 1)

.PHONY: generate
generate: ## Regenerate signatures from upstream (set WAFW00F_SRC=/path/to/wafw00f)
	python3 -I tools/py2go/py2go.py $(WAFW00F_SRC) plugins
	python3 -I tools/parity/gen_parity.py $(WAFW00F_SRC) testdata/parity.json
	python3 -I tools/nuclei2go/nuclei2go.py testdata/nuclei-waf-detect.yaml plugins/nuclei_gen.go
	gofmt -w plugins
	go test ./...

.PHONY: docker
docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) -t $(BINARY):latest .

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY) cover.out

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
