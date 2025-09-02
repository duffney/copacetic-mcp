# Makefile for copacetic-mcp

# Build information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Targets
.PHONY: all build build-server build-client clean test fmt vet release-snapshot help

all: build

build: build-server build-client ## Build both server and client

build-server: ## Build the MCP server
	@echo "Building copacetic-mcp-server..."
	@go build -ldflags "$(LDFLAGS)" -o bin/copacetic-mcp-server .

build-client: ## Build the test client
	@echo "Building copacetic-mcp-client..."
	@go build -o bin/copacetic-mcp-client ./cmd/client

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/ dist/

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

fmt: ## Format Go code
	@echo "Formatting code..."
	@go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

release-snapshot: ## Create a snapshot release with GoReleaser
	@echo "Creating snapshot release..."
	@goreleaser release --snapshot --clean

cross-compile: ## Cross-compile for all platforms
	@echo "Cross-compiling for all platforms..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/copacetic-mcp-server-linux-amd64 .
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/copacetic-mcp-server-linux-arm64 .
	@GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/copacetic-mcp-server-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/copacetic-mcp-server-darwin-arm64 .
	@GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/copacetic-mcp-server-windows-amd64.exe .

help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
