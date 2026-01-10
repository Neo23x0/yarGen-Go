# Makefile for yarGen-Go
# Builds all binaries and provides common development tasks

.PHONY: all build clean test tidy fmt vet lint help install release-build

# Binary names
BINARY_YARGEN := yargen
BINARY_UTIL := yargen-util

# Build directory
BUILD_DIR := bin

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet

# Version and build info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# LDFLAGS for version injection
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# Default target
all: clean build

# Build all binaries
build: $(BUILD_DIR)/$(BINARY_YARGEN) $(BUILD_DIR)/$(BINARY_UTIL)

# Build yargen binary
$(BUILD_DIR)/$(BINARY_YARGEN):
	@echo "Building $(BINARY_YARGEN)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_YARGEN) ./cmd/yargen

# Build yargen-util binary
$(BUILD_DIR)/$(BINARY_UTIL):
	@echo "Building $(BINARY_UTIL)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_UTIL) ./cmd/yargen-util

# Build for current platform (local install)
install:
	@echo "Installing binaries to GOPATH/bin..."
	$(GOBUILD) $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_YARGEN) ./cmd/yargen
	$(GOBUILD) $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_UTIL) ./cmd/yargen-util

# Cross-platform builds
release-build: clean
	@echo "Building release binaries for all platforms..."
	@mkdir -p $(BUILD_DIR)/release
	
	# Linux
	@echo "Building for linux/amd64..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_YARGEN)-linux-amd64 ./cmd/yargen
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_UTIL)-linux-amd64 ./cmd/yargen-util
	
	@echo "Building for linux/arm64..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_YARGEN)-linux-arm64 ./cmd/yargen
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_UTIL)-linux-arm64 ./cmd/yargen-util
	
	# macOS
	@echo "Building for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_YARGEN)-darwin-amd64 ./cmd/yargen
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_UTIL)-darwin-amd64 ./cmd/yargen-util
	
	@echo "Building for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_YARGEN)-darwin-arm64 ./cmd/yargen
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_UTIL)-darwin-arm64 ./cmd/yargen-util
	
	# Windows
	@echo "Building for windows/amd64..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_YARGEN)-windows-amd64.exe ./cmd/yargen
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_UTIL)-windows-amd64.exe ./cmd/yargen-util
	
	@echo "Build complete! Binaries are in $(BUILD_DIR)/release/"

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

# Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install it from https://golangci-lint.run/"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Run all checks (format, vet, test)
check: fmt vet test

# Show help
help:
	@echo "Available targets:"
	@echo "  make              - Clean and build all binaries"
	@echo "  make build        - Build all binaries"
	@echo "  make install      - Install binaries to GOPATH/bin"
	@echo "  make release-build - Build binaries for all platforms"
	@echo "  make test         - Run tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make deps         - Download and tidy dependencies"
	@echo "  make fmt          - Format code"
	@echo "  make vet          - Run go vet"
	@echo "  make lint         - Run golangci-lint (if installed)"
	@echo "  make check        - Run fmt, vet, and test"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make help         - Show this help message"
