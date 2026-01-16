.PHONY: build clean test run help deps fmt lint
.PHONY: build-all build-windows build-linux build-macos
.PHONY: build-windows-amd64 build-windows-arm64
.PHONY: build-linux-amd64 build-linux-arm64
.PHONY: build-macos-amd64 build-macos-arm64

# Binary name
BINARY_NAME=pocsuite-go
BUILD_DIR=bin

# Version information
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# Default build for current platform
build:
	@echo "Building $(BINARY_NAME) for current platform..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for all platforms
build-all: build-windows-amd64 build-windows-arm64 build-linux-amd64 build-linux-arm64 build-macos-amd64 build-macos-arm64
	@echo "All builds complete!"

# Windows builds
build-windows: build-windows-amd64 build-windows-arm64

build-windows-amd64:
	@echo "Building $(BINARY_NAME) for Windows amd64..."
	@mkdir -p $(BUILD_DIR)/windows-amd64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/windows-amd64/$(BINARY_NAME).exe main.go
	@echo "Build complete: $(BUILD_DIR)/windows-amd64/$(BINARY_NAME).exe"

build-windows-arm64:
	@echo "Building $(BINARY_NAME) for Windows arm64..."
	@mkdir -p $(BUILD_DIR)/windows-arm64
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/windows-arm64/$(BINARY_NAME).exe main.go
	@echo "Build complete: $(BUILD_DIR)/windows-arm64/$(BINARY_NAME).exe"

# Linux builds
build-linux: build-linux-amd64 build-linux-arm64

build-linux-amd64:
	@echo "Building $(BINARY_NAME) for Linux amd64..."
	@mkdir -p $(BUILD_DIR)/linux-amd64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/linux-amd64/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/linux-amd64/$(BINARY_NAME)"

build-linux-arm64:
	@echo "Building $(BINARY_NAME) for Linux arm64..."
	@mkdir -p $(BUILD_DIR)/linux-arm64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/linux-arm64/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/linux-arm64/$(BINARY_NAME)"

# macOS builds
build-macos: build-macos-amd64 build-macos-arm64

build-macos-amd64:
	@echo "Building $(BINARY_NAME) for macOS amd64..."
	@mkdir -p $(BUILD_DIR)/darwin-amd64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/darwin-amd64/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/darwin-amd64/$(BINARY_NAME)"

build-macos-arm64:
	@echo "Building $(BINARY_NAME) for macOS arm64 (Apple Silicon)..."
	@mkdir -p $(BUILD_DIR)/darwin-arm64
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/darwin-arm64/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/darwin-arm64/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)/
	@echo "Clean complete!"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run the application
run:
	@echo "Running $(BINARY_NAME)..."
	go run main.go

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy
	@echo "Dependencies installed!"

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "Code formatted!"

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Create release packages
release: build-all
	@echo "Creating release packages..."
	@cd $(BUILD_DIR) && \
	for dir in */; do \
		platform=$${dir%/}; \
		if [ "$$platform" = "windows-amd64" ] || [ "$$platform" = "windows-arm64" ]; then \
			zip -r $(BINARY_NAME)-$$platform-$(VERSION).zip $$platform; \
		else \
			tar -czf $(BINARY_NAME)-$$platform-$(VERSION).tar.gz $$platform; \
		fi \
	done
	@echo "Release packages created in $(BUILD_DIR)/"

# Help
help:
	@echo "Pocsuite-Go Makefile"
	@echo ""
	@echo "Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build              - Build for current platform"
	@echo "  build-all          - Build for all platforms (Windows/Linux/macOS)"
	@echo "  build-windows      - Build for all Windows platforms"
	@echo "  build-linux        - Build for all Linux platforms"
	@echo "  build-macos        - Build for all macOS platforms"
	@echo "  build-windows-amd64   - Build for Windows amd64"
	@echo "  build-windows-arm64   - Build for Windows arm64"
	@echo "  build-linux-amd64     - Build for Linux amd64"
	@echo "  build-linux-arm64     - Build for Linux arm64"
	@echo "  build-macos-amd64     - Build for macOS amd64"
	@echo "  build-macos-arm64     - Build for macOS arm64 (Apple Silicon)"
	@echo ""
	@echo "Other targets:"
	@echo "  clean              - Clean build artifacts"
	@echo "  test               - Run tests"
	@echo "  run                - Run the application"
	@echo "  deps               - Install dependencies"
	@echo "  fmt                - Format code"
	@echo "  lint               - Run linter"
	@echo "  release            - Create release packages"
	@echo "  help               - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build-all              # Build for all platforms"
	@echo "  make build-windows-amd64    # Build for Windows 64-bit"
	@echo "  make build-macos-arm64      # Build for Apple Silicon"
	@echo "  make release                # Create release packages"
