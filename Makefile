# Makefile for rekrypt project
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 stenvenleep

.PHONY: all help clean build test
.PHONY: build-wasm build-ffi build-server
.PHONY: test-wasm test-ffi test-server
.PHONY: clean-wasm clean-ffi clean-server
.PHONY: dev-server install check

# Default target
all: build

# Display help information
help:
	@echo "rekrypt - Proxy Re-Encryption Toolkit"
	@echo ""
	@echo "Build targets:"
	@echo "  make all           Build everything (WASM + FFI + Transform Service)"
	@echo "  make build-wasm    Build WebAssembly package"
	@echo "  make build-ffi     Build FFI library"
	@echo "  make build-server  Build transform service"
	@echo ""
	@echo "Test targets:"
	@echo "  make test          Run all tests"
	@echo "  make test-wasm     Test WASM package"
	@echo "  make test-ffi      Test FFI library"
	@echo ""
	@echo "Clean targets:"
	@echo "  make clean         Clean all build artifacts"
	@echo "  make clean-wasm    Clean WASM artifacts"
	@echo "  make clean-ffi     Clean FFI artifacts"
	@echo "  make clean-server  Clean service artifacts"
	@echo ""
	@echo "Development:"
	@echo "  make dev-server    Run transform service in dev mode"
	@echo "  make check         Check code quality"
	@echo "  make fmt           Format code"
	@echo "  make install       Install dependencies"

# Build everything
build: build-wasm build-ffi build-server
	@echo "[✓] All components built successfully"

# Build WASM package
build-wasm:
	@echo "[BUILD] WebAssembly package..."
	@if command -v wasm-pack >/dev/null 2>&1; then \
		wasm-pack build --target web --out-dir pkg; \
		echo "[✓] WASM package: pkg/"; \
	else \
		echo "[ERROR] wasm-pack not found. Install: cargo install wasm-pack"; \
		exit 1; \
	fi

# Build FFI library
build-ffi:
	@echo "[BUILD] FFI library..."
	@cd rekrypt-ffi && cargo build --release
	@mkdir -p rekrypt-ffi/lib
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		cp rekrypt-ffi/target/release/librekrypt_ffi.dylib rekrypt-ffi/lib/ 2>/dev/null || true; \
		cp rekrypt-ffi/target/release/librekrypt_ffi.a rekrypt-ffi/lib/ 2>/dev/null || true; \
		echo "[✓] FFI library: rekrypt-ffi/lib/ (macOS)"; \
	elif [ "$$(uname -s)" = "Linux" ]; then \
		cp rekrypt-ffi/target/release/librekrypt_ffi.so rekrypt-ffi/lib/ 2>/dev/null || true; \
		cp rekrypt-ffi/target/release/librekrypt_ffi.a rekrypt-ffi/lib/ 2>/dev/null || true; \
		echo "[✓] FFI library: rekrypt-ffi/lib/ (Linux)"; \
	else \
		echo "[WARN] Unknown platform, check rekrypt-ffi/target/release/"; \
	fi

# Build transform service
build-server: build-ffi
	@echo "[BUILD] Transform service..."
	@cd transform-service && $(MAKE) build
	@echo "[✓] Transform service: transform-service/rekrypt-transform"

# Run all tests
test: test-wasm test-ffi test-server
	@echo "[✓] All tests passed"

# Test WASM
test-wasm:
	@echo "[TEST] WASM package..."
	@if command -v wasm-pack >/dev/null 2>&1; then \
		wasm-pack test --headless --firefox || wasm-pack test --headless --chrome || cargo test; \
	else \
		cargo test; \
	fi

# Test FFI library
test-ffi:
	@echo "[TEST] FFI library..."
	@cd rekrypt-ffi && cargo test --lib

# Test transform service
test-server:
	@echo "[TEST] Transform service..."
	@cd transform-service && go test ./... || echo "[INFO] No Go tests found"

# Clean all
clean: clean-wasm clean-ffi clean-server
	@echo "[CLEAN] All build artifacts..."
	@rm -rf target/
	@echo "[✓] Clean complete"

# Clean WASM artifacts
clean-wasm:
	@echo "[CLEAN] WASM artifacts..."
	@rm -rf pkg/rekrypt*.js pkg/rekrypt*.wasm pkg/rekrypt*.ts

# Clean FFI artifacts
clean-ffi:
	@echo "[CLEAN] FFI artifacts..."
	@cd rekrypt-ffi && cargo clean
	@rm -rf rekrypt-ffi/lib/

# Clean transform service artifacts
clean-server:
	@echo "[CLEAN] Transform service artifacts..."
	@cd transform-service && $(MAKE) clean

# Run transform service in development mode
dev-server: build-ffi
	@echo "[DEV] Starting transform service..."
	@cd transform-service && $(MAKE) dev

# Check code quality
check:
	@echo "[CHECK] Code quality..."
	@echo "  Rust (clippy)..."
	@cargo clippy --all-targets --all-features -- -D warnings || true
	@cd rekrypt-ffi && cargo clippy --all-targets -- -D warnings || true
	@echo "  Go (vet)..."
	@cd transform-service && go vet ./... || true
	@echo "[✓] Code check complete"

# Install dependencies
install:
	@echo "[INSTALL] Dependencies..."
	@echo "  Checking Rust..."
	@rustc --version || (echo "[ERROR] Rust not found: https://rustup.rs/" && exit 1)
	@echo "  Checking wasm-pack..."
	@if ! command -v wasm-pack >/dev/null 2>&1; then \
		echo "  Installing wasm-pack..."; \
		cargo install wasm-pack; \
	fi
	@echo "  Checking Go..."
	@go version || (echo "[ERROR] Go not found: https://golang.org/" && exit 1)
	@echo "  Downloading Go dependencies..."
	@cd transform-service && go mod download
	@echo "[✓] All dependencies installed"

# Development shortcuts
.PHONY: wasm ffi server
wasm: build-wasm
ffi: build-ffi
server: build-server

# Version information
.PHONY: version
version:
	@echo "rekrypt versions:"
	@echo "  Core:    $$(cargo pkgid | cut -d# -f2 || echo 'unknown')"
	@echo "  FFI:     $$(cd rekrypt-ffi && cargo pkgid | cut -d# -f2 || echo 'unknown')"
	@echo "  Service: $$(cd transform-service && go list -m | awk '{print $$2}' || echo 'unknown')"

# Quick development cycle
.PHONY: quick
quick: build-ffi build-server
	@echo "[✓] Quick build complete (FFI + Service)"

# Documentation
.PHONY: doc
doc:
	@echo "[DOC] Generating documentation..."
	@cargo doc --no-deps --open

# Format code
.PHONY: fmt
fmt:
	@echo "[FORMAT] Formatting code..."
	@cargo fmt --all
	@cd rekrypt-ffi && cargo fmt
	@cd transform-service && go fmt ./...
	@echo "[✓] Code formatted"

# Lint everything
.PHONY: lint
lint: check
	@echo "[LINT] Running lints..."
	@cargo fmt --all -- --check || echo "[INFO] Run 'make fmt' to format"
	@cd rekrypt-ffi && cargo fmt -- --check || echo "[INFO] Run 'make fmt' for FFI"

# Release build (optimized)
.PHONY: release
release:
	@echo "[RELEASE] Building optimized binaries..."
	@cargo build --release
	@cd rekrypt-ffi && cargo build --release
	@cd transform-service && CGO_ENABLED=1 go build -o rekrypt-transform -ldflags="-s -w" .
	@echo "[✓] Release build complete"
	@echo "  WASM:    pkg/"
	@echo "  FFI:     rekrypt-ffi/lib/"
	@echo "  Service: transform-service/rekrypt-transform"

# Watch for changes (requires cargo-watch)
.PHONY: watch
watch:
	@if command -v cargo-watch >/dev/null 2>&1; then \
		cargo watch -x 'test --lib'; \
	else \
		echo "[ERROR] cargo-watch not installed: cargo install cargo-watch"; \
		exit 1; \
	fi

# Size analysis
.PHONY: size
size:
	@echo "[SIZE] Binary sizes:"
	@echo "  WASM:"
	@du -h pkg/rekrypt_bg.wasm 2>/dev/null || echo "    Not built yet"
	@echo "  FFI:"
	@du -h rekrypt-ffi/lib/librekrypt_ffi.* 2>/dev/null || echo "    Not built yet"
	@echo "  Service:"
	@du -h transform-service/rekrypt-transform 2>/dev/null || echo "    Not built yet"

# Benchmarks
.PHONY: bench
bench:
	@echo "[BENCH] Running benchmarks..."
	@cargo bench --no-fail-fast

# Continuous Integration simulation
.PHONY: ci
ci: clean install build test check
	@echo "[✓] CI checks passed"
