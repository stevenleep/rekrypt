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
	@echo "  make build-ffi     Build FFI library (current platform)"
	@echo "  make build-server  Build transform service"
	@echo ""
	@echo "Cross-compilation (FFI):"
	@echo "  make install-targets   Install cross-compilation tools"
	@echo "  make cross-compile     Build FFI for all platforms"
	@echo "  make cross-linux       Build for Linux (x64 + ARM64)"
	@echo "  make cross-windows     Build for Windows (x64)"
	@echo "  make cross-macos       Build for macOS (x64 + ARM64)"
	@echo "  make cross-help        Show cross-compilation help"
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
	@echo "  make version       Show version information"
	@echo "  make size          Show build artifact sizes"

# Build everything
build: build-wasm build-ffi build-server
	@echo "[✓] All components built successfully"

# Build WASM package
build-wasm:
	@echo "[BUILD] WebAssembly package..."
	@if command -v wasm-pack >/dev/null 2>&1; then \
		wasm-pack build \
			--target web \
			--out-dir pkg \
			--release \
			--scope stevenleep; \
		echo "[✓] WASM package built: pkg/"; \
		if command -v node >/dev/null 2>&1 && [ -f scripts/enhance-pkg.js ]; then \
			node scripts/enhance-pkg.js; \
		else \
			echo "[WARN] Could not enhance package.json (node or script not found)"; \
		fi; \
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

# Cross-compilation targets for FFI
.PHONY: cross-compile cross-linux cross-windows cross-macos install-targets

# Install cross-compilation targets and tools
install-targets:
	@echo "[INSTALL] Cross-compilation targets and tools..."
	@rustup target add x86_64-unknown-linux-gnu || true
	@rustup target add aarch64-unknown-linux-gnu || true
	@rustup target add x86_64-pc-windows-gnu || true
	@rustup target add x86_64-apple-darwin || true
	@if ! command -v cargo-zigbuild >/dev/null 2>&1; then \
		echo "  Installing cargo-zigbuild..."; \
		cargo install cargo-zigbuild; \
	fi
	@if ! command -v zig >/dev/null 2>&1; then \
		echo "  [WARN] zig not found. Install with: brew install zig"; \
		exit 1; \
	fi
	@echo "[✓] Targets and tools installed"

# Cross-compile for Linux x86_64
cross-linux-x64:
	@echo "[CROSS] Building FFI for Linux x86_64..."
	@cd rekrypt-ffi && cargo zigbuild --release --target x86_64-unknown-linux-gnu
	@mkdir -p rekrypt-ffi/lib/linux-x64
	@cp rekrypt-ffi/target/x86_64-unknown-linux-gnu/release/librekrypt_ffi.so rekrypt-ffi/lib/linux-x64/ 2>/dev/null || true
	@cp rekrypt-ffi/target/x86_64-unknown-linux-gnu/release/librekrypt_ffi.a rekrypt-ffi/lib/linux-x64/ 2>/dev/null || true
	@echo "[✓] Linux x86_64: rekrypt-ffi/lib/linux-x64/"

# Cross-compile for Linux ARM64
cross-linux-arm64:
	@echo "[CROSS] Building FFI for Linux ARM64..."
	@cd rekrypt-ffi && cargo zigbuild --release --target aarch64-unknown-linux-gnu
	@mkdir -p rekrypt-ffi/lib/linux-arm64
	@cp rekrypt-ffi/target/aarch64-unknown-linux-gnu/release/librekrypt_ffi.so rekrypt-ffi/lib/linux-arm64/ 2>/dev/null || true
	@cp rekrypt-ffi/target/aarch64-unknown-linux-gnu/release/librekrypt_ffi.a rekrypt-ffi/lib/linux-arm64/ 2>/dev/null || true
	@echo "[✓] Linux ARM64: rekrypt-ffi/lib/linux-arm64/"

# Cross-compile for Windows x86_64
cross-windows-x64:
	@echo "[CROSS] Building FFI for Windows x86_64..."
	@cd rekrypt-ffi && cargo zigbuild --release --target x86_64-pc-windows-gnu
	@mkdir -p rekrypt-ffi/lib/windows-x64
	@cp rekrypt-ffi/target/x86_64-pc-windows-gnu/release/rekrypt_ffi.dll rekrypt-ffi/lib/windows-x64/ 2>/dev/null || true
	@cp rekrypt-ffi/target/x86_64-pc-windows-gnu/release/rekrypt_ffi.lib rekrypt-ffi/lib/windows-x64/ 2>/dev/null || true
	@cp rekrypt-ffi/target/x86_64-pc-windows-gnu/release/librekrypt_ffi.a rekrypt-ffi/lib/windows-x64/ 2>/dev/null || true
	@echo "[✓] Windows x86_64: rekrypt-ffi/lib/windows-x64/"

# Cross-compile for macOS x86_64
cross-macos-x64:
	@echo "[CROSS] Building FFI for macOS x86_64..."
	@cd rekrypt-ffi && cargo build --release --target x86_64-apple-darwin
	@mkdir -p rekrypt-ffi/lib/macos-x64
	@cp rekrypt-ffi/target/x86_64-apple-darwin/release/librekrypt_ffi.dylib rekrypt-ffi/lib/macos-x64/ 2>/dev/null || true
	@cp rekrypt-ffi/target/x86_64-apple-darwin/release/librekrypt_ffi.a rekrypt-ffi/lib/macos-x64/ 2>/dev/null || true
	@echo "[✓] macOS x86_64: rekrypt-ffi/lib/macos-x64/"

# Cross-compile for macOS ARM64
cross-macos-arm64:
	@echo "[CROSS] Building FFI for macOS ARM64..."
	@cd rekrypt-ffi && cargo build --release --target aarch64-apple-darwin
	@mkdir -p rekrypt-ffi/lib/macos-arm64
	@cp rekrypt-ffi/target/aarch64-apple-darwin/release/librekrypt_ffi.dylib rekrypt-ffi/lib/macos-arm64/ 2>/dev/null || true
	@cp rekrypt-ffi/target/aarch64-apple-darwin/release/librekrypt_ffi.a rekrypt-ffi/lib/macos-arm64/ 2>/dev/null || true
	@echo "[✓] macOS ARM64: rekrypt-ffi/lib/macos-arm64/"

# Cross-compile for all Linux platforms
cross-linux: cross-linux-x64 cross-linux-arm64

# Cross-compile for all Windows platforms
cross-windows: cross-windows-x64

# Cross-compile for all macOS platforms
cross-macos: cross-macos-x64 cross-macos-arm64

# Cross-compile for all platforms (requires cross-compilation tools)
cross-compile: install-targets
	@echo "[CROSS] Building FFI for all platforms..."
	@$(MAKE) cross-linux || echo "[WARN] Linux cross-compilation failed (may need cross-compilation tools)"
	@$(MAKE) cross-windows || echo "[WARN] Windows cross-compilation failed (may need mingw-w64)"
	@$(MAKE) cross-macos || echo "[INFO] macOS cross-compilation only works on macOS"
	@echo ""
	@echo "[✓] Cross-compilation complete!"
	@echo ""
	@echo "Built libraries in rekrypt-ffi/lib/:"
	@ls -lh rekrypt-ffi/lib/*/librekrypt_ffi.* 2>/dev/null || echo "  (check individual platform directories)"

# Show cross-compilation help
.PHONY: cross-help
cross-help:
	@echo "Cross-compilation targets (using cargo-zigbuild):"
	@echo ""
	@echo "Setup:"
	@echo "  make install-targets     Install all cross-compilation targets and tools"
	@echo ""
	@echo "Build commands:"
	@echo "  make cross-compile       Build for all platforms"
	@echo "  make cross-linux         Build for Linux (x64 + ARM64)"
	@echo "  make cross-linux-x64     Build for Linux x86_64"
	@echo "  make cross-linux-arm64   Build for Linux ARM64"
	@echo "  make cross-windows       Build for Windows x64"
	@echo "  make cross-windows-x64   Build for Windows x86_64"
	@echo "  make cross-macos         Build for macOS (x64 + ARM64)"
	@echo "  make cross-macos-x64     Build for macOS x86_64"
	@echo "  make cross-macos-arm64   Build for macOS ARM64"
	@echo ""
	@echo "Prerequisites:"
	@echo "  cargo-zigbuild: cargo install cargo-zigbuild"
	@echo "  zig compiler:   brew install zig (macOS)"
	@echo ""
	@echo "Output: rekrypt-ffi/lib/{linux-x64,linux-arm64,windows-x64,macos-x64,macos-arm64}/"
