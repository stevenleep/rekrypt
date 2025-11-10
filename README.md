# Rekrypt

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![WebAssembly](https://img.shields.io/badge/wasm-ready-green.svg)](https://webassembly.org/)

Professional proxy re-encryption library based on **Curve25519 (ECC)** for Rust and WebAssembly. 

https://github.com/user-attachments/assets/64e1568e-75d8-4266-8e52-345594fe212f

## Installation

> **⚠️ Notice:** This project is under active development. NPM and Cargo packages are not yet published. Please build from source for now.

```bash
# NPM (coming soon)
pnpm add @stevenleep/rekrypt

# Cargo (coming soon)
cargo add rekrypt
```

For now, please build from source (see below).

## Build from Source

This project provides a unified Makefile for building all components:

```bash
# Quick start - build everything
make all

# Or build specific components
make build-wasm     # WebAssembly package
make build-ffi      # FFI library (for Go/Python/C++)
make build-server   # Go transform server

# Cross-compile FFI for multiple platforms
make install-targets    # Install cross-compilation tools
make cross-compile      # Build for all platforms
make cross-linux-x64    # Linux x86_64
make cross-windows-x64  # Windows x64
make cross-macos-arm64  # macOS Apple Silicon
make cross-help         # Show cross-compilation help

# Run tests
make test           # All tests
make test-ffi       # FFI tests only

# Development
make dev-server     # Run Go server in dev mode
make clean          # Clean all artifacts
make help           # Show all available commands
```

## Quick Start

```javascript
import init, { EncryptSDK } from 'rekrypt';

await init();
const sdk = new EncryptSDK();

// Generate keypair
const alice = sdk.generateKeypair();

// Encrypt
const data = new TextEncoder().encode('Secret');
const encrypted = sdk.encrypt(data, alice.public_key);

// Decrypt
const decrypted = sdk.decrypt(encrypted.capsule, alice.private_key, encrypted.c_data);
```

See [docs/](docs/) for complete examples and API reference.

### Using FFI Library (Go Example)

```go
package main

/*
#cgo LDFLAGS: -L./rekrypt-ffi/lib/linux-x64 -lrekrypt_ffi
#include <stdint.h>
extern int rekrypt_version();
*/
import "C"
import "fmt"

func main() {
    version := C.rekrypt_version()
    fmt.Printf("Rekrypt version: %d\n", version)
}
```

More examples in [rekrypt-ffi/](rekrypt-ffi/).

## Supported Platforms

### WebAssembly
- All modern browsers (Chrome, Firefox, Safari, Edge)
- Node.js with WASM support
- Deno and Bun

### FFI Library (Native)
Rekrypt provides native FFI libraries for multiple platforms:

| Platform | Architecture | Status |
|----------|--------------|--------|
| **Linux** | x86_64 (Intel/AMD) | Supported |
| **Linux** | ARM64 (ARMv8) | Supported |
| **Windows** | x86_64 (64-bit) | Supported |
| **macOS** | x86_64 (Intel) | Supported |
| **macOS** | ARM64 (Apple Silicon) | Supported |

**Language Bindings:** C, C++, Go (CGO), Python (ctypes), Node.js (FFI), Rust, and any language with C FFI support.

See [rekrypt-ffi/](rekrypt-ffi/) for FFI usage examples.

## Documentation

- [API Reference](docs/API.md) - Complete API documentation
- [Usage Examples](docs/EXAMPLES.md) - Code examples
- [Cross-Compilation Guide](rekrypt-ffi/CROSS_COMPILE.md) - Build FFI for multiple platforms
- [Architecture & Design](docs/ARCHITECTURE.md) - System architecture and cryptographic design
- [Internal Implementation](docs/INTERNALS.md) - Deep dive into implementation details
- [Security Guide](docs/SECURITY.md) - Security best practices
- [Streaming Guide](docs/STREAMING.md) - Large file handling
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment and scaling

## What is Proxy Re-Encryption?

Allows a semi-trusted proxy to transform ciphertext from one key to another **without learning the plaintext**.

```
Alice encrypts → Transform Key → Proxy transforms → Bob decrypts
                (Alice grants)   (Zero knowledge)
```

**Core Technology**: Curve25519 (ECC) - Modern elliptic curve cryptography, NOT RSA

Benefits: Zero-trust proxy, key isolation, flexible delegation, one-to-many sharing.

## Proxy Re-Encryption Flow

```
  Alice          Business Server       Proxy Server            Bob
    │                  │                     │                   │
    │ 1. Encrypt       │                     │                   │
    │  encrypt(data,   │                     │                   │
    │  alice.pubKey)   │                     │                   │
    │                  │                     │                   │
    │ 2. Upload        │                     │                   │
    ├─────────────────►│                     │                   │
    │  Ciphertext +    │ Store encrypted     │                   │
    │  Capsule         │ data                │                   │
    │                  │                     │                   │
    │ 3. Grant Access  │                     │                   │
    │  transformKey =  │                     │                   │
    │  generateTransformKey(                 │                   │
    │    alice.privKey,│                     │                   │
    │    bob.pubKey)   │                     │                   │
    │                  │                     │                   │
    │ 4. Send Key      │                     │                   │
    ├─────────────────►│                     │                   │
    │                  │                     │                   │
    │                  │ 5. Request Transform│                   │
    │                  ├────────────────────►│                   │
    │                  │  Ciphertext +       │                   │
    │                  │  TransformKey       │                   │
    │                  │                     │                   │
    │                  │                     │ 6. Transform      │
    │                  │                     │  (Zero Knowledge) │
    │                  │                     │  ⚠️ CANNOT see    │
    │                  │                     │     plaintext     │
    │                  │                     │                   │
    │                  │ 7. Transformed      │                   │
    │                  │◄────────────────────┤                   │
    │                  │  Ciphertext         │                   │
    │                  │  (for Bob)          │                   │
    │                  │                     │                   │
    │                  │        8. Bob requests access           │
    │                  │◄───────────────────────────────────────┤
    │                  │                     │                   │
    │                  │ 9. Send Transformed │                   │
    │                  ├───────────────────────────────────────►│
    │                  │                     │                   │
    │                  │                     │    10. Decrypt    │
    │                  │                     │    decryptDelegated(
    │                  │                     │      bob.privKey) │
    │                  │                     │                   │
    │                  │                     │   ┌──────────┐    │
    │                  │                     │   │Plaintext │◄───┤
    │                  │                     │   └──────────┘    │
    
Key Points:
• Alice's private key never leaves her device
• Proxy transforms without seeing plaintext
• Bob decrypts without Alice's key
• Business server stores encrypted data only
```

## License

AGPL-3.0

Copyright (C) 2025 stenvenleep
