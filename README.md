# Rekrypt

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![WebAssembly](https://img.shields.io/badge/wasm-ready-green.svg)](https://webassembly.org/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/stevenleep/rekrypt)

Professional proxy re-encryption library based on **Curve25519 (ECC)** for Rust and WebAssembly. 

https://github.com/user-attachments/assets/64e1568e-75d8-4266-8e52-345594fe212f

---

## 🔍 What is Proxy Re-Encryption?

Proxy Re-Encryption allows a **semi-trusted proxy** to transform ciphertext from one key to another **without learning the plaintext**.

```
Alice encrypts → Transform Key → Proxy transforms → Bob decrypts
                (Alice grants)   (Zero knowledge)
```

**Core Technology**: Curve25519 (ECC) - Modern elliptic curve cryptography, NOT RSA

**Key Benefits**:
- 🔒 **Zero-trust proxy** - Proxy never sees plaintext
- 🔑 **Key isolation** - Alice's key never leaves her device
- 🎯 **Flexible delegation** - Grant/revoke access dynamically
- 📤 **One-to-many sharing** - Share with multiple recipients efficiently

### How It Works

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

---

## 🚀 Quick Start

### JavaScript/TypeScript (WebAssembly)

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

### Go (FFI)

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

📚 **More examples**: See [docs/EXAMPLES.md](docs/EXAMPLES.md) for complete examples and [docs/API.md](docs/API.md) for API reference.

---

## 📦 Installation
```bash
# pnpm -> nodejs/browser
pnpm add @stevenleep/rekrypt

# Cargo
cargo add rekrypt
```

---

## 📖 Documentation

### API & Usage

- 📘 [API Reference](docs/API.md) - Complete API documentation
- 💡 [Usage Examples](docs/EXAMPLES.md) - Code examples for all platforms
- 🏗️ [Architecture & Design](docs/ARCHITECTURE.md) - System architecture and cryptographic design
- 🔐 [Security Guide](docs/SECURITY.md) - Security best practices
- 📊 [Streaming Guide](docs/STREAMING.md) - Large file handling

### Advanced Topics

- 🔧 [Internal Implementation](docs/INTERNALS.md) - Deep dive into implementation details
- 🚀 [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment and scaling
- 🔨 [Cross-Compilation Guide](rekrypt-ffi/CROSS_COMPILE.md) - Build FFI for multiple platforms
- 📝 [Publishing Guide](PUBLISHING.md) - How to publish documentation and packages

### Generated Documentation

- **Rust API Docs**: Run `make doc-open` or visit https://docs.rs/rekrypt (after publishing)
- **GitHub Pages**: https://stevenleep.github.io/rekrypt/ (auto-deployed on push)

---

## 🖥️ Supported Platforms

### WebAssembly

- ✅ All modern browsers (Chrome, Firefox, Safari, Edge)
- ✅ Node.js with WASM support
- ✅ Deno and Bun

### Native FFI Library

Rekrypt provides native FFI libraries for multiple platforms:

| Platform | Architecture | Status |
|----------|--------------|--------|
| **Linux** | x86_64 (Intel/AMD) | ✅ Supported |
| **Linux** | ARM64 (ARMv8) | ✅ Supported |
| **Windows** | x86_64 (64-bit) | ✅ Supported |
| **macOS** | x86_64 (Intel) | ✅ Supported |
| **macOS** | ARM64 (Apple Silicon) | ✅ Supported |

**Language Bindings:** C, C++, Go (CGO), Python (ctypes), Node.js (FFI), Rust, and any language with C FFI support.

📚 See [rekrypt-ffi/](rekrypt-ffi/) for FFI usage examples and [CROSS_COMPILE.md](rekrypt-ffi/CROSS_COMPILE.md) for cross-compilation guide.

---

## 🔨 Build from Source

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

📚 For more details, see [CROSS_COMPILE.md](rekrypt-ffi/CROSS_COMPILE.md) for cross-compilation and [DEPLOYMENT.md](docs/DEPLOYMENT.md) for production builds.

---

## 📄 License

AGPL-3.0

Copyright (C) 2025 stenvenleep
