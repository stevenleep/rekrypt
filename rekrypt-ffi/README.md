# Rekrypt FFI

Foreign Function Interface (FFI) bindings for Rekrypt - enables usage from C, C++, Go, Python, Node.js, and any language with C FFI support.

## Supported Platforms

| Platform | Architecture | Library Files | Status |
|----------|--------------|---------------|--------|
| **Linux** | x86_64 | `.so`, `.a` | Fully Supported |
| **Linux** | ARM64 | `.so`, `.a` | Fully Supported |
| **Windows** | x86_64 | `.dll`, `.a` | Fully Supported |
| **macOS** | x86_64 (Intel) | `.dylib`, `.a` | Fully Supported |
| **macOS** | ARM64 (Apple Silicon) | `.dylib`, `.a` | Fully Supported |

## Quick Start

### 1. Build FFI Library

#### Build for current platform:
```bash
cd /path/to/rekrypt
make build-ffi
```

Library files will be in `rekrypt-ffi/lib/`

#### Cross-compile for all platforms:
```bash
# Install cross-compilation tools (once)
make install-targets

# Build for all platforms
make cross-compile

# Or build specific platforms
make cross-linux-x64      # Linux x86_64
make cross-linux-arm64    # Linux ARM64
make cross-windows-x64    # Windows x64
make cross-macos-x64      # macOS Intel
make cross-macos-arm64    # macOS Apple Silicon
```

See [CROSS_COMPILE.md](CROSS_COMPILE.md) for detailed cross-compilation guide.

### 2. Use in Your Project

## Usage Examples

### Go (CGO)

```go
package main

/*
#cgo linux LDFLAGS: -L${SRCDIR}/lib/linux-x64 -lrekrypt_ffi
#cgo darwin LDFLAGS: -L${SRCDIR}/lib/macos-arm64 -lrekrypt_ffi
#cgo windows LDFLAGS: -L${SRCDIR}/lib/windows-x64 -lrekrypt_ffi

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t *data;
    size_t len;
} ByteArray;

extern int rekrypt_version();
extern int rekrypt_generate_keypair(ByteArray *out_private_key, ByteArray *out_public_key);
extern void rekrypt_free_byte_array(ByteArray *arr);
*/
import "C"
import (
    "fmt"
    "unsafe"
)

func GetVersion() int {
    return int(C.rekrypt_version())
}

func GenerateKeypair() ([]byte, []byte, error) {
    var privKey, pubKey C.ByteArray
    
    result := C.rekrypt_generate_keypair(&privKey, &pubKey)
    if result != 0 {
        return nil, nil, fmt.Errorf("failed to generate keypair")
    }
    
    defer C.rekrypt_free_byte_array(&privKey)
    defer C.rekrypt_free_byte_array(&pubKey)
    
    privKeyBytes := C.GoBytes(unsafe.Pointer(privKey.data), C.int(privKey.len))
    pubKeyBytes := C.GoBytes(unsafe.Pointer(pubKey.data), C.int(pubKey.len))
    
    return privKeyBytes, pubKeyBytes, nil
}

func main() {
    fmt.Printf("Rekrypt version: %d\n", GetVersion())
    
    privKey, pubKey, err := GenerateKeypair()
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Generated keypair:\n")
    fmt.Printf("  Private key: %d bytes\n", len(privKey))
    fmt.Printf("  Public key: %d bytes\n", len(pubKey))
}
```

### Python (ctypes)

```python
import ctypes
import platform
from pathlib import Path

# Select library based on platform
system = platform.system()
machine = platform.machine()

if system == "Linux":
    if machine == "x86_64":
        lib_path = "lib/linux-x64/librekrypt_ffi.so"
    else:
        lib_path = "lib/linux-arm64/librekrypt_ffi.so"
elif system == "Darwin":
    if machine == "arm64":
        lib_path = "lib/macos-arm64/librekrypt_ffi.dylib"
    else:
        lib_path = "lib/macos-x64/librekrypt_ffi.dylib"
elif system == "Windows":
    lib_path = "lib/windows-x64/rekrypt_ffi.dll"
else:
    raise RuntimeError(f"Unsupported platform: {system} {machine}")

# Load library
lib = ctypes.CDLL(str(Path(__file__).parent / lib_path))

# Define ByteArray structure
class ByteArray(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t)
    ]

# Define functions
lib.rekrypt_version.argtypes = []
lib.rekrypt_version.restype = ctypes.c_int

lib.rekrypt_generate_keypair.argtypes = [
    ctypes.POINTER(ByteArray),
    ctypes.POINTER(ByteArray)
]
lib.rekrypt_generate_keypair.restype = ctypes.c_int

lib.rekrypt_free_byte_array.argtypes = [ctypes.POINTER(ByteArray)]
lib.rekrypt_free_byte_array.restype = None

# Usage
def get_version():
    return lib.rekrypt_version()

def generate_keypair():
    priv_key = ByteArray()
    pub_key = ByteArray()
    
    result = lib.rekrypt_generate_keypair(
        ctypes.byref(priv_key),
        ctypes.byref(pub_key)
    )
    
    if result != 0:
        raise RuntimeError("Failed to generate keypair")
    
    try:
        priv_bytes = bytes(priv_key.data[:priv_key.len])
        pub_bytes = bytes(pub_key.data[:pub_key.len])
        return priv_bytes, pub_bytes
    finally:
        lib.rekrypt_free_byte_array(ctypes.byref(priv_key))
        lib.rekrypt_free_byte_array(ctypes.byref(pub_key))

if __name__ == "__main__":
    print(f"Rekrypt version: {get_version()}")
    
    priv_key, pub_key = generate_keypair()
    print(f"Generated keypair:")
    print(f"  Private key: {len(priv_key)} bytes")
    print(f"  Public key: {len(pub_key)} bytes")
```

### C/C++

```c
#include <stdio.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
} ByteArray;

extern int rekrypt_version();
extern int rekrypt_generate_keypair(ByteArray *out_private_key, ByteArray *out_public_key);
extern void rekrypt_free_byte_array(ByteArray *arr);

int main() {
    printf("Rekrypt version: %d\n", rekrypt_version());
    
    ByteArray priv_key, pub_key;
    
    if (rekrypt_generate_keypair(&priv_key, &pub_key) != 0) {
        fprintf(stderr, "Failed to generate keypair\n");
        return 1;
    }
    
    printf("Generated keypair:\n");
    printf("  Private key: %zu bytes\n", priv_key.len);
    printf("  Public key: %zu bytes\n", pub_key.len);
    
    rekrypt_free_byte_array(&priv_key);
    rekrypt_free_byte_array(&pub_key);
    
    return 0;
}
```

Compile:
```bash
# Linux
gcc -o example example.c -L./lib/linux-x64 -lrekrypt_ffi -Wl,-rpath,./lib/linux-x64

# macOS
gcc -o example example.c -L./lib/macos-arm64 -lrekrypt_ffi

# Windows (MinGW)
gcc -o example.exe example.c -L./lib/windows-x64 -lrekrypt_ffi
```

### Node.js (node-ffi-napi)

```javascript
const ffi = require('ffi-napi');
const ref = require('ref-napi');
const path = require('path');

// ByteArray structure
const ByteArray = ref.types.void;
const ByteArrayPtr = ref.refType(ByteArray);

// Select library path
const platform = process.platform;
const arch = process.arch;

let libPath;
if (platform === 'linux') {
    libPath = arch === 'x64' 
        ? 'lib/linux-x64/librekrypt_ffi.so'
        : 'lib/linux-arm64/librekrypt_ffi.so';
} else if (platform === 'darwin') {
    libPath = arch === 'arm64'
        ? 'lib/macos-arm64/librekrypt_ffi.dylib'
        : 'lib/macos-x64/librekrypt_ffi.dylib';
} else if (platform === 'win32') {
    libPath = 'lib/windows-x64/rekrypt_ffi.dll';
}

// Load library
const lib = ffi.Library(path.join(__dirname, libPath), {
    'rekrypt_version': ['int', []],
    'rekrypt_generate_keypair': ['int', [ByteArrayPtr, ByteArrayPtr]],
    'rekrypt_free_byte_array': ['void', [ByteArrayPtr]]
});

function getVersion() {
    return lib.rekrypt_version();
}

console.log('Rekrypt version:', getVersion());
```

## API Reference

### Core Functions

#### `rekrypt_version() -> int`
Returns the library version.

#### `rekrypt_generate_keypair(out_private_key: *ByteArray, out_public_key: *ByteArray) -> int`
Generates a new keypair. Returns 0 on success.

#### `rekrypt_generate_signing_keypair(out_signing_keypair: *ByteArray) -> int`
Generates a signing keypair. Returns 0 on success.

#### `rekrypt_generate_transform_key(...) -> int`
Generates a transform key for proxy re-encryption.

#### `rekrypt_encrypt(...) -> int`
Encrypts data.

#### `rekrypt_transform(...) -> int`
Transforms ciphertext (proxy operation).

#### `rekrypt_decrypt_delegated(...) -> int`
Decrypts transformed ciphertext.

#### `rekrypt_free_byte_array(arr: *ByteArray)`
Frees memory allocated by the library.

### Error Handling

All functions return an integer status code:
- `0`: Success
- Non-zero: Error (use `rekrypt_get_last_error()` for details)

```c
const char* rekrypt_get_last_error();
void rekrypt_free_error(const char* error);
```

## Building

### Prerequisites
- Rust 1.70+ (`rustup`)
- cargo-zigbuild (`cargo install cargo-zigbuild`)
- zig compiler (for cross-compilation)

### Build Commands

```bash
# Current platform
cargo build --release

# Cross-compile (requires cargo-zigbuild + zig)
cargo zigbuild --release --target x86_64-unknown-linux-gnu
cargo zigbuild --release --target aarch64-unknown-linux-gnu
cargo zigbuild --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

See [CROSS_COMPILE.md](CROSS_COMPILE.md) for detailed instructions.

## Library Sizes

Approximate sizes for each platform:

| Platform | Dynamic Library | Static Library | Total |
|----------|----------------|----------------|-------|
| Linux x86_64 | ~3.7 MB | ~4.4 MB | ~8.1 MB |
| Linux ARM64 | ~3.8 MB | ~4.4 MB | ~8.2 MB |
| Windows x64 | ~3.3 MB | ~3.6 MB | ~6.9 MB |
| macOS x64 | ~0.6 MB | ~5.5 MB | ~6.1 MB |
| macOS ARM64 | ~0.6 MB | ~5.4 MB | ~6.0 MB |

## Dynamic vs Static Linking

### Dynamic Library (`.so`, `.dylib`, `.dll`)
- Smaller executable size
- Shared between multiple programs
- Must be present at runtime
- Better for plugins/shared libraries

### Static Library (`.a`, `.lib`)
- No runtime dependencies
- Larger executable size
- Slightly better performance
- Better for standalone applications

## Troubleshooting

### Library not found
Make sure the library is in your system's library path or use `-rpath` (Linux/macOS) or copy DLL to exe directory (Windows).

### Symbol not found
Ensure you're using the correct library for your platform and architecture.

### Linking errors
Check that you're linking against the correct library type (static vs dynamic) and all dependencies are satisfied.

## Testing

```bash
# Run FFI tests
cd rekrypt-ffi
cargo test --lib

# Test from parent directory
cd ..
make test-ffi
```

## License

AGPL-3.0

Copyright (C) 2025 stenvenleep

