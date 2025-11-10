# Architecture & Design Principles

## Table of Contents

1. [Proxy Re-Encryption Theory](#proxy-re-encryption-theory)
2. [Hybrid Encryption Scheme](#hybrid-encryption-scheme)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Security Design](#security-design)
5. [Key Management](#key-management)
6. [Multi-Platform Architecture](#multi-platform-architecture)
7. [Module Architecture](#module-architecture)
8. [Data Flow](#data-flow)
9. [Cross-Platform Build System](#cross-platform-build-system)

## Proxy Re-Encryption Theory

### Mathematical Foundation

Proxy re-encryption is based on elliptic curve cryptography. The core idea:

```
Given:
- Ciphertext encrypted under Alice's public key (PKₐ)
- Transform key (TKₐ→ᵦ) from Alice to Bob
- Proxy can compute: Transform(Ciphertext, TKₐ→ᵦ) = Ciphertext'

Result:
- Ciphertext' can be decrypted by Bob's private key (SKᵦ)
- Proxy learns nothing about the plaintext
- Bob cannot derive Alice's private key
```

### Properties

**Unidirectional**: Transform key only works Alice → Bob, not Bob → Alice

**Non-transitive**: Bob cannot create transform keys for others

**Collusion-resistant**: Bob + Proxy together cannot decrypt Alice's other messages

**Key Privacy**: Alice's private key is never exposed

## Hybrid Encryption Scheme

Rekrypt uses a hybrid approach combining proxy re-encryption with symmetric encryption:

### Encryption Process

```
┌──────────────┐
│  Plaintext   │
│    Data      │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│ Step 1: Generate Random Plaintext (P)      │
│         using recrypt library               │
└──────────────┬──────────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
       ▼                ▼
┌──────────────┐  ┌─────────────────┐
│ Encrypt P    │  │ Derive AES Key  │
│ using PKᵣ    │  │ K = KDF(P)      │
│              │  │                 │
│ Result: E(P) │  │ K (32 bytes)    │
└──────┬───────┘  └────────┬────────┘
       │                   │
       │                   │ Use K to encrypt data
       │                   ▼
       │          ┌──────────────────┐
       │          │ AES-256-GCM      │
       │          │ Encrypt(Data, K) │
       │          └────────┬─────────┘
       │                   │
       ▼                   ▼
┌─────────────┐    ┌─────────────┐
│   Capsule   │    │ Ciphertext  │
│  (Metadata) │    │   (Data)    │
└─────────────┘    └─────────────┘

Capsule contains:
• E(P) - Encrypted plaintext value
• Signing keys
• Nonce for AES
• Integrity hash
• Anti-replay metadata
```

### Why Hybrid?

**Problem**: Pure proxy re-encryption is slow for large data

**Solution**: 
1. Use proxy re-encryption for key agreement
2. Use AES-256-GCM for actual data encryption
3. Combine benefits of both

**Advantages**:
- Fast encryption/decryption of large files
- Flexible delegation via transform keys
- Authenticated encryption (integrity + confidentiality)

## Cryptographic Primitives

### Core: Elliptic Curve Cryptography (ECC)

⚠️ **Important: This library uses ECC (Curve25519), NOT RSA**

**Curve**: Curve25519 (via recrypt library)
- Type: Montgomery curve elliptic curve
- Security: 128-bit security level (equivalent to 3072-bit RSA)
- Performance: Much faster than RSA
- Key size: 32 bytes (vs 384 bytes for RSA-3072)
- Constant-time: Resistant to timing attacks

**Why ECC over RSA**:
- Smaller keys (32 bytes vs 256+ bytes)
- Faster operations (10-100x)
- Lower bandwidth
- Better for mobile/web
- Modern cryptographic standard

**Key Generation**:
```rust
private_key: 32 bytes random scalar
public_key = private_key × G (where G is curve generator)
```

**Signing**: Ed25519 (EdDSA on Curve25519)
- Fast verification
- Small signatures (64 bytes)
- Deterministic (no random needed)

### Symmetric Encryption

**Algorithm**: AES-256-GCM

**Parameters**:
- Key: 256 bits (32 bytes)
- Nonce: 96 bits (12 bytes) - randomly generated per encryption
- Tag: 128 bits (16 bytes) - authentication tag

**Why AES-GCM**:
- Authenticated encryption (AEAD)
- Single-pass encryption + authentication
- Efficient in hardware
- NIST approved

### Key Derivation

**HKDF-SHA256** (for mnemonic → private key):
```
Seed = BIP39(mnemonic, passphrase)  // 512 bits
Private_Key = HKDF-SHA256(Seed, "recrypt-key-v1")  // 32 bytes
```

**PBKDF2-HMAC-SHA256** (for keystore):
```
Iterations: 600,000 (OWASP 2023 recommendation)
Salt: 16 bytes random
Output: 32 bytes AES key
```

### Message Authentication

**HMAC-SHA256**:
- Prevents length extension attacks
- Cryptographically binds data to key
- Constant-time verification

### Hash Functions

**SHA-256**: Used for integrity hashes, not for MACs

## Security Design

### Memory Safety

**Zeroization**:
```rust
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeypairResult {
    pub private_key: Vec<u8>,
    pub mnemonic: String,
}
// Auto-cleared when dropped
```

**Why Important**:
- Prevents memory disclosure attacks
- Protects against cold boot attacks
- Clears sensitive data from heap

### Timing Attack Prevention

**Constant-Time Comparison**:
```rust
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()  // Using subtle crate
}
```

Used for:
- MAC verification
- Password comparison
- Key comparison

### Replay Attack Protection

**Three-Layer Defense**:

1. **Timestamp**: Validates message age
   - Default: 24 hours window
   - Detects old message replay

2. **UUID v4**: Unique request identifier
   - Cryptographically random
   - 128-bit collision resistance

3. **Sequence Number**: Monotonic counter
   - Randomized start point
   - Detects out-of-order messages

**Implementation**:
```rust
pub struct Capsule {
    pub sequence: u64,           // Monotonic
    pub request_id: String,      // UUID v4
    pub client_timestamp: u64,   // Milliseconds since epoch
    // ...
}
```

### Integrity Protection

**Multi-Layer Verification**:

1. **Ciphertext Hash**: SHA-256 of encrypted data
2. **Capsule HMAC**: Authenticates all metadata
3. **AES-GCM Tag**: Built-in authentication

**Keystore HMAC** protects:
- Ciphertext
- Salt
- IV
- Iteration count
- Version
- Algorithm names

Prevents parameter tampering attacks.

## Key Management

### BIP39 Mnemonic

**Generation**:
```
24 words = 256 bits entropy
→ PBKDF2(mnemonic, passphrase) = 512-bit seed
→ HKDF(seed, "recrypt-key-v1") = 32-byte private key
```

**Why 24 words**:
- 256-bit entropy (vs 128-bit for 12 words)
- Stronger against brute force
- Future-proof security

**Domain Separation**:
```rust
b"recrypt-key-v1"  // Context string
```
Ensures keys derived for different purposes are cryptographically independent.

### Key Derivation Chain

```
Mnemonic (24 words)
    │
    │ BIP39 + Passphrase
    ▼
512-bit Seed
    │
    │ HKDF-SHA256 (domain: "recrypt-key-v1")
    ▼
32-byte Private Key
    │
    │ Elliptic Curve Scalar Multiplication
    ▼
64-byte Public Key (x, y coordinates)
```

### Keystore Encryption

```
Password
    │
    │ PBKDF2-HMAC-SHA256 (600k iterations)
    ▼
32-byte Derived Key (K)
    │
    ├─────────────────────────┐
    │                         │
    ▼                         ▼
AES-256-GCM                HMAC-SHA256
Encrypt(PrivateKey, K)     MAC = HMAC(K, Params)
    │                         │
    ▼                         ▼
Ciphertext                  MAC
    │                         │
    └─────────┬───────────────┘
              ▼
          Keystore
```

**Why 600k iterations**:
- OWASP 2023 recommendation
- ~1-2 seconds on modern hardware
- Strong protection against brute force
- Balanced with DoS prevention (max 10M)

### Key Recovery Hierarchy

```
         ┌───────────────────────┐
         │  Mnemonic (Ultimate)  │ ← Save offline!
         └──────────┬────────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │   Full Keypair        │
         │ • Private Key         │
         │ • Public Key          │
         │ • Mnemonic            │
         └──────────┬────────────┘
                    │
         ┌──────────┴────────────┐
         │                       │
         ▼                       ▼
    Password                 Direct Use
    Protected                
         │                       
         ▼                       
┌─────────────────┐         
│    Keystore     │         
│  • Encrypted    │         
│  • HMAC         │         
│  • Salt         │         
└────────┬────────┘         
         │
         │ Password Required
         ▼
┌─────────────────┐
│  Private Key    │ ← Can derive public key
└─────────────────┘    Cannot recover mnemonic!
```

## Multi-Platform Architecture

Rekrypt supports multiple deployment targets through different build configurations:

### Deployment Targets

```
                    ┌─────────────────┐
                    │  Rekrypt Core   │
                    │  (Rust Library) │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  WASM Build  │  │   FFI Build  │  │ Transform    │
    │              │  │              │  │ Service      │
    │ Target:      │  │ Target:      │  │              │
    │ • Browser    │  │ • Linux x64  │  │ Go binary    │
    │ • Node.js    │  │ • Linux ARM  │  │ using FFI    │
    │ • Deno/Bun   │  │ • Windows    │  │              │
    │              │  │ • macOS x64  │  │              │
    │ Output:      │  │ • macOS ARM  │  │              │
    │ .wasm (512KB)│  │              │  │              │
    │              │  │ Output:      │  │              │
    │              │  │ .so/.dll     │  │              │
    │              │  │ .a (static)  │  │              │
    └──────────────┘  └──────────────┘  └──────────────┘
```

### Platform Support Matrix

| Platform | WASM | FFI | Transform Service |
|----------|------|-----|-------------------|
| Browser | Yes | No | No |
| Node.js | Yes | Yes | No |
| Linux x64 | Via Node | Yes | Yes |
| Linux ARM64 | Via Node | Yes | Yes |
| Windows x64 | Via Node | Yes | Possible |
| macOS Intel | Yes | Yes | Yes |
| macOS ARM | Yes | Yes | Yes |

### FFI Architecture

The FFI layer provides C-compatible bindings for native integration:

```
┌──────────────────────────────────────────────────┐
│           Application Layer (C, Go, Python...)    │
└─────────────────────┬────────────────────────────┘
                      │ C ABI
                      ▼
┌──────────────────────────────────────────────────┐
│            FFI Layer (rekrypt-ffi)                │
│                                                   │
│  • ByteArray marshalling                         │
│  • Error handling & conversion                   │
│  • Thread-safe error storage                     │
│  • Memory management (allocation/free)           │
└─────────────────────┬────────────────────────────┘
                      │ Rust API
                      ▼
┌──────────────────────────────────────────────────┐
│            Core Library (rekrypt)                 │
│                                                   │
│  • Cryptographic operations                      │
│  • Key management                                │
│  • Data validation                               │
└──────────────────────────────────────────────────┘
```

**Key Features**:
- No runtime dependencies (static linking available)
- Thread-safe error handling
- Zero-copy where possible
- Consistent API across all platforms

## Module Architecture

### Layered Design

```
┌─────────────────────────────────────────────┐
│         API Layer (lib.rs / ffi)             │ ← WASM or C bindings
├─────────────────────────────────────────────┤
│         Business Logic Layer                 │
│  ┌─────────┬──────────┬─────────────────┐  │
│  │  keys   │ keystore │    streaming    │  │
│  └─────────┴──────────┴─────────────────┘  │
├─────────────────────────────────────────────┤
│         Cryptographic Layer                  │
│  ┌─────────┬────────────┬──────────────┐   │
│  │ crypto  │ validation │  serialization│   │
│  └─────────┴────────────┴──────────────┘   │
├─────────────────────────────────────────────┤
│         Foundation Layer                     │
│  ┌─────────┬──────────┬──────────┐         │
│  │ types   │  errors  │   i18n   │         │
│  └─────────┴──────────┴──────────┘         │
└─────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────┐
│      External Dependencies                   │
│  • recrypt (proxy re-encryption)            │
│  • aes-gcm (symmetric encryption)           │
│  • bip39 (mnemonic generation)              │
│  • pbkdf2 (key derivation)                  │
│  • hmac, sha2 (hashing)                     │
│  • zeroize (memory safety)                  │
│  • subtle (timing attack prevention)        │
└─────────────────────────────────────────────┘
```

### Module Responsibilities

**Core Library (rekrypt/src/)**:

**lib.rs** (437 lines):
- WASM API bindings
- Thin wrapper over business logic
- Method routing
- EncryptSDK main interface

**crypto.rs** (176 lines):
- AES-256-GCM encryption/decryption
- HMAC computation
- Hash functions
- Key derivation (PBKDF2, HKDF)
- Random generation (IV, salt, UUID)

**keys.rs** (83 lines):
- BIP39 mnemonic generation
- Keypair derivation from mnemonic
- Key recovery

**keystore.rs** (129 lines):
- Password-based encryption
- PBKDF2 key derivation
- HMAC integrity protection
- Keystore structure management

**streaming.rs** (182 lines):
- Chunked encryption/decryption
- StreamEncryptor class
- StreamDecryptor class
- Chunk integrity verification

**helpers.rs** (135 lines):
- Utility functions
- Data validation helpers
- Serialization helpers
- Hex/bytes conversion

**validation.rs** (210 lines):
- Password strength validation
- Key format validation
- Timestamp validation
- Request ID validation
- Replay attack checks

**serialization.rs** (121 lines):
- Recrypt type serialization adapters
- EncryptedValue wrapper
- TransformKey placeholder

**types.rs** (97 lines):
- Data structure definitions
- Serde annotations
- Zeroize traits

**errors.rs** (117 lines):
- Error type definitions
- Error code enumeration
- WASM error conversion

**i18n.rs** (176 lines):
- English/Chinese messages
- Error message localization

**FFI Library (rekrypt-ffi/src/)**:

**lib.rs** (549 lines):
- C-compatible FFI bindings
- ByteArray structure for memory marshalling
- Error handling and thread-safe error storage
- Functions exported for C ABI:
  - rekrypt_version()
  - rekrypt_generate_keypair()
  - rekrypt_generate_signing_keypair()
  - rekrypt_generate_transform_key()
  - rekrypt_encrypt()
  - rekrypt_transform()
  - rekrypt_decrypt_delegated()
  - rekrypt_free_byte_array()
  - rekrypt_get_last_error()
- Memory management utilities
- Platform-specific compilation (Linux, Windows, macOS)

## Data Flow

### Encryption Data Flow

```
Input: Plaintext Data
   │
   ├─► validate_data_not_empty()
   │
   ▼
Validate Public Key
   │
   ├─► validate_public_key()
   ├─► postcard::from_bytes()
   ├─► PublicKey::new() [point-on-curve check]
   │
   ▼
Generate Signing Key
   │
   ├─► recrypt.generate_ed25519_key_pair()
   │
   ▼
Proxy Re-Encryption
   │
   ├─► recrypt.gen_plaintext() → P
   ├─► recrypt.encrypt(P, PK) → E(P)
   ├─► recrypt.derive_symmetric_key(P) → K
   │
   ▼
Symmetric Encryption
   │
   ├─► generate_iv() → Nonce
   ├─► aes_encrypt(K, Nonce, Data) → Ciphertext
   ├─► compute_hash(Ciphertext) → Hash
   │
   ▼
Build Capsule
   │
   ├─► Serialize E(P)
   ├─► Add metadata (nonce, hash, signing key)
   ├─► Add anti-replay (sequence, UUID, timestamp)
   │
   ▼
Return Result
   │
   └─► { capsule, ciphertext, hash }
```

### Decryption Data Flow

```
Input: Capsule + Ciphertext
   │
   ├─► validate_private_key()
   ├─► deserialize capsule
   │
   ▼
Anti-Replay Validation
   │
   ├─► validate_version()
   ├─► validate_timestamp() [24h window, 5min skew]
   ├─► validate_request_id() [UUID format]
   │
   ▼
Integrity Verification
   │
   ├─► compute_hash(Ciphertext)
   ├─► verify_mac(computed, expected) [constant-time]
   │
   ▼
Proxy Re-Encryption Decryption
   │
   ├─► Deserialize E(P) from capsule
   ├─► recrypt.decrypt(E(P), SK) → P
   ├─► recrypt.derive_symmetric_key(P) → K
   │
   ▼
Symmetric Decryption
   │
   ├─► aes_decrypt(K, Nonce, Ciphertext) → Data
   │
   ▼
Return Plaintext
```

## Cryptographic Primitives

### Algorithm Selection Rationale

| Primitive | Algorithm | Reason |
|-----------|-----------|--------|
| **Asymmetric** | **Curve25519 (ECC)** | **Fast, secure, constant-time** |
| Symmetric | AES-256-GCM | AEAD, hardware accelerated |
| Hash | SHA-256 | Standard, fast, 256-bit security |
| MAC | HMAC-SHA256 | Prevents extension attacks |
| KDF (password) | PBKDF2-SHA256 | OWASP standard, tunable |
| KDF (key) | HKDF-SHA256 | Proper key expansion |
| Signature | Ed25519 | Fast, secure, small keys |

**Note**: No RSA is used in this library. All asymmetric operations use ECC.

### Security Levels

```
Asymmetric:     128-bit security (Curve25519)
Symmetric:      256-bit security (AES-256)
Hash:           256-bit security (SHA-256)
Mnemonic:       256-bit entropy (24 words)
```

All exceed current recommendations for long-term security.

### Nonce Management

**Problem**: Reusing nonce with same key breaks GCM security

**Solution**: Fully random 96-bit nonces

**Analysis**:
```
Collision probability = n² / 2^97 (birthday paradox)

For 2^40 encryptions:
P(collision) ≈ 2^80 / 2^97 = 1 / 2^17 ≈ 0.00076%

Conclusion: Safe for billions of encryptions
```

**Why not counter-based**:
- Risk of counter reset across SDK instances
- Page refresh resets counter
- Multiple tabs/windows conflict
- Random is safer for client-side

## Security Design

### Defense in Depth

Multiple layers of protection:

```
┌─────────────────────────────────────┐
│   Application Layer                 │
│   • Input validation                │
│   • Password strength checks        │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Protocol Layer                    │
│   • Anti-replay (timestamp, UUID)   │
│   • Version negotiation             │
│   • Forward compatibility           │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Cryptographic Layer               │
│   • Authenticated encryption (AEAD) │
│   • Integrity checks (HMAC)         │
│   • Key derivation (PBKDF2/HKDF)    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Implementation Layer              │
│   • Memory safety (zeroize)         │
│   • Timing safety (constant-time)   │
│   • Error handling                  │
└─────────────────────────────────────┘
```

### Threat Model

**Protected Against**:
- ✅ Eavesdropping (encryption)
- ✅ Tampering (MAC/HMAC)
- ✅ Replay attacks (timestamp + UUID)
- ✅ Timing attacks (constant-time ops)
- ✅ Memory disclosure (zeroization)
- ✅ Brute force (strong KDF)
- ✅ Length extension (HMAC vs SHA)
- ✅ Padding oracle (MAC-then-decrypt)

**NOT Protected Against**:
- ❌ Malware on user's device
- ❌ Compromised endpoints
- ❌ Social engineering
- ❌ Physical access to device

**Requires External**:
- Server-side request_id deduplication
- Rate limiting
- Access control
- Audit logging

### Attack Resistance

**Brute Force Attacks**:
```
PBKDF2 with 600k iterations:
~1-2 seconds per attempt on modern CPU
~500 attempts/second on GPU

For 12-char mixed password (~60 bits):
Time to crack: 2^60 / 500 ≈ 73 million years
```

**Quantum Resistance**:
- Symmetric: AES-256 provides 128-bit quantum security (Grover's algorithm)
- Asymmetric: Curve25519 vulnerable to Shor's algorithm
- Mitigation: Hybrid encryption limits exposure

## Performance Optimization

### WASM Optimizations

**Cargo Profile**:
```toml
[profile.release]
codegen-units = 1     # Better optimization
lto = true            # Link-time optimization
opt-level = "z"       # Size optimization
panic = "abort"       # No unwinding overhead
strip = true          # Remove debug symbols
```

**wasm-opt**:
```toml
wasm-opt = ["-O4", "--enable-bulk-memory"]
```

Result: 512 KB WASM binary

### Algorithm Efficiency

| Operation | Complexity | Time (1KB) |
|-----------|-----------|------------|
| SHA-256 | O(n) | ~0.01ms |
| HMAC-SHA256 | O(n) | ~0.02ms |
| AES-256-GCM | O(n) | ~0.1ms |
| PBKDF2-600k | O(iterations) | ~1s |
| Curve25519 | O(1) | ~0.5ms |

### Memory Usage

**Typical Encryption**:
```
Input: 1MB data
Stack: ~1KB
Heap: ~2MB (temporary buffers)
Peak: ~3MB total
```

**Streaming**:
```
Chunk size: 1MB
Peak memory: ~2MB (single chunk)
Scales to GB files
```

## Design Decisions

### Why Postcard for Serialization?

- Compact binary format
- No schema required
- Fast serialization
- Smaller than JSON/MessagePack

### Why Not Pure Proxy Re-Encryption?

**Problem**: Slow for large data (curve operations)

**Solution**: Hybrid scheme
- Proxy re-encryption: Key agreement
- AES-GCM: Bulk data

**Trade-off**: More complex but much faster

### Why Client-Side Transform Not Supported?

**Limitation**: TransformKey contains internal curve points that cannot be safely serialized

**Design**: Server-side proxy model
- Transform keys stored on server
- Server performs transformation
- Client only encrypts/decrypts

**Benefit**: Cleaner separation of concerns

### Why Separate StreamEncryptor Class?

**Alternative**: Add chunk mode to main SDK

**Chosen**: Separate classes
- Clearer API
- Stateful chunk counters
- Independent lifecycles
- Easier to understand

## Cross-Platform Build System

### Build Configuration

**WASM Target**:
```toml
[lib]
crate-type = ["cdylib", "rlib"]

[profile.release]
opt-level = "z"          # Optimize for size
lto = true               # Link-time optimization
codegen-units = 1        # Better optimization
panic = "abort"          # Smaller binary
strip = true             # Remove debug symbols
```

**FFI Target**:
```toml
[lib]
crate-type = ["cdylib", "staticlib"]

[profile.release]
opt-level = 3            # Optimize for speed
lto = true
codegen-units = 1
strip = true
```

### Cross-Compilation

Using `cargo-zigbuild` for seamless cross-platform builds:

```bash
# Linux x86_64
cargo zigbuild --release --target x86_64-unknown-linux-gnu

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-gnu

# Windows x64
cargo zigbuild --release --target x86_64-pc-windows-gnu

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# macOS ARM
cargo build --release --target aarch64-apple-darwin
```

**Benefits**:
- No complex toolchain setup
- Works from any host platform
- Consistent build process
- Fast compilation

## Future Enhancements

### Planned Features

1. **Threshold Re-Encryption**: Multiple proxies required
2. **Time-Locked Encryption**: Automatic key release
3. **Multi-Recipient**: Single encryption, multiple recipients
4. **Quantum-Resistant**: Post-quantum cryptography
5. **More FFI Bindings**: Java JNI, Ruby FFI, Swift

### Extensibility Points

**Version Field**: All structures include version for upgrades

**Modular Design**: Easy to swap implementations

**Plugin Architecture**: Future support for:
- Alternative curves
- Different symmetric algorithms
- Custom KDF parameters

**Platform Expansion**:
- Android AAR (Java/Kotlin)
- iOS XCFramework (Swift)
- .NET P/Invoke bindings

