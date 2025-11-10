# Internal Implementation Details

## Multi-Platform Implementation

Rekrypt is implemented in Rust and compiled to multiple targets:

### Build Targets

1. **WebAssembly (cdylib)**
   - Compiled with `wasm-pack`
   - Output: `rekrypt_bg.wasm` (512KB)
   - Target: `wasm32-unknown-unknown`
   - Optimization: Size (`opt-level = "z"`)

2. **FFI Library (cdylib + staticlib)**
   - Compiled with `cargo` or `cargo-zigbuild`
   - Output: `.so`, `.dylib`, `.dll`, `.a`
   - Targets: Linux, Windows, macOS (x64 + ARM64)
   - Optimization: Speed (`opt-level = 3`)

3. **Rust Library (rlib)**
   - For direct Rust integration
   - Zero-cost abstraction

### FFI Layer Implementation

The FFI layer (`rekrypt-ffi`) provides C ABI bindings:

**Key Components**:

1. **ByteArray Structure**
   ```rust
   #[repr(C)]
   pub struct ByteArray {
       pub data: *mut u8,
       pub len: usize,
   }
   ```
   - C-compatible memory layout
   - Caller must free using `rekrypt_free_byte_array()`

2. **Error Handling**
   ```rust
   static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
   
   fn set_error(msg: String) {
       *LAST_ERROR.lock().unwrap() = Some(msg);
   }
   ```
   - Thread-safe error storage
   - Accessible via `rekrypt_get_last_error()`

3. **Memory Management**
   ```rust
   impl ByteArray {
       fn from_vec(vec: Vec<u8>) -> Self {
           let mut vec = vec;
           let ptr = vec.as_mut_ptr();
           let len = vec.len();
           std::mem::forget(vec);  // Don't drop
           ByteArray { data: ptr, len }
       }
   }
   
   #[no_mangle]
   pub extern "C" fn rekrypt_free_byte_array(arr: *mut ByteArray) {
       if !arr.is_null() {
           unsafe {
               let arr = &*arr;
               if !arr.data.is_null() && arr.len > 0 {
                   Vec::from_raw_parts(arr.data, arr.len, arr.len);
                   // Vec is dropped here, freeing memory
               }
           }
       }
   }
   ```

4. **Function Exports**
   ```rust
   #[no_mangle]
   pub extern "C" fn rekrypt_generate_keypair(
       out_private_key: *mut ByteArray,
       out_public_key: *mut ByteArray,
   ) -> i32 {
       // Implementation...
   }
   ```
   - `#[no_mangle]`: Preserve function names
   - `extern "C"`: Use C calling convention
   - Returns `0` on success, non-zero on error

### Platform-Specific Compilation

**Cargo Configuration**:
```toml
[lib]
crate-type = ["cdylib", "staticlib"]  # Both dynamic and static

[profile.release]
opt-level = 3        # Speed over size for FFI
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization
strip = true         # Remove debug symbols
```

**Cross-Compilation with cargo-zigbuild**:
- Uses Zig as universal linker
- No need for platform-specific toolchains
- Supports Linux, Windows, macOS from any host

## BIP39 Mnemonic Deep Dive

### Generation Process

```
1. Generate 256 bits of entropy (24 words)
   random_bytes = CSPRNG(32 bytes)

2. Compute checksum
   checksum = SHA-256(random_bytes)[0..8 bits]

3. Combine entropy + checksum
   combined = random_bytes || checksum
   total = 264 bits

4. Split into 11-bit words
   264 bits / 11 = 24 words
   
5. Map to BIP39 wordlist
   Each 11-bit value → one word
   2^11 = 2048 words in list
```

### Recovery Process

```
1. Validate wordlist
   Check each word exists in BIP39 English wordlist

2. Verify checksum
   computed_checksum = SHA-256(entropy)[0..8]
   if computed_checksum != stored_checksum:
       reject (corrupted mnemonic)

3. Normalize
   lowercase, trim whitespace

4. Derive seed (PBKDF2)
   seed = PBKDF2-HMAC-SHA512(
       password = mnemonic,
       salt = "mnemonic" + passphrase,
       iterations = 2048,
       dklen = 64
   )

5. Derive private key (HKDF)
   private_key = HKDF-SHA256(
       ikm = seed,
       info = "recrypt-key-v1",
       length = 32
   )
```

### Why Domain Separation?

```rust
b"recrypt-key-v1"  // Context string
```

Ensures keys for different purposes are cryptographically independent:
- Same mnemonic can derive multiple independent keys
- Prevents key reuse across applications
- Forward compatibility (v2, v3, etc.)

## PBKDF2 Deep Dive

### Iteration Count Selection

```
OWASP 2023 Recommendation:
- PBKDF2-SHA256: 600,000 iterations minimum
- ~1-2 seconds on modern hardware

Security Analysis:
Time to compute: T_compute = iterations / hash_rate

Attacker with GPU:
- Hash rate: ~10^9 hashes/sec
- Time per attempt: 600,000 / 10^9 = 0.6ms

For 12-char password (60 bits entropy):
- Attempts needed: 2^60
- Time: 2^60 × 0.6ms ≈ 22 million years

Conclusion: 600k iterations provides adequate security
```

### Implementation

```rust
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dklen: usize,
) -> Vec<u8> {
    let mut key = vec![0u8; dklen];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        password,
        salt,
        iterations,
        &mut key
    );
    key
}
```

## AES-GCM Implementation Details

### Nonce Generation Strategy

**Problem**: GCM nonce reuse catastrophically breaks security

**Options**:
1. Counter-based (deterministic)
2. Random (probabilistic)

**Our Choice**: Random

**Rationale**:
```
Counter-based risks:
• Counter reset on page refresh
• Multiple tabs conflict
• SDK reinstantiation

Random analysis:
• Nonce: 96 bits
• Birthday bound: 2^48 encryptions
• With 2^40 encryptions: collision probability < 0.001%
• Safe for billions of operations
```

**Implementation**:
```rust
pub fn generate_iv() -> [u8; 12] {
    use rand::Rng;
    rand::thread_rng().gen()  // Cryptographically secure
}
```

### GCM Authentication Tag

**Structure**:
```
Ciphertext = Encrypt(plaintext, key, nonce)
Tag = GHASH(ciphertext, AAD, key)

Output = Ciphertext || Tag (128-bit tag)
```

**Verification**:
- Decrypt computes tag
- Compares with stored tag
- Rejects if mismatch (tampering detected)

## Capsule Structure Design

### Fields Explained

```rust
pub struct Capsule {
    version: u8,              // Protocol version
    nonce: Vec<u8>,           // AES-GCM nonce (12 bytes)
    signing_key_pair: Vec<u8>, // Ed25519 keypair (64 bytes)
    encrypted_data: Vec<u8>,   // Serialized EncryptedValue
    data_hash: Vec<u8>,        // SHA-256 of ciphertext
    sequence: u64,             // Monotonic counter
    request_id: String,        // UUID v4
    client_timestamp: u64,     // Milliseconds since epoch
}
```

**Why Each Field**:

1. **version**: Forward compatibility
   - Current: v1
   - Future: Can add fields in v2

2. **nonce**: Uniqueness for AES-GCM
   - Random 96-bit value
   - Never reuse with same key

3. **signing_key_pair**: Authentication
   - Proves message origin
   - Ed25519 signature verification

4. **encrypted_data**: Core payload
   - Serialized EncryptedValue from recrypt
   - Contains encrypted plaintext value

5. **data_hash**: Integrity
   - SHA-256 of ciphertext
   - Verify before decryption

6. **sequence**: Replay protection
   - Monotonic counter per session
   - Detects out-of-order messages

7. **request_id**: Uniqueness
   - UUID v4 for deduplication
   - Server-side tracking

8. **client_timestamp**: Freshness
   - Rejects old messages
   - Clock skew tolerance: 5 minutes

### Size Analysis

```
Typical Capsule Size:
• version: 1 byte
• nonce: 12 bytes
• signing_key_pair: 64 bytes
• encrypted_data: ~600 bytes (EncryptedValue)
• data_hash: 32 bytes
• sequence: 8 bytes (as string in JSON)
• request_id: 36 bytes (UUID string)
• client_timestamp: 13 bytes (as string)

Total: ~750-800 bytes overhead per encryption
```

## Serialization Strategy

### Why Postcard?

Compared to alternatives:

| Format | Serialized Size | Speed | Schema |
|--------|----------------|-------|--------|
| JSON | 1.5x | Slow | No |
| MessagePack | 1.2x | Medium | No |
| **Postcard** | **1.0x** | **Fast** | **No** |
| Protobuf | 0.9x | Fast | Yes (required) |

**Postcard advantages**:
- Smallest size without schema
- Fast serialization
- No schema maintenance
- Works well with serde

### EncryptedValue Serialization Challenge

**Problem**: recrypt's `EncryptedValue` doesn't implement `Serialize`

**Solution**: Manual serialization using public API

```rust
pub struct SerializableEncryptedValue {
    variant: u8,
    ephemeral_public_key_x: Vec<u8>,  // Extract via bytes_x_y()
    ephemeral_public_key_y: Vec<u8>,
    encrypted_message: Vec<u8>,       // Extract via bytes()
    auth_hash: Vec<u8>,
    public_signing_key: Vec<u8>,
    signature: Vec<u8>,
}

// Serialize
let (x, y) = public_key.bytes_x_y();
let msg = encrypted_message.bytes();
// ... build SerializableEncryptedValue

// Deserialize
let pk = PublicKey::new((x, y))?;
let msg = EncryptedMessage::new_from_slice(bytes)?;
// ... rebuild EncryptedValue
```

## Error Handling Philosophy

### Error Code Design

```rust
pub enum ErrorCode {
    RecryptError = 1000,      // 1xxx: Crypto errors
    InvalidPrivateKey = 2000,  // 2xxx: Key errors
    BIP39Error = 3000,         // 3xxx: Mnemonic errors
    SerdeError = 4000,         // 4xxx: Serialization
    Ed25519Error = 5000,       // 5xxx: Signature
    IntegrityCheckFailed = 6000, // 6xxx: Integrity
    InvalidKdfParams = 7000,   // 7xxx: KDF
    WeakPassword = 8000,       // 8xxx: Password
    InvalidInput = 9000,       // 9xxx: Input validation
    UnsupportedVersion = 10000, // 10xxx: Version
    InvalidIV = 11000,         // 11xxx: IV
    NotImplemented = 12000,    // 12xxx: Not implemented
    InvalidData = 13000,       // 13xxx: Data errors
}
```

**Design Rationale**:
- Grouped by category (1000s)
- Easy to identify error source
- Supports i18n lookup
- WASM-friendly (can serialize as number)

### Error Propagation

```rust
// Internal functions return Result
pub fn aes_encrypt(...) -> Result<Vec<u8>, CryptoError> {
    // ...
}

// Use ? operator for clean propagation
pub fn encrypt(...) -> Result<JsValue, CryptoError> {
    let ciphertext = aes_encrypt(...)?;  // Auto-propagate
    // ...
}

// Convert to JsValue for WASM
impl From<CryptoError> for JsValue {
    fn from(error: CryptoError) -> Self {
        JsValue::from_str(&error.to_string())
    }
}
```

## Memory Management

### Zeroization Details

**What Gets Zeroized**:
```rust
// Automatic (via Zeroize derive)
KeypairResult {
    private_key: Vec<u8>,  // Zeroized on drop
    mnemonic: String,      // Zeroized on drop
}

// Manual (explicit calls)
let mut key = derive_key_pbkdf2(...);
// ... use key ...
key.zeroize();  // Explicit clear
```

**Implementation**:
```rust
use zeroize::Zeroize;

impl Drop for KeypairResult {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.mnemonic.zeroize();
    }
}
```

**Why Important**:
- Prevents memory dumps from revealing keys
- Protects against cold boot attacks
- Clears heap after use
- Defense against Heartbleed-style bugs

### WebAssembly Memory Model

```
┌─────────────────────────────────┐
│     JavaScript Heap             │
│  (Garbage collected)            │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│    WebAssembly Linear Memory    │
│  (Manual management)            │
│                                 │
│  ┌──────────────────────────┐  │
│  │  Rust allocations        │  │
│  │  (Box, Vec, String)      │  │
│  │                          │  │
│  │  Zeroized on drop ✅     │  │
│  └──────────────────────────┘  │
└─────────────────────────────────┘
```

## Constant-Time Operations

### Why Constant-Time?

**Vulnerable Code**:
```rust
// ❌ BAD: Timing leak
fn compare_mac(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;  // Early return reveals position!
        }
    }
    true
}
```

**Timing Attack**:
- Attacker measures time to rejection
- Shorter time = failed earlier
- Can determine correct bytes one by one

**Secure Code**:
```rust
// ✅ GOOD: Constant-time
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()  // subtle crate
}
```

**How It Works**:
- Always compares all bytes
- Time doesn't reveal position
- Prevents timing side-channel

### Used In

- MAC verification
- Password comparison  
- Key comparison
- Any security-critical comparison

## Streaming Implementation

### Chunk State Machine

```
StreamEncryptor State:
┌─────────────────┐
│ chunk_index = 0 │
└────────┬────────┘
         │
    encryptChunk()
         │
         ▼
┌─────────────────┐
│ chunk_index = 1 │
└────────┬────────┘
         │
    encryptChunk()
         │
         ▼
┌─────────────────┐
│ chunk_index = 2 │
└─────────────────┘

reset() → back to 0
```

### Chunk Integrity Chain

Each chunk is independently authenticated:

```
Chunk N:
• Unique nonce (12 bytes random)
• Ciphertext = AES-GCM(data, key, nonce)
• Hash = SHA-256(ciphertext)

No chain dependency:
✅ Chunks can be verified independently
✅ Parallel decryption possible
✅ Random access to chunks
```

**vs. CBC Mode** (for comparison):
```
CBC (chained):
C[0] = Encrypt(P[0] ⊕ IV)
C[1] = Encrypt(P[1] ⊕ C[0])  ← Depends on previous!
C[2] = Encrypt(P[2] ⊕ C[1])  ← Chain

Problem: Cannot decrypt chunk 2 without chunk 1
```

## WASM-Rust Boundary

### Type Conversions

**JavaScript → Rust**:
```javascript
// JavaScript
const data = new Uint8Array([1, 2, 3]);
sdk.encrypt(data, publicKey);
```

```rust
// Rust receives
pub fn encrypt(&self, data: &[u8], public_key: &[u8]) -> Result<JsValue, CryptoError>
                      // ↑ borrowed slice, no copy
```

**Rust → JavaScript**:
```rust
// Rust returns
let result = vec![1, 2, 3];
Ok(result)  // Vec<u8> → Uint8Array automatically
```

### JsValue Conversions

**Complex Objects**:
```rust
// Serialize to JsValue
let keypair = KeypairResult { ... };
serde_wasm_bindgen::to_value(&keypair)?

// Deserialize from JsValue
let capsule: Capsule = serde_wasm_bindgen::from_value(js_value)?
```

**Performance**:
- Small objects: ~0.01ms
- Large objects (1MB): ~1-2ms
- Minimal overhead

## Recrypt Library Integration

### Transform Key Limitation

**Problem**: TransformKey contains private internal fields

```rust
pub struct TransformKey {
    // Internal: Cannot access
    // Cannot serialize safely
}
```

**Our Solution**: Server-side model

```
Client:
• Generate transform key
• Send to server immediately
• Never serialize/deserialize

Server:
• Store transform key in memory
• Use directly for transformation
• Never send back to client
```

### EncryptedValue Handling

```rust
// recrypt library
pub enum EncryptedValue {
    EncryptedOnceValue {
        ephemeral_public_key: PublicKey,
        encrypted_message: EncryptedMessage,
        auth_hash: AuthHash,
        public_signing_key: PublicSigningKey,
        signature: Ed25519Signature,
    },
    TransformedValue { ... }
}
```

**Our Wrapper**:
- Extract all fields via public API
- Store as plain bytes
- Reconstruct when needed
- Only support EncryptedOnceValue (client-side)
- TransformedValue handled server-side

## Validation Pipeline

### Input Validation Order

```
1. Type validation (length, format)
   ├─► Private key: 32 bytes
   ├─► Public key: 64 bytes
   ├─► Password: 12-128 chars
   └─► IV: 12 bytes

2. Semantic validation
   ├─► Public key not all-zero
   ├─► Public key not all-0xFF
   ├─► Password complexity check
   └─► Mnemonic in wordlist

3. Cryptographic validation
   ├─► Point-on-curve check (PublicKey::new)
   ├─► Scalar validity (PrivateKey::new_from_slice)
   └─► Signature verification

4. Anti-replay validation
   ├─► Timestamp within window
   ├─► Request ID not used
   └─► Sequence number valid

5. Integrity validation
   ├─► Hash matches
   ├─► MAC verifies
   └─► GCM tag authentic
```

### Fail-Fast Principle

Validate early, fail fast:

```rust
pub fn encrypt(&self, data: &[u8], public_key: &[u8]) -> Result<...> {
    // Validate immediately
    validation::validate_data_not_empty(data, &self.i18n)?;
    let public_key = self.validate_and_parse_public_key(public_key)?;
    
    // Only proceed if valid
    // ...
}
```

Benefits:
- Saves computation on invalid input
- Clear error messages
- Security: reject early

## JavaScript BigInt Handling

### Problem: JS Number Precision

```javascript
// JavaScript Number
const maxSafe = Number.MAX_SAFE_INTEGER;  // 2^53 - 1

// Rust u64
const rustMax = 2^64 - 1;  // Much larger!

// Precision loss
const bigNumber = 9007199254740993;  // 2^53 + 1
console.log(bigNumber === 9007199254740992);  // true! (loss)
```

### Solution: Serialize as String

```rust
#[serde(with = "u64_as_string")]
pub sequence: u64,

mod u64_as_string {
    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
```

**Result**:
```json
{
    "sequence": "18446744073709551615"  // As string, no loss
}
```

## Performance Profiling Results

### Bottleneck Analysis

```
Operation breakdown for encrypt(1MB data):

1. Validation:           0.1ms   (0.05%)
2. recrypt operations:   5ms     (2.5%)
3. AES-256-GCM:         190ms    (95%)
4. Serialization:        5ms     (2.5%)
────────────────────────────────────────
Total:                  200ms   (100%)
```

**Insight**: AES-GCM dominates - hardware acceleration critical

### Optimization Opportunities

**Rejected**: WebAssembly SIMD
- Reason: Limited browser support
- Benefit: ~2x speedup
- Trade-off: Not worth compatibility loss

**Accepted**: Release profile optimization
```toml
opt-level = "z"  # Size optimization
lto = true       # Link-time optimization
```
Result: 512KB (vs 2MB+ without optimization)

## Testing Strategy

### Unit Tests (TODO)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sdk = EncryptSDK::new();
        let keypair = sdk.generateKeypair(None).unwrap();
        let data = b"test data";
        let encrypted = sdk.encrypt(data, &keypair.public_key).unwrap();
        let decrypted = sdk.decrypt(
            encrypted.capsule,
            &keypair.private_key,
            &encrypted.c_data
        ).unwrap();
        assert_eq!(data, &decrypted[..]);
    }
}
```

### Integration Tests (TODO)

```javascript
// WASM integration test
describe('EncryptSDK', () => {
    let sdk;
    
    beforeAll(async () => {
        await init();
        sdk = new EncryptSDK();
    });
    
    test('full encryption flow', () => {
        const keypair = sdk.generateKeypair();
        expect(keypair.private_key.length).toBe(32);
        expect(keypair.public_key.length).toBe(64);
        expect(keypair.mnemonic.split(' ').length).toBe(24);
    });
});
```

## Future Optimization Ideas

1. **Batch Operations**: Encrypt multiple files in one call
2. **Parallel Processing**: Multi-threaded encryption (wasm-threads)
3. **Hardware Acceleration**: WebGPU for AES
4. **Incremental Hashing**: For large files
5. **Zero-Copy**: Reduce memory allocations

