# API Reference

## Platform APIs

Rekrypt provides two types of APIs:
1. **WebAssembly API** - For browser and Node.js
2. **FFI API** - For C, Go, Python, and other native languages

---

## WebAssembly API

### EncryptSDK

#### Constructor

```javascript
import init, { EncryptSDK } from 'rekrypt';
await init();
const sdk = new EncryptSDK();
```

#### Language

```javascript
sdk.setLanguage('zh-CN');  // or 'en-US'
```

## Core Methods

### generateKeypair(passphrase?)

Generate new keypair with BIP39 mnemonic.

```javascript
const keypair = sdk.generateKeypair();
// Returns: { private_key, public_key, mnemonic }

const withPass = sdk.generateKeypair("my-passphrase");
```

### encrypt(data, publicKey)

Encrypt data using hybrid encryption.

```javascript
const encrypted = sdk.encrypt(data, recipientPublicKey);
// Returns: { capsule, c_data, c_hash }
```

### decrypt(capsule, privateKey, ciphertext)

Decrypt encrypted data.

```javascript
const plaintext = sdk.decrypt(capsule, privateKey, ciphertext);
```

### recoverKeypair(mnemonic, passphrase?)

Recover keypair from BIP39 mnemonic.

```javascript
const keypair = sdk.recoverKeypair("word1 word2 ... word24");
const withPass = sdk.recoverKeypair(mnemonic, "my-passphrase");
```

### validateMnemonic(mnemonic)

Validate BIP39 mnemonic format.

```javascript
if (sdk.validateMnemonic(userInput)) {
    console.log('Valid mnemonic');
}
```

### validateAndNormalizeMnemonic(mnemonic)

Normalize mnemonic (lowercase, trim).

```javascript
const normalized = sdk.validateAndNormalizeMnemonic("  WORD1  word2  ");
// Returns: "word1 word2"
```

## Keystore Methods

### createKeystore(keypair, password)

Create encrypted keystore (PBKDF2 600k iterations).

```javascript
const keystore = sdk.createKeystore(keypair, password);
```

### unlockKeystore(keystore, password)

Unlock keystore and get private key.

```javascript
const privateKey = sdk.unlockKeystore(keystore, password);
```

### recoverKeypairFromKeystore(keystore, password)

Get full keypair from keystore (mnemonic will be empty).

```javascript
const keypair = sdk.recoverKeypairFromKeystore(keystore, password);
// keypair.mnemonic === "" (cannot recover from keystore)
```

### reconstructKeypair(privateKey)

Build keypair structure from private key.

```javascript
const keypair = sdk.reconstructKeypair(privateKey);
```

### exportPrivateKey(keypair)

Export private key with security warnings.

```javascript
const exported = sdk.exportPrivateKey(keypair);
// Returns: { warning, private_key, safety_tips }
```

## Proxy Re-Encryption

### generateTransformKey(delegatorPrivateKey, delegateePublicKey, signingKeyPair)

Generate transform key for delegation.

```javascript
const transformKey = sdk.generateTransformKey(
    alice.private_key,
    bob.public_key,
    encrypted.capsule.signing_key_pair
);
```

### decryptDelegated(capsule, transformKey, delegateePrivateKey, ciphertext)

Decrypt with transform key (requires server-side proxy).

```javascript
// Not implemented in client SDK
// Use service/transform/ for server-side implementation
```

### serializeCapsule(capsule)

Serialize capsule for network transmission.

```javascript
const bytes = sdk.serializeCapsule(capsule);
```

### deserializeCapsule(bytes)

Deserialize bytes to capsule.

```javascript
const capsule = sdk.deserializeCapsule(bytes);
```

## Utility Methods

### validatePasswordStrength(password)

Validate password strength (12+ chars, 3+ types).

```javascript
sdk.validatePasswordStrength('MyPass123!');
```

### validatePublicKey(publicKey)

Validate public key format.

```javascript
sdk.validatePublicKey(publicKey);
```

### validatePrivateKey(privateKey)

Validate private key format.

```javascript
sdk.validatePrivateKey(privateKey);
```

### verifyKeypairMatch(privateKey, publicKey)

Verify keys belong together.

```javascript
const matches = sdk.verifyKeypairMatch(privateKey, publicKey);
```

### derivePublicKey(privateKey)

Derive public key from private key.

```javascript
const publicKey = sdk.derivePublicKey(privateKey);
```

### hashData(data)

Compute SHA-256 hash.

```javascript
const hash = sdk.hashData(data);
```

### generateRandomBytes(length)

Generate cryptographically secure random bytes.

```javascript
const random = sdk.generateRandomBytes(32);
```

### computeHmac(key, data)

Compute HMAC-SHA256.

```javascript
const mac = sdk.computeHmac(key, data);
```

### verifyHmac(key, data, expectedMac)

Verify HMAC tag (constant-time).

```javascript
const valid = sdk.verifyHmac(key, data, mac);
```

### generateUuid()

Generate UUID v4.

```javascript
const uuid = sdk.generateUuid();
```

### bytesToHex(bytes) / hexToBytes(hex)

Convert between bytes and hex.

```javascript
const hex = sdk.bytesToHex(bytes);
const bytes = sdk.hexToBytes('0xdeadbeef');
```

### getVersion()

Get SDK version.

```javascript
const version = sdk.getVersion();
```

## StreamEncryptor

### Constructor

```javascript
import { StreamEncryptor } from 'rekrypt';
const encryptor = new StreamEncryptor(key, chunkSize);
```

### encryptChunk(chunkData)

Encrypt a chunk of data.

```javascript
const encrypted = encryptor.encryptChunk(chunk);
// Returns: { chunk_index, nonce, ciphertext, chunk_hash }
```

### getChunkIndex()

Get current chunk index.

```javascript
const index = encryptor.getChunkIndex();
```

### reset()

Reset chunk counter.

```javascript
encryptor.reset();
```

## StreamDecryptor

### Constructor

```javascript
import { StreamDecryptor } from 'rekrypt';
const decryptor = new StreamDecryptor(key, chunkSize);
```

### decryptChunk(encryptedChunk)

Decrypt a chunk.

```javascript
const plaintext = decryptor.decryptChunk(encryptedChunk);
```

### getChunkIndex()

Get current chunk index.

```javascript
const index = decryptor.getChunkIndex();
```

### reset()

Reset chunk counter.

```javascript
decryptor.reset();
```

---

## FFI API (C/Go/Python/Native)

The FFI library provides C-compatible functions for native integration with C, C++, Go, Python, Node.js (FFI), and other languages.

### Platform Support

| Platform | Dynamic Library | Static Library |
|----------|----------------|----------------|
| Linux x64 | `librekrypt_ffi.so` | `librekrypt_ffi.a` |
| Linux ARM64 | `librekrypt_ffi.so` | `librekrypt_ffi.a` |
| Windows x64 | `rekrypt_ffi.dll` | `librekrypt_ffi.a` |
| macOS x64 | `librekrypt_ffi.dylib` | `librekrypt_ffi.a` |
| macOS ARM64 | `librekrypt_ffi.dylib` | `librekrypt_ffi.a` |

### Data Structures

#### ByteArray

```c
typedef struct {
    uint8_t *data;  // Pointer to data
    size_t len;     // Length in bytes
} ByteArray;
```

Memory allocated by the library must be freed using `rekrypt_free_byte_array()`.

### Core Functions

#### rekrypt_version

Get library version number.

```c
int rekrypt_version();
```

**Returns**: Version number (e.g., 200 for v0.2.0)

**Example**:
```c
int version = rekrypt_version();
printf("Rekrypt FFI version: %d\n", version);
```

#### rekrypt_generate_keypair

Generate a new encryption keypair.

```c
int rekrypt_generate_keypair(
    ByteArray *out_private_key,
    ByteArray *out_public_key
);
```

**Parameters**:
- `out_private_key`: Output buffer for private key (32 bytes)
- `out_public_key`: Output buffer for public key (64 bytes)

**Returns**: 
- `0` on success
- Non-zero on error (call `rekrypt_get_last_error()`)

**Example (C)**:
```c
ByteArray priv_key, pub_key;

if (rekrypt_generate_keypair(&priv_key, &pub_key) == 0) {
    printf("Private key: %zu bytes\n", priv_key.len);
    printf("Public key: %zu bytes\n", pub_key.len);
    
    // Always free
    rekrypt_free_byte_array(&priv_key);
    rekrypt_free_byte_array(&pub_key);
} else {
    const char* error = rekrypt_get_last_error();
    fprintf(stderr, "Error: %s\n", error);
    rekrypt_free_error(error);
}
```

**Example (Go)**:
```go
var privKey, pubKey C.ByteArray
result := C.rekrypt_generate_keypair(&privKey, &pubKey)

if result != 0 {
    errorMsg := C.rekrypt_get_last_error()
    defer C.rekrypt_free_error(errorMsg)
    return fmt.Errorf("%s", C.GoString(errorMsg))
}

defer C.rekrypt_free_byte_array(&privKey)
defer C.rekrypt_free_byte_array(&pubKey)

privKeyBytes := C.GoBytes(unsafe.Pointer(privKey.data), C.int(privKey.len))
pubKeyBytes := C.GoBytes(unsafe.Pointer(pubKey.data), C.int(pubKey.len))
```

#### rekrypt_generate_signing_keypair

Generate Ed25519 signing keypair.

```c
int rekrypt_generate_signing_keypair(
    ByteArray *out_signing_keypair
);
```

**Parameters**:
- `out_signing_keypair`: Output for signing keypair (96 bytes)

**Returns**: `0` on success, non-zero on error

#### rekrypt_generate_transform_key

Generate transform key for proxy re-encryption.

```c
int rekrypt_generate_transform_key(
    const uint8_t *delegator_private_key,
    size_t delegator_private_key_len,
    const uint8_t *delegatee_public_key,
    size_t delegatee_public_key_len,
    const uint8_t *signing_keypair,
    size_t signing_keypair_len,
    ByteArray *out_transform_key
);
```

**Parameters**:
- `delegator_private_key`: Alice's private key (32 bytes)
- `delegator_private_key_len`: Length (must be 32)
- `delegatee_public_key`: Bob's public key (64 bytes)
- `delegatee_public_key_len`: Length (must be 64)
- `signing_keypair`: Signing keypair (96 bytes)
- `signing_keypair_len`: Length (must be 96)
- `out_transform_key`: Output transform key

**Returns**: `0` on success, non-zero on error

#### rekrypt_encrypt

Encrypt plaintext data.

```c
int rekrypt_encrypt(
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *public_key,
    size_t public_key_len,
    ByteArray *out_capsule,
    ByteArray *out_ciphertext
);
```

**Parameters**:
- `plaintext`: Data to encrypt
- `plaintext_len`: Data length in bytes
- `public_key`: Recipient's public key (64 bytes)
- `public_key_len`: Length (must be 64)
- `out_capsule`: Output for encrypted capsule metadata
- `out_ciphertext`: Output for encrypted data

**Returns**: `0` on success, non-zero on error

**Note**: Both `out_capsule` and `out_ciphertext` must be freed after use.

#### rekrypt_transform

Transform encrypted data (proxy server operation).

```c
int rekrypt_transform(
    const uint8_t *encrypted_value,
    size_t encrypted_value_len,
    const uint8_t *transform_key,
    size_t transform_key_len,
    const uint8_t *signing_keypair,
    size_t signing_keypair_len,
    ByteArray *out_transformed
);
```

**Parameters**:
- `encrypted_value`: Serialized encrypted value
- `encrypted_value_len`: Length
- `transform_key`: Transform key from delegator to delegatee
- `transform_key_len`: Length
- `signing_keypair`: Signing keypair for verification (96 bytes)
- `signing_keypair_len`: Length (must be 96)
- `out_transformed`: Output transformed value

**Returns**: `0` on success, non-zero on error

#### rekrypt_decrypt_delegated

Decrypt transformed ciphertext.

```c
int rekrypt_decrypt_delegated(
    const uint8_t *alice_private_key,
    size_t alice_private_key_len,
    const uint8_t *alice_public_key,
    size_t alice_public_key_len,
    const uint8_t *bob_public_key,
    size_t bob_public_key_len,
    const uint8_t *signing_keypair,
    size_t signing_keypair_len,
    const uint8_t *transformed_capsule,
    size_t transformed_capsule_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    ByteArray *out_result
);
```

**Returns**: `0` on success, non-zero on error

### Memory Management

#### rekrypt_free_byte_array

Free ByteArray structure allocated by the library.

```c
void rekrypt_free_byte_array(ByteArray *arr);
```

**Critical**: Always call this for every ByteArray returned by the library to prevent memory leaks.

**Best Practice**:
```c
// C
ByteArray result;
if (rekrypt_some_function(&result) == 0) {
    // Use result...
    rekrypt_free_byte_array(&result);  // Don't forget!
}

// Go
defer C.rekrypt_free_byte_array(&result)

// Python
try:
    # Use result...
finally:
    lib.rekrypt_free_byte_array(ctypes.byref(result))
```

### Error Handling

#### rekrypt_get_last_error

Get detailed error message for the last failed operation.

```c
const char* rekrypt_get_last_error();
```

**Returns**: 
- Pointer to UTF-8 error string if error occurred
- NULL if no error

**Thread Safety**: Error storage is thread-local.

**Example**:
```c
if (rekrypt_generate_keypair(&priv_key, &pub_key) != 0) {
    const char* error = rekrypt_get_last_error();
    if (error != NULL) {
        fprintf(stderr, "Error: %s\n", error);
        rekrypt_free_error(error);
    }
}
```

#### rekrypt_free_error

Free error string returned by `rekrypt_get_last_error()`.

```c
void rekrypt_free_error(const char *error);
```

### Return Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Success | Continue |
| `-1` | Error | Call `rekrypt_get_last_error()` |
| `-2` | Invalid parameter | Check input values |
| `-3` | Memory allocation failed | Reduce data size or free memory |
| `-4` | Serialization error | Check data format |

### Complete Example (C)

```c
#include <stdio.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len;
} ByteArray;

extern int rekrypt_version();
extern int rekrypt_generate_keypair(ByteArray*, ByteArray*);
extern int rekrypt_encrypt(const uint8_t*, size_t, const uint8_t*, size_t, ByteArray*, ByteArray*);
extern void rekrypt_free_byte_array(ByteArray*);
extern const char* rekrypt_get_last_error();
extern void rekrypt_free_error(const char*);

int main() {
    // Version
    printf("Rekrypt version: %d\n", rekrypt_version());
    
    // Generate keypair
    ByteArray priv_key, pub_key;
    if (rekrypt_generate_keypair(&priv_key, &pub_key) != 0) {
        const char* error = rekrypt_get_last_error();
        fprintf(stderr, "Error: %s\n", error);
        rekrypt_free_error(error);
        return 1;
    }
    
    printf("Keypair generated\n");
    printf("  Private: %zu bytes\n", priv_key.len);
    printf("  Public: %zu bytes\n", pub_key.len);
    
    // Encrypt data
    const char* data = "Secret message";
    ByteArray capsule, ciphertext;
    
    int result = rekrypt_encrypt(
        (const uint8_t*)data, strlen(data),
        pub_key.data, pub_key.len,
        &capsule, &ciphertext
    );
    
    if (result == 0) {
        printf("Encrypted successfully\n");
        printf("  Capsule: %zu bytes\n", capsule.len);
        printf("  Ciphertext: %zu bytes\n", ciphertext.len);
        
        rekrypt_free_byte_array(&capsule);
        rekrypt_free_byte_array(&ciphertext);
    }
    
    // Cleanup
    rekrypt_free_byte_array(&priv_key);
    rekrypt_free_byte_array(&pub_key);
    
    return 0;
}
```

Compile:
```bash
gcc -o demo demo.c -L./rekrypt-ffi/lib/linux-x64 -lrekrypt_ffi -Wl,-rpath,./rekrypt-ffi/lib/linux-x64
```

### Platform-Specific Usage

**Dynamic Linking (Recommended for development)**:
```bash
# Linux
export LD_LIBRARY_PATH=./rekrypt-ffi/lib/linux-x64:$LD_LIBRARY_PATH

# macOS
export DYLD_LIBRARY_PATH=./rekrypt-ffi/lib/macos-arm64:$DYLD_LIBRARY_PATH

# Windows
# Copy rekrypt_ffi.dll to same directory as .exe
```

**Static Linking (Recommended for production)**:
```bash
# Link statically for no runtime dependencies
gcc -o app app.c ./rekrypt-ffi/lib/linux-x64/librekrypt_ffi.a -lpthread -ldl -lm
```

For more examples, see:
- [rekrypt-ffi/README.md](../rekrypt-ffi/README.md) - Complete FFI guide
- [EXAMPLES.md](EXAMPLES.md) - Go, Python, C examples
- [CROSS_COMPILE.md](../rekrypt-ffi/CROSS_COMPILE.md) - Building for multiple platforms

