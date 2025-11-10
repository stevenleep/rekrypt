# Usage Examples

## WebAssembly (Browser/Node.js)

### Basic Encryption

```javascript
import init, { EncryptSDK } from 'rekrypt';

await init();
const sdk = new EncryptSDK();

// Generate keypair
const alice = sdk.generateKeypair();
console.log('Save mnemonic:', alice.mnemonic);

// Encrypt
const data = new TextEncoder().encode('Secret message');
const encrypted = sdk.encrypt(data, alice.public_key);

// Decrypt
const decrypted = sdk.decrypt(
    encrypted.capsule,
    alice.private_key,
    encrypted.c_data
);

console.log(new TextDecoder().decode(decrypted));
```

## Keystore Usage

```javascript
// Create password-protected keystore
const password = 'MySecure@Pass123';
sdk.validatePasswordStrength(password); // Check first

const keystore = sdk.createKeystore(alice, password);
localStorage.setItem('keystore', JSON.stringify(keystore));

// Later: unlock keystore
const storedKeystore = JSON.parse(localStorage.getItem('keystore'));
const privateKey = sdk.unlockKeystore(storedKeystore, password);

// Or get full keypair
const keypair = sdk.recoverKeypairFromKeystore(storedKeystore, password);
```

## Mnemonic Recovery

```javascript
// User lost keystore but has mnemonic
const mnemonic = prompt('Enter your 24-word mnemonic:');

if (sdk.validateMnemonic(mnemonic)) {
    const recovered = sdk.recoverKeypair(mnemonic);
    
    // Create new keystore
    const newPassword = prompt('Set new password:');
    const keystore = sdk.createKeystore(recovered, newPassword);
    localStorage.setItem('keystore', JSON.stringify(keystore));
}
```

## File Encryption

```javascript
// Read file
const file = document.getElementById('file').files[0];
const arrayBuffer = await file.arrayBuffer();
const fileData = new Uint8Array(arrayBuffer);

// Compute hash for integrity
const originalHash = sdk.hashData(fileData);
console.log('File hash:', sdk.bytesToHex(originalHash));

// Encrypt
const encrypted = sdk.encrypt(fileData, recipientPublicKey);

// Save encrypted file
const blob = new Blob([encrypted.c_data]);
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = file.name + '.encrypted';
a.click();

// Save capsule for decryption
localStorage.setItem('capsule', JSON.stringify(encrypted.capsule));
```

## Streaming Large Files

```javascript
import { StreamEncryptor, StreamDecryptor } from 'rekrypt';

// Encrypt large file in chunks
const key = sdk.generateRandomBytes(32);
const chunkSize = 1024 * 1024; // 1MB
const encryptor = new StreamEncryptor(key, chunkSize);

const encryptedChunks = [];
for (let offset = 0; offset < file.size; offset += chunkSize) {
    const chunk = file.slice(offset, offset + chunkSize);
    const data = await chunk.arrayBuffer();
    const encrypted = encryptor.encryptChunk(new Uint8Array(data));
    encryptedChunks.push(encrypted);
    
    console.log(`Progress: ${(offset / file.size * 100).toFixed(1)}%`);
}

// Decrypt
const decryptor = new StreamDecryptor(key, chunkSize);
const decryptedParts = [];

for (const encrypted of encryptedChunks) {
    const plaintext = decryptor.decryptChunk(encrypted);
    decryptedParts.push(plaintext);
}

const result = new Blob(decryptedParts);
```

## Proxy Re-Encryption

```javascript
// 1. Alice encrypts data
const alice = sdk.generateKeypair();
const bob = sdk.generateKeypair();

const data = new TextEncoder().encode('Confidential document');
const encrypted = sdk.encrypt(data, alice.public_key);

// 2. Alice grants access to Bob
const transformKey = sdk.generateTransformKey(
    alice.private_key,
    bob.public_key,
    encrypted.capsule.signing_key_pair
);

// 3. Send to business server
const capsuleBytes = sdk.serializeCapsule(encrypted.capsule);
await fetch('/api/share', {
    method: 'POST',
    body: JSON.stringify({
        ciphertext: Array.from(encrypted.c_data),
        capsule: Array.from(capsuleBytes),
        transformKey: Array.from(transformKey),
        recipient: 'bob@example.com'
    })
});

// 4. Server forwards to proxy for transformation
// (See service/transform/ for server implementation)

// 5. Bob retrieves and decrypts
const response = await fetch('/api/get-shared');
const { transformedCapsule, transformedData } = await response.json();

const capsule = sdk.deserializeCapsule(new Uint8Array(transformedCapsule));
const plaintext = sdk.decryptDelegated(
    capsule,
    transformKey,
    bob.private_key,
    new Uint8Array(transformedData)
);
```

## Key Validation

```javascript
// Verify keypair integrity
const isValid = sdk.verifyKeypairMatch(
    keypair.private_key,
    keypair.public_key
);

if (!isValid) {
    throw new Error('Keypair corrupted!');
}

// Validate keys before important operations
sdk.validatePrivateKey(privateKey);
sdk.validatePublicKey(publicKey);
```

## Data Integrity

```javascript
// Use HMAC for data authentication
const secretKey = sdk.generateRandomBytes(32);
const data = new TextEncoder().encode('Important data');

// Compute MAC
const mac = sdk.computeHmac(secretKey, data);

// Later: verify integrity
if (!sdk.verifyHmac(secretKey, data, mac)) {
    throw new Error('Data has been tampered!');
}
```

## Import from External Wallet

```javascript
// User has private key from another wallet
const externalPrivateKey = sdk.hexToBytes('0x1234...');

// Validate
sdk.validatePrivateKey(externalPrivateKey);

// Reconstruct to our format
const keypair = sdk.reconstructKeypair(externalPrivateKey);

// Create keystore
const keystore = sdk.createKeystore(keypair, password);

// ⚠️ Note: No mnemonic available for recovery
// User must keep keystore safe!
```

## Native FFI Library

### Go Example

```go
package main

/*
#cgo LDFLAGS: -L./rekrypt-ffi/lib/linux-x64 -lrekrypt_ffi
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

func main() {
    // Get version
    version := C.rekrypt_version()
    fmt.Printf("Rekrypt FFI version: %d\n", version)
    
    // Generate keypair
    var privKey, pubKey C.ByteArray
    result := C.rekrypt_generate_keypair(&privKey, &pubKey)
    
    if result != 0 {
        fmt.Println("Failed to generate keypair")
        return
    }
    
    defer C.rekrypt_free_byte_array(&privKey)
    defer C.rekrypt_free_byte_array(&pubKey)
    
    // Convert to Go bytes
    privKeyBytes := C.GoBytes(unsafe.Pointer(privKey.data), C.int(privKey.len))
    pubKeyBytes := C.GoBytes(unsafe.Pointer(pubKey.data), C.int(pubKey.len))
    
    fmt.Printf("Private key: %d bytes\n", len(privKeyBytes))
    fmt.Printf("Public key: %d bytes\n", len(pubKeyBytes))
}
```

### Python Example

```python
import ctypes
import platform
from pathlib import Path

# Load library
system = platform.system()
if system == "Linux":
    lib_path = "rekrypt-ffi/lib/linux-x64/librekrypt_ffi.so"
elif system == "Darwin":
    lib_path = "rekrypt-ffi/lib/macos-arm64/librekrypt_ffi.dylib"
elif system == "Windows":
    lib_path = "rekrypt-ffi/lib/windows-x64/rekrypt_ffi.dll"

lib = ctypes.CDLL(lib_path)

# Define structures
class ByteArray(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t)
    ]

# Define functions
lib.rekrypt_version.restype = ctypes.c_int
lib.rekrypt_generate_keypair.argtypes = [
    ctypes.POINTER(ByteArray),
    ctypes.POINTER(ByteArray)
]
lib.rekrypt_generate_keypair.restype = ctypes.c_int
lib.rekrypt_free_byte_array.argtypes = [ctypes.POINTER(ByteArray)]

# Use library
print(f"Rekrypt version: {lib.rekrypt_version()}")

priv_key = ByteArray()
pub_key = ByteArray()

if lib.rekrypt_generate_keypair(ctypes.byref(priv_key), ctypes.byref(pub_key)) == 0:
    try:
        priv_bytes = bytes(priv_key.data[:priv_key.len])
        pub_bytes = bytes(pub_key.data[:pub_key.len])
        
        print(f"Private key: {len(priv_bytes)} bytes")
        print(f"Public key: {len(pub_bytes)} bytes")
    finally:
        lib.rekrypt_free_byte_array(ctypes.byref(priv_key))
        lib.rekrypt_free_byte_array(ctypes.byref(pub_key))
```

### C Example

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
    
    if (rekrypt_generate_keypair(&priv_key, &pub_key) == 0) {
        printf("Private key: %zu bytes\n", priv_key.len);
        printf("Public key: %zu bytes\n", pub_key.len);
        
        rekrypt_free_byte_array(&priv_key);
        rekrypt_free_byte_array(&pub_key);
    } else {
        printf("Failed to generate keypair\n");
        return 1;
    }
    
    return 0;
}
```

Compile: `gcc -o example example.c -L./rekrypt-ffi/lib/linux-x64 -lrekrypt_ffi`

