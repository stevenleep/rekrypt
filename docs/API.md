# API Reference

## EncryptSDK

### Constructor

```javascript
import init, { EncryptSDK } from 'rekrypt';
await init();
const sdk = new EncryptSDK();
```

### Language

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

