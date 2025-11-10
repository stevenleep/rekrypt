# Usage Examples

## Basic Encryption

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

