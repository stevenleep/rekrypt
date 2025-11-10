# Streaming Encryption Guide

## Overview

For large files that don't fit in memory, use chunked streaming encryption.

## StreamEncryptor

### Basic Usage

```javascript
import { StreamEncryptor } from 'rekrypt';

const key = sdk.generateRandomBytes(32);
const chunkSize = 1024 * 1024; // 1MB
const encryptor = new StreamEncryptor(key, chunkSize);

// Encrypt chunks
const chunk1 = encryptor.encryptChunk(data1);
const chunk2 = encryptor.encryptChunk(data2);
```

### Large File Example

```javascript
async function encryptLargeFile(file, key) {
    const chunkSize = 1024 * 1024;
    const encryptor = new StreamEncryptor(key, chunkSize);
    const encryptedChunks = [];
    
    for (let offset = 0; offset < file.size; offset += chunkSize) {
        const chunk = file.slice(offset, offset + chunkSize);
        const arrayBuffer = await chunk.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);
        
        const encrypted = encryptor.encryptChunk(data);
        encryptedChunks.push(encrypted);
        
        // Update progress
        const progress = (offset / file.size * 100).toFixed(1);
        updateProgress(progress);
    }
    
    return encryptedChunks;
}
```

### With Progress Callback

```javascript
async function encryptWithProgress(file, key, onProgress) {
    const chunkSize = 1024 * 1024;
    const encryptor = new StreamEncryptor(key, chunkSize);
    const chunks = [];
    
    let processed = 0;
    
    for (let offset = 0; offset < file.size; offset += chunkSize) {
        const chunk = file.slice(offset, offset + chunkSize);
        const data = new Uint8Array(await chunk.arrayBuffer());
        
        const encrypted = encryptor.encryptChunk(data);
        chunks.push(encrypted);
        
        processed += data.length;
        onProgress(processed, file.size);
    }
    
    return chunks;
}

// Usage
await encryptWithProgress(file, key, (current, total) => {
    console.log(`${(current / total * 100).toFixed(1)}%`);
});
```

## StreamDecryptor

### Basic Usage

```javascript
import { StreamDecryptor } from 'rekrypt';

const decryptor = new StreamDecryptor(key, chunkSize);

// Decrypt chunks in order
const plaintext1 = decryptor.decryptChunk(encrypted1);
const plaintext2 = decryptor.decryptChunk(encrypted2);
```

### Large File Decryption

```javascript
async function decryptLargeFile(encryptedChunks, key) {
    const chunkSize = 1024 * 1024;
    const decryptor = new StreamDecryptor(key, chunkSize);
    const decryptedParts = [];
    
    for (const encryptedChunk of encryptedChunks) {
        const plaintext = decryptor.decryptChunk(encryptedChunk);
        decryptedParts.push(plaintext);
    }
    
    return new Blob(decryptedParts);
}
```

## Web Worker Integration

For non-blocking encryption of large files:

```javascript
// worker.js
importScripts('./pkg/rekrypt.js');

self.onmessage = async (e) => {
    const { wasm, key, chunks } = e.data;
    
    await wasm_bindgen(wasm);
    const { StreamEncryptor } = wasm_bindgen;
    
    const encryptor = new StreamEncryptor(key, 1024 * 1024);
    const encrypted = [];
    
    for (let i = 0; i < chunks.length; i++) {
        encrypted.push(encryptor.encryptChunk(chunks[i]));
        self.postMessage({ type: 'progress', current: i + 1, total: chunks.length });
    }
    
    self.postMessage({ type: 'done', encrypted });
};

// main.js
const worker = new Worker('worker.js');

worker.onmessage = (e) => {
    if (e.data.type === 'progress') {
        console.log(`${e.data.current}/${e.data.total}`);
    } else if (e.data.type === 'done') {
        console.log('Encryption complete!', e.data.encrypted);
    }
};

// Start encryption
const wasmBytes = await fetch('./pkg/rekrypt_bg.wasm').then(r => r.arrayBuffer());
worker.postMessage({ wasm: wasmBytes, key, chunks });
```

## Chunk Metadata

Each encrypted chunk contains:

```typescript
interface EncryptedChunk {
    chunk_index: number;    // Sequential index
    nonce: Uint8Array;      // Unique IV (12 bytes)
    ciphertext: Uint8Array; // Encrypted data
    chunk_hash: Uint8Array; // SHA-256 integrity hash
}
```

## Error Handling

```javascript
try {
    const encrypted = encryptor.encryptChunk(chunk);
} catch (e) {
    if (e.message.includes('exceeds maximum')) {
        console.error('Chunk too large');
    } else if (e.message.includes('empty')) {
        console.error('Empty chunk');
    }
}

try {
    const plaintext = decryptor.decryptChunk(encrypted);
} catch (e) {
    if (e.message.includes('Index mismatch')) {
        console.error('Chunks out of order');
    } else if (e.message.includes('integrity')) {
        console.error('Chunk corrupted');
    }
}
```

## Best Practices

1. **Chunk Size**: 1MB is a good balance (memory vs. performance)
2. **Order**: Decrypt chunks in the same order as encryption
3. **Metadata**: Store chunk count and total size separately
4. **Verification**: Verify all chunks before combining
5. **Progress**: Show progress for user experience

## Performance Tips

```javascript
// Use appropriate chunk size
const chunkSize = Math.min(file.size / 100, 5 * 1024 * 1024); // Max 5MB

// Process in parallel (if order doesn't matter)
const promises = chunks.map(chunk => 
    new Promise(resolve => {
        const encrypted = encryptor.encryptChunk(chunk);
        resolve(encrypted);
    })
);
await Promise.all(promises);

// Use Web Workers for large files
if (file.size > 50 * 1024 * 1024) { // > 50MB
    useWebWorker(file);
}
```

