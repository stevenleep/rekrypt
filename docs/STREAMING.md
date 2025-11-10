# Streaming Encryption Guide

## Overview

For large files that don't fit in memory, use chunked streaming encryption.

## Platform Support

| Platform | Support | Implementation |
|----------|---------|----------------|
| Browser (WASM) | Yes | StreamEncryptor/StreamDecryptor classes |
| Node.js (WASM) | Yes | Same API, use fs.createReadStream |
| FFI Library | Partial | Manual chunk handling required |
| Transform Service | N/A | Not applicable |

**Note**: FFI library provides core encryption but requires application-level chunk management.

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

## Node.js Streaming

### Using Streams

```javascript
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { Transform } from 'stream';
import init, { StreamEncryptor } from 'rekrypt';

await init();

// Create encryption transform stream
class EncryptStream extends Transform {
    constructor(key, chunkSize) {
        super();
        this.encryptor = new StreamEncryptor(key, chunkSize);
        this.buffer = Buffer.alloc(0);
    }
    
    _transform(chunk, encoding, callback) {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        
        while (this.buffer.length >= this.chunkSize) {
            const toEncrypt = this.buffer.slice(0, this.chunkSize);
            this.buffer = this.buffer.slice(this.chunkSize);
            
            try {
                const encrypted = this.encryptor.encryptChunk(toEncrypt);
                this.push(JSON.stringify(encrypted) + '\n');
            } catch (e) {
                return callback(e);
            }
        }
        callback();
    }
    
    _flush(callback) {
        if (this.buffer.length > 0) {
            try {
                const encrypted = this.encryptor.encryptChunk(this.buffer);
                this.push(JSON.stringify(encrypted) + '\n');
            } catch (e) {
                return callback(e);
            }
        }
        callback();
    }
}

// Usage
const key = sdk.generateRandomBytes(32);
const encryptStream = new EncryptStream(key, 1024 * 1024);

await pipeline(
    createReadStream('large-file.bin'),
    encryptStream,
    createWriteStream('encrypted.chunks')
);
```

## Platform-Specific Performance

### Browser (WASM)

**Characteristics**:
- Memory limit: ~2GB (depends on browser)
- Single-threaded (unless using Workers)
- Good for files up to 1GB

**Optimization**:
```javascript
// Use larger chunks for better performance
const chunkSize = 2 * 1024 * 1024; // 2MB

// For very large files, use Web Workers
if (file.size > 100 * 1024 * 1024) {
    const worker = new Worker('encrypt-worker.js');
    worker.postMessage({ file, key });
}
```

### Node.js (WASM)

**Characteristics**:
- Memory limit: Configurable (--max-old-space-size)
- Can use streams efficiently
- Good for files of any size

**Optimization**:
```javascript
// Increase heap size for large files
// node --max-old-space-size=4096 app.js

// Use backpressure handling
const stream = createReadStream('huge-file.bin', {
    highWaterMark: 1024 * 1024 // 1MB buffer
});
```

### Native (FFI)

**Characteristics**:
- Direct memory access
- No GC overhead
- Best performance for server-side processing

**Implementation**:
```go
// Go example - manual chunk processing
func EncryptFileStreaming(inputPath, outputPath string, key []byte) error {
    input, err := os.Open(inputPath)
    if err != nil {
        return err
    }
    defer input.Close()
    
    output, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer output.Close()
    
    chunkSize := 1024 * 1024 // 1MB
    buffer := make([]byte, chunkSize)
    chunkIndex := 0
    
    for {
        n, err := input.Read(buffer)
        if n > 0 {
            // Encrypt chunk using FFI
            encrypted, err := EncryptChunk(buffer[:n], key, chunkIndex)
            if err != nil {
                return err
            }
            
            // Write to output
            if _, err := output.Write(encrypted); err != nil {
                return err
            }
            
            chunkIndex++
        }
        
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }
    }
    
    return nil
}
```

## Performance Comparison

### Throughput by Platform

| Platform | Chunk Size | Throughput | Notes |
|----------|-----------|------------|-------|
| Browser WASM | 1MB | ~50 MB/s | Single thread |
| Node.js WASM | 1MB | ~80 MB/s | Better JIT |
| FFI (Native) | 1MB | ~150 MB/s | No WASM overhead |
| FFI (Native) | 4MB | ~200 MB/s | Larger chunks |

**Note**: Performance varies by hardware and data type.

### Memory Usage by Platform

| Platform | Chunk Size | Peak Memory | Scalability |
|----------|-----------|-------------|-------------|
| Browser | 1MB | ~10MB | Files up to 1GB |
| Node.js | 1MB | ~20MB | Files unlimited |
| FFI Native | 1MB | ~5MB | Files unlimited |

## Performance Tips

### Chunk Size Selection

```javascript
// Small files (< 10MB): Use larger chunks
const smallFileChunkSize = 5 * 1024 * 1024; // 5MB

// Medium files (10-100MB): Balanced
const mediumFileChunkSize = 1 * 1024 * 1024; // 1MB

// Large files (> 100MB): Smaller chunks for better progress tracking
const largeFileChunkSize = 512 * 1024; // 512KB

// Auto-select based on file size
function selectChunkSize(fileSize) {
    if (fileSize < 10 * 1024 * 1024) return 5 * 1024 * 1024;
    if (fileSize < 100 * 1024 * 1024) return 1 * 1024 * 1024;
    return 512 * 1024;
}
```

### Parallel Processing (WebAssembly)

```javascript
// Process multiple chunks in parallel (unordered)
const chunkSize = 1024 * 1024;
const chunks = [];

// Read all chunks
for (let i = 0; i < file.size; i += chunkSize) {
    const chunk = file.slice(i, i + chunkSize);
    chunks.push(chunk);
}

// Encrypt in parallel (each needs its own encryptor)
const encrypted = await Promise.all(
    chunks.map(async (chunk, index) => {
        const data = new Uint8Array(await chunk.arrayBuffer());
        const key = sdk.generateRandomBytes(32);
        const encryptor = new StreamEncryptor(key, chunkSize);
        return encryptor.encryptChunk(data);
    })
);
```

### Web Workers

```javascript
// Main thread
const worker = new Worker('encrypt-worker.js');

worker.postMessage({
    file: file,
    chunkSize: 1024 * 1024
});

worker.onmessage = (e) => {
    if (e.data.type === 'progress') {
        updateProgress(e.data.percent);
    } else if (e.data.type === 'complete') {
        handleEncrypted(e.data.chunks);
    }
};

// encrypt-worker.js
self.onmessage = async (e) => {
    const { file, chunkSize } = e.data;
    
    // Import WASM in worker
    await import('./rekrypt.js');
    const { StreamEncryptor } = await import('rekrypt');
    
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const encryptor = new StreamEncryptor(key, chunkSize);
    
    const chunks = [];
    for (let offset = 0; offset < file.size; offset += chunkSize) {
        const chunk = file.slice(offset, offset + chunkSize);
        const data = new Uint8Array(await chunk.arrayBuffer());
        const encrypted = encryptor.encryptChunk(data);
        chunks.push(encrypted);
        
        self.postMessage({
            type: 'progress',
            percent: (offset / file.size * 100)
        });
    }
    
    self.postMessage({
        type: 'complete',
        chunks: chunks
    });
};
```

