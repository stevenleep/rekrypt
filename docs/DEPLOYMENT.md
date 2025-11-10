# Deployment Guide

## Production Architecture

### Recommended Three-Tier Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Client Layer                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │  Browser   │  │   Mobile   │  │  Desktop   │    │
│  │   (WASM)   │  │    App     │  │    App     │    │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │
│        └─────────────────┼─────────────────┘         │
└──────────────────────────┼───────────────────────────┘
                           │
                    HTTPS (TLS 1.3)
                           │
┌──────────────────────────▼───────────────────────────┐
│              Business Application Server              │
│  ┌──────────────────────────────────────────────┐   │
│  │  • User authentication                       │   │
│  │  • Access control                            │   │
│  │  • Encrypted data storage                    │   │
│  │  • Transform key management                  │   │
│  │  • Request_id deduplication                  │   │
│  │  • Audit logging                             │   │
│  └───────────────────┬──────────────────────────┘   │
└──────────────────────┼───────────────────────────────┘
                       │
                  Internal Network
                       │
┌──────────────────────▼───────────────────────────────┐
│              Proxy Transform Service                  │
│  ┌──────────────────────────────────────────────┐   │
│  │  • Transform key storage                     │   │
│  │  • Ciphertext transformation                 │   │
│  │  • NO access to plaintext                    │   │
│  │  • NO access to private keys                 │   │
│  │  • Rate limiting                             │   │
│  └──────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

### Deployment Options

#### Option 1: Client-Only (No Proxy)

```
Client (Browser/App) ──► Direct encryption/decryption
                          Use: encrypt() / decrypt()
                          No server needed
```

**Use Cases**:
- Local file encryption
- Peer-to-peer sharing
- Offline applications

**Limitations**:
- No delegation features
- No proxy re-encryption

#### Option 2: Client + Business Server

```
Client ──► Business Server ──► Database
           • Store encrypted data
           • Manage keystores
           • User authentication
```

**Use Cases**:
- Cloud storage
- Encrypted backups
- Secure file sharing (direct)

#### Option 3: Full Proxy Re-Encryption (Recommended)

```
Client ──► Business Server ──► Proxy Server
           • Access control    • Transform only
           • Key management    • Zero knowledge
           • Audit logs
```

**Use Cases**:
- Multi-user collaboration
- Delegated access
- Enterprise data sharing
- Healthcare records (HIPAA)

## Business Server Setup

### Database Schema Example

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    keystore JSONB,  -- Encrypted keystore
    created_at TIMESTAMP
);

-- Encrypted files table
CREATE TABLE encrypted_files (
    id UUID PRIMARY KEY,
    owner_id UUID REFERENCES users(id),
    filename VARCHAR(255),
    capsule BYTEA,  -- Serialized capsule
    ciphertext BYTEA,  -- Encrypted data
    file_hash BYTEA,  -- Integrity hash
    created_at TIMESTAMP
);

-- Transform keys table
CREATE TABLE transform_keys (
    id UUID PRIMARY KEY,
    delegator_id UUID REFERENCES users(id),
    delegatee_id UUID REFERENCES users(id),
    file_id UUID REFERENCES encrypted_files(id),
    transform_key BYTEA,
    created_at TIMESTAMP,
    revoked_at TIMESTAMP NULL
);

-- Request ID tracking (anti-replay)
CREATE TABLE used_request_ids (
    request_id VARCHAR(36) PRIMARY KEY,
    used_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Create index for fast lookups
CREATE INDEX idx_request_expires ON used_request_ids(expires_at);
```

### API Endpoints Example

```typescript
// Node.js/Express example
app.post('/api/encrypt-upload', async (req, res) => {
    const { capsule, ciphertext, fileHash } = req.body;
    const userId = req.user.id;
    
    // Validate request_id (anti-replay)
    const requestId = capsule.request_id;
    const exists = await db.query(
        'SELECT 1 FROM used_request_ids WHERE request_id = $1',
        [requestId]
    );
    
    if (exists.rows.length > 0) {
        return res.status(400).json({ error: 'Replay attack detected' });
    }
    
    // Store request_id
    await db.query(
        'INSERT INTO used_request_ids (request_id, used_at, expires_at) VALUES ($1, NOW(), NOW() + INTERVAL \'24 hours\')',
        [requestId]
    );
    
    // Store encrypted file
    await db.query(
        'INSERT INTO encrypted_files (id, owner_id, capsule, ciphertext, file_hash) VALUES ($1, $2, $3, $4, $5)',
        [uuid(), userId, capsule, ciphertext, fileHash]
    );
    
    res.json({ success: true });
});

app.post('/api/grant-access', async (req, res) => {
    const { fileId, recipientEmail, transformKey } = req.body;
    const userId = req.user.id;
    
    // Verify ownership
    const file = await db.query(
        'SELECT * FROM encrypted_files WHERE id = $1 AND owner_id = $2',
        [fileId, userId]
    );
    
    if (file.rows.length === 0) {
        return res.status(403).json({ error: 'Not authorized' });
    }
    
    const recipient = await db.query(
        'SELECT id FROM users WHERE email = $1',
        [recipientEmail]
    );
    
    // Store transform key
    await db.query(
        'INSERT INTO transform_keys (delegator_id, delegatee_id, file_id, transform_key) VALUES ($1, $2, $3, $4)',
        [userId, recipient.rows[0].id, fileId, transformKey]
    );
    
    res.json({ success: true });
});
```

### Request ID Cleanup

```javascript
// Periodic cleanup of expired request IDs
setInterval(async () => {
    await db.query('DELETE FROM used_request_ids WHERE expires_at < NOW()');
}, 3600000); // Every hour
```

## Proxy Server Setup

The proxy server should be isolated and minimal:

```go
// Go example (see service/transform/ in repo)
package main

import (
    "net/http"
    "encoding/json"
)

type TransformRequest struct {
    Capsule      []byte `json:"capsule"`
    Ciphertext   []byte `json:"ciphertext"`
    TransformKey []byte `json:"transform_key"`
}

func transformHandler(w http.ResponseWriter, r *http.Request) {
    var req TransformRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    // Call Rust transform library
    transformed, err := transform(req.Capsule, req.TransformKey)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    json.NewEncoder(w).Encode(map[string]interface{}{
        "capsule": transformed,
    })
}

func main() {
    http.HandleFunc("/transform", transformHandler)
    http.ListenAndServe(":8080", nil)
}
```

### Proxy Security Requirements

1. **Network Isolation**: Only accept connections from business server
2. **No Data Persistence**: Never store transform keys or ciphertext
3. **Rate Limiting**: Prevent DoS attacks
4. **Audit Logging**: Log all transform operations
5. **Minimal Privileges**: Run as non-root user

## CDN Deployment (WASM)

### Static File Hosting

```nginx
# nginx configuration
server {
    listen 443 ssl http2;
    server_name cdn.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # WASM MIME type
    location ~ \.wasm$ {
        types { application/wasm wasm; }
        add_header Cache-Control "public, max-age=31536000, immutable";
        add_header Access-Control-Allow-Origin "*";
    }
    
    # JavaScript files
    location ~ \.js$ {
        add_header Cache-Control "public, max-age=31536000, immutable";
        add_header Content-Type "application/javascript";
    }
    
    root /var/www/rekrypt;
}
```

### CDN Best Practices

1. **Compression**: Serve pre-compressed .wasm.gz files
   ```bash
   gzip -9 rekrypt_bg.wasm  # ~150KB from 512KB
   ```

2. **Cache Headers**: Long cache for versioned files
3. **CORS**: Allow cross-origin for public CDN
4. **Integrity**: Use Subresource Integrity (SRI)
   ```html
   <script type="module" 
           src="https://cdn.example.com/rekrypt.js"
           integrity="sha384-..."
           crossorigin="anonymous">
   </script>
   ```

## Docker Deployment

### Dockerfile for Business Server

```dockerfile
FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --production

# Copy application
COPY . .

# Run as non-root
USER node

EXPOSE 3000

CMD ["node", "server.js"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  business-server:
    build: ./business-server
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgres://user:pass@db:5432/rekrypt
      - PROXY_URL=http://proxy-server:8080
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - db
      - proxy-server
    restart: unless-stopped

  proxy-server:
    build: ./proxy-server
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=info
    restart: unless-stopped
    # Network isolation
    networks:
      - internal

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=rekrypt
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - internal

  redis:
    image: redis:7-alpine
    networks:
      - internal

volumes:
  pgdata:

networks:
  internal:
    driver: bridge
```

## Performance Tuning

### Browser Optimization

```javascript
// 1. Lazy load WASM
let sdkPromise = null;

async function getSDK() {
    if (!sdkPromise) {
        sdkPromise = init().then(() => new EncryptSDK());
    }
    return sdkPromise;
}

// 2. Reuse SDK instance
const sdk = await getSDK();

// 3. Web Worker for large files
const worker = new Worker('encrypt-worker.js');

// 4. IndexedDB for caching
const db = await openDB('rekrypt-cache', 1);
```

### Server-Side Optimization

```javascript
// Connection pooling
const pool = new Pool({
    max: 20,
    idleTimeoutMillis: 30000,
});

// Redis caching for transform keys
const redis = new Redis();

async function getTransformKey(fileId, recipientId) {
    const cacheKey = `tk:${fileId}:${recipientId}`;
    
    // Try cache first
    let key = await redis.get(cacheKey);
    if (key) return key;
    
    // Fetch from database
    key = await db.query('SELECT transform_key FROM transform_keys WHERE ...');
    
    // Cache for 1 hour
    await redis.set(cacheKey, key, 'EX', 3600);
    
    return key;
}
```

## Monitoring & Observability

### Metrics to Track

```javascript
// Business server metrics
const metrics = {
    encryption_requests: counter,
    decryption_requests: counter,
    transform_key_generations: counter,
    keystore_creations: counter,
    replay_attacks_blocked: counter,
    avg_encryption_time: histogram,
    avg_decryption_time: histogram,
};

// Proxy server metrics
const proxyMetrics = {
    transform_requests: counter,
    transform_errors: counter,
    avg_transform_time: histogram,
};
```

### Health Check Endpoints

```javascript
// Business server
app.get('/health', async (req, res) => {
    const dbOk = await checkDatabase();
    const proxyOk = await checkProxy();
    
    if (dbOk && proxyOk) {
        res.json({ status: 'healthy', timestamp: Date.now() });
    } else {
        res.status(503).json({ status: 'unhealthy', db: dbOk, proxy: proxyOk });
    }
});

// Proxy server
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', service: 'proxy-transform' });
});
```

### Logging

```javascript
// Structured logging
const logger = winston.createLogger({
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
    ],
});

// Security events
logger.info('encryption_request', {
    user_id: userId,
    request_id: capsule.request_id,
    timestamp: Date.now(),
    file_size: data.length,
});

// DO NOT log sensitive data
// ❌ logger.info('private_key', privateKey);  // NEVER
// ❌ logger.info('plaintext', data);  // NEVER
```

## Scaling Strategies

### Horizontal Scaling

```
Load Balancer
     │
     ├──► Business Server 1
     ├──► Business Server 2
     └──► Business Server 3
              │
              ▼
          Shared Database
              +
        Redis Cluster
```

### Proxy Server Scaling

```
Business Servers
     │
     ├──► Proxy 1
     ├──► Proxy 2
     └──► Proxy 3
```

Proxy servers are stateless - easy to scale horizontally.

### Database Optimization

```sql
-- Partitioning by date
CREATE TABLE encrypted_files (
    -- ... columns ...
) PARTITION BY RANGE (created_at);

-- Archival strategy
CREATE TABLE encrypted_files_archive (
    -- ... same columns ...
);

-- Move old data periodically
INSERT INTO encrypted_files_archive 
SELECT * FROM encrypted_files 
WHERE created_at < NOW() - INTERVAL '1 year';
```

## Security Hardening

### Environment Variables

```bash
# .env
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
JWT_SECRET=random-256-bit-secret
PROXY_URL=https://internal-proxy:8080
ALLOWED_ORIGINS=https://app.example.com

# Rate limiting
MAX_ENCRYPTIONS_PER_HOUR=1000
MAX_KEYSTORE_ATTEMPTS=5

# Timeouts
CAPSULE_MAX_AGE_HOURS=24
SESSION_TIMEOUT_MINUTES=30
```

### HTTPS Configuration

```javascript
// Strict Transport Security
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'");
    next();
});
```

### Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

const encryptLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // 100 requests per hour
    message: 'Too many encryption requests',
});

app.post('/api/encrypt', encryptLimiter, encryptHandler);
```

## Backup & Recovery

### Backup Strategy

**What to Backup**:
- ✅ Database (encrypted data + keystores)
- ✅ Transform keys
- ✅ User data
- ❌ NOT proxy server (stateless)

**Backup Schedule**:
```bash
# Daily full backup
0 2 * * * pg_dump rekrypt > backup_$(date +\%Y\%m\%d).sql

# Hourly incremental
0 * * * * pg_dump --data-only --table=encrypted_files > incremental.sql
```

### Disaster Recovery

**Recovery Time Objective (RTO)**: < 1 hour
**Recovery Point Objective (RPO)**: < 1 hour

```bash
# Restore from backup
psql rekrypt < backup_20250110.sql

# Verify integrity
psql rekrypt -c "SELECT COUNT(*) FROM encrypted_files"
```

## Cost Estimation

### AWS Example (Medium Scale)

```
• EC2 t3.medium (Business Server): $35/month
• RDS PostgreSQL db.t3.medium: $85/month
• ElastiCache Redis: $15/month
• ECS Fargate (Proxy): $30/month
• S3 (encrypted storage): $23/GB/month
• Data transfer: $0.09/GB
• CloudWatch logs: $0.50/GB

Total (10k users, 100GB data): ~$300/month
```

### Cost Optimization

1. **Use S3 for large files**: Store ciphertext in S3, metadata in DB
2. **CloudFront CDN**: Cache WASM files globally
3. **Reserved Instances**: 40% savings for steady workload
4. **Compression**: Reduce storage/bandwidth costs

## Compliance

### GDPR Considerations

**Right to Erasure**:
```javascript
// Delete user's encrypted data
await db.query('DELETE FROM encrypted_files WHERE owner_id = $1', [userId]);
await db.query('DELETE FROM transform_keys WHERE delegator_id = $1', [userId]);
```

**Data Portability**:
```javascript
// Export user's keystore
app.get('/api/export-keystore', async (req, res) => {
    const keystore = await db.query(
        'SELECT keystore FROM users WHERE id = $1',
        [req.user.id]
    );
    res.json(keystore);
});
```

### Audit Trail

```javascript
// Log all key operations
function logKeyOperation(operation, userId, details) {
    auditLog.info({
        operation,
        user_id: userId,
        timestamp: Date.now(),
        ip: req.ip,
        ...details
    });
}

// Examples
logKeyOperation('keypair_generated', userId, { has_passphrase: false });
logKeyOperation('transform_key_created', userId, { recipient_id: bobId });
logKeyOperation('access_granted', userId, { file_id: fileId });
```

## Testing in Production

### Smoke Tests

```javascript
// Automated health check
async function smokeTest() {
    const sdk = new EncryptSDK();
    
    // Test encryption
    const keypair = sdk.generateKeypair();
    const data = new TextEncoder().encode('test');
    const encrypted = sdk.encrypt(data, keypair.public_key);
    const decrypted = sdk.decrypt(encrypted.capsule, keypair.private_key, encrypted.c_data);
    
    assert(new TextDecoder().decode(decrypted) === 'test');
    
    // Test keystore
    const keystore = sdk.createKeystore(keypair, 'TestPassword123!');
    const unlocked = sdk.unlockKeystore(keystore, 'TestPassword123!');
    
    assert(unlocked.length === 32);
    
    return true;
}

// Run every 5 minutes
setInterval(async () => {
    try {
        await smokeTest();
        metrics.health_check_success.inc();
    } catch (e) {
        metrics.health_check_failure.inc();
        alertOps('Smoke test failed: ' + e.message);
    }
}, 300000);
```

## Troubleshooting

### Common Issues

**1. WASM Loading Fails**
```javascript
// Check MIME type
fetch('/pkg/rekrypt_bg.wasm')
    .then(r => console.log('Content-Type:', r.headers.get('content-type')));
// Should be: application/wasm
```

**2. Keystore Unlock Takes Too Long**
```javascript
// Expected: ~1-2 seconds (PBKDF2 600k iterations)
// If slower: Check CPU throttling, try Web Worker
```

**3. Replay Attack Warnings**
```javascript
// Check system clock sync
console.log('Server time:', serverTime, 'Client time:', Date.now());
// Difference should be < 5 minutes
```

### Debug Mode

```javascript
// Enable debug logging
const sdk = new EncryptSDK();
sdk.setLanguage('en-US');

try {
    const encrypted = sdk.encrypt(data, publicKey);
} catch (e) {
    console.error('Error code:', e.code);
    console.error('Message:', e.message);
    console.error('Stack:', e.stack);
}
```

## Performance Benchmarks

### Latency Targets

| Operation | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| Key generation | 50ms | 100ms | 150ms |
| Encrypt 1KB | 2ms | 5ms | 10ms |
| Decrypt 1KB | 2ms | 5ms | 10ms |
| Keystore create | 1s | 2s | 3s |
| Transform | 10ms | 20ms | 50ms |

### Load Testing

```bash
# Apache Bench
ab -n 1000 -c 10 https://api.example.com/encrypt

# Artillery
artillery quick --count 100 --num 1000 https://api.example.com/encrypt
```

## Disaster Recovery Checklist

- [ ] Database backups verified
- [ ] Encryption keys backed up offline
- [ ] Transform keys in secure storage
- [ ] Monitoring alerts configured
- [ ] Incident response plan documented
- [ ] Recovery procedures tested
- [ ] Secondary region configured
- [ ] DNS failover ready

