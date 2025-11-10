# Security Guide

## Password Requirements

### Strength Rules
- Minimum: 12 characters
- Maximum: 128 characters
- Complexity: At least 3 of the following:
  - Lowercase letters
  - Uppercase letters
  - Digits
  - Special characters

### Examples

```javascript
// Good passwords
'MySecure@Pass123'
'correct-horse-battery-staple-2024!'
'P@ssw0rd!Complex'

// Weak passwords (rejected)
'password'        // Too short
'Password123'     // Only 2 types
'abcdefghijkl'    // No complexity
```

### Validation

```javascript
try {
    sdk.validatePasswordStrength(password);
    console.log('Password is strong');
} catch (e) {
    console.error('Weak password:', e.message);
}
```

## Mnemonic Management

### Critical Rules

1. **Save Immediately**: Mnemonic is generated only once
2. **Offline Storage**: Paper backup recommended
3. **No Screenshots**: Don't take photos or screenshots
4. **Secure Location**: Safe deposit box, encrypted vault
5. **Passphrase**: Optional extra security layer

### Backup Strategy

```javascript
const keypair = sdk.generateKeypair();

// 1. Show to user
alert('WRITE DOWN THIS MNEMONIC:\n\n' + keypair.mnemonic);

// 2. Verify they saved it
const verify = prompt('Re-enter the first 3 words:');
// ... verification logic ...

// 3. Create keystore for daily use
const keystore = sdk.createKeystore(keypair, password);
localStorage.setItem('keystore', JSON.stringify(keystore));
```

## Key Storage

### DO NOT

```javascript
// ❌ Plain text storage
localStorage.setItem('privateKey', privateKey);

// ❌ Unencrypted in memory too long
window.myPrivateKey = privateKey;

// ❌ Logging sensitive data
console.log('Private key:', privateKey);
```

### DO

```javascript
// ✅ Encrypted keystore
const keystore = sdk.createKeystore(keypair, password);
localStorage.setItem('keystore', JSON.stringify(keystore));

// ✅ Clear from memory after use
// (SDK auto-zeroizes with zeroize crate)

// ✅ Only decrypt when needed
const privateKey = sdk.unlockKeystore(keystore, password);
// Use immediately
// Let it go out of scope
```

## Replay Attack Protection

### Built-in Mechanisms

The SDK automatically includes:
- **Timestamp**: Validates message age (default 24 hours)
- **UUID**: Unique request identifier
- **Sequence**: Monotonic counter

### Production Recommendations

1. **Server-side Validation**
```javascript
// Maintain used request_id database
const usedIds = new Set();

function validateRequest(capsule) {
    if (usedIds.has(capsule.request_id)) {
        throw new Error('Replay attack detected');
    }
    usedIds.add(capsule.request_id);
}
```

2. **Adjust Time Window**
```javascript
// In SDK source, adjust validation.rs:
// validate_timestamp(timestamp, 3600, i18n) // 1 hour instead of 24
```

## Memory Safety

### Auto-Zeroization

Sensitive data is automatically cleared:

```rust
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeypairResult {
    pub private_key: Vec<u8>,
    pub mnemonic: String,
}
// Automatically zeroized when dropped
```

### Manual Cleanup

```javascript
// SDK handles this internally, but be aware:
// - Private keys cleared after operations
// - Mnemonics zeroized on drop
// - Derived keys cleared after use
```

## Integrity Protection

### Data Verification

All encrypted data includes integrity checks:

```javascript
const encrypted = sdk.encrypt(data, publicKey);
// encrypted.c_hash contains SHA-256 of ciphertext

// Decryption automatically verifies:
// 1. Capsule integrity (HMAC)
// 2. Ciphertext integrity (hash comparison)
// 3. Authentication tag (AES-GCM)
```

### Keystore Protection

Keystore uses HMAC over all parameters:

```javascript
// Protects against:
// - Iteration count tampering
// - Salt manipulation
// - Version rollback
// - Parameter substitution
```

## Browser Security

### Content Security Policy

```html
<meta http-equiv="Content-Security-Policy" 
      content="script-src 'self' 'wasm-unsafe-eval'">
```

### Secure Context

Always use HTTPS in production:

```javascript
if (!window.isSecureContext) {
    alert('Please use HTTPS for security');
}
```

### Storage Security

```javascript
// Use secure storage
if (window.crypto && window.crypto.subtle) {
    // SubtleCrypto available
} else {
    console.error('Secure context required');
}
```

## Common Vulnerabilities

### ❌ Timing Attacks

SDK uses constant-time comparison for:
- MAC verification
- Password comparison
- Key comparison

### ❌ Padding Oracle

SDK verifies MAC before decryption to prevent padding oracle attacks.

### ❌ Length Extension

SDK uses HMAC-SHA256 (not plain SHA-256) to prevent length extension attacks.

### ❌ Weak Randomness

SDK uses:
- Browser's `crypto.getRandomValues()`
- Rust's `rand::thread_rng()`
- Both are cryptographically secure

## Security Checklist

Before production:

- [ ] All private keys encrypted in keystore
- [ ] Strong passwords enforced (12+ chars)
- [ ] Mnemonics backed up offline
- [ ] HTTPS enabled
- [ ] Server-side request_id validation
- [ ] Reasonable timestamp windows
- [ ] CSP headers configured
- [ ] No sensitive data in logs
- [ ] Regular security audits

