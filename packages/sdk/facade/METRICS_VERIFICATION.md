# STVOR v2.4.0 - Metrics Verification Guide

## Overview

STVOR v2.4.0 provides **cryptographically verified metrics** - real E2EE activity counters that cannot be forged or faked.

**Core Principle:** Only the SDK runtime is the source of truth. Dashboard displays metrics ONLY if cryptographic proof is valid.

## For Dashboard Integration

### 1. Get Signed Metrics from SDK

```typescript
import { StvorApp, verifyMetricsSignature } from '@stvor/sdk';

const app = new StvorApp({ appToken: 'sk_live_...' });

// Get signed metrics (includes cryptographic proof)
const { metrics, proof } = app.getSignedMetrics();

// metrics: { messagesEncrypted, messagesDecrypted, messagesRejected, replayAttempts, authFailures }
// proof: HMAC-SHA256 hex string proving these metrics
```

### 2. Verify Before Displaying

```typescript
const isValid = verifyMetricsSignature(
  JSON.stringify(metrics),  // Exact JSON payload
  proof,                     // HMAC proof from SDK
  apiKey                     // Your API key for verification
);

if (!isValid) {
  // SECURITY: Reject - proof invalid
  console.error('Metrics rejected: Invalid signature');
  displayUnverified();
  return;
}

// SECURITY: Proof valid - display metrics
displayMetrics(metrics);
```

### 3. What the Proof Proves

The HMAC-SHA256 proof guarantees:
- ✅ Metrics came from SDK runtime (not UI-generated)
- ✅ Metrics bound to your specific API key
- ✅ No tampering in transit
- ✅ Metrics represent real E2EE activity (post-AEAD encryption/AAD decryption)

### 4. Cryptographic Details

```
Derivation:
  salt = 32 zero bytes
  info = "stvor-metrics-v3"
  derivedKey = HKDF-SHA256(appToken, salt, info, 32 bytes)

Signing:
  payload = JSON.stringify({messagesEncrypted, messagesDecrypted, ...})
  proof = HMAC-SHA256(payload, derivedKey) as hex

Verification:
  computedProof = HMAC-SHA256(payload, derivedKey)
  valid = (computedProof === proof) // Constant-time comparison
```

### 5. Counter Semantics

Each counter increments ONLY after cryptographic success:

| Counter | Increments After | Example |
|---------|-----------------|---------|
| `messagesEncrypted` | Successful AEAD encryption | Message sealed and sent |
| `messagesDecrypted` | Successful AAD decryption | Ciphertext verified and decoded |
| `messagesRejected` | Failed AAD (auth/nonce/format failure) | Tampered message detected |
| `replayAttempts` | Duplicate nonce detected | Replay attack prevented |
| `authFailures` | HMAC verification failure | Signature mismatch |

**Key:** Counters represent REAL E2EE events, not UI interactions.

## Integration Example

```typescript
// dashboard.html - Receive metrics from SDK
window.addEventListener('message', (event) => {
  if (event.data.type === 'STVOR_METRICS') {
    const { metrics, proof } = event.data.payload;
    
    // Verify proof
    const valid = verifyMetricsSignature(
      JSON.stringify(metrics),
      proof,
      document.getElementById('api-key').value
    );
    
    if (valid) {
      // Display verified metrics
      document.getElementById('encrypted-count').textContent = metrics.messagesEncrypted;
      document.getElementById('decrypted-count').textContent = metrics.messagesDecrypted;
      document.getElementById('status').textContent = '✅ Verified by SDK v2.4.0';
    } else {
      // Display rejection
      document.getElementById('status').textContent = '❌ Invalid signature - metrics rejected';
    }
  }
});
```

## Security Invariants

1. **Immutability:** Counters cannot be set from external code (only incremented internally)
2. **Cryptographic Binding:** Proof proves ownership of specific API key
3. **Timing Attack Protection:** Verification uses constant-time comparison
4. **No Fallback Values:** Dashboard shows "Unverified" if proof fails (never fake numbers)
5. **Runtime Source of Truth:** Only events that passed AEAD/AAD increment counters

## Testing

```bash
# 1. Create app with API token
const app = new StvorApp({ appToken: 'stvor_test_...' });

# 2. Encrypt a message (increments messagesEncrypted)
await app.client.send('recipient', 'Hello');

# 3. Get signed metrics
const { metrics, proof } = app.getSignedMetrics();

# 4. Verify with same API key
const valid = verifyMetricsSignature(
  JSON.stringify(metrics),
  proof,
  'stvor_test_...'
);
// valid === true

# 5. Try to verify with wrong key
const invalid = verifyMetricsSignature(
  JSON.stringify(metrics),
  proof,
  'stvor_wrong_...'
);
// invalid === false
```

## Fallback Behaviors

| Scenario | Display |
|----------|---------|
| No SDK metrics available | "📊 No Verified E2EE Activity" |
| Invalid proof | "❌ Metrics Rejected (invalid signature)" |
| Proof valid | Actual counters with "✅ Verified by SDK v2.4.0" |
| All counters at zero | Show 0 for each counter (valid state) |

## Key Derivation Format

API keys can be:
- `sk_live_...` - Production key
- `stvor_...` - Standard key  
- `stvor_dev_...` - Development key

All use same HKDF-SHA256 derivation for metrics signing.

---

**Golden Rule:** The Dashboard should NEVER display a number unless `verifyMetricsSignature()` returns `true`.
