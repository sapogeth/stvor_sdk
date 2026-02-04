# STVOR SDK Security Guarantees

**Version:** 2.1.0  
**Date:** February 4, 2026  
**Crypto Backend:** libsodium-wrappers

---

## Overview

STVOR SDK implements Signal Protocol-level end-to-end encryption with the following cryptographic primitives and security guarantees.

---

## Cryptographic Primitives

### Key Exchange
- **X3DH (Extended Triple Diffie-Hellman)**
  - Identity keys: Ed25519 (signing) + X25519 (DH)
  - Signed Pre-Keys: X25519 with Ed25519 signature
  - One-Time Pre-Keys: X25519 ephemeral keys
  - Protocol binding: version + cipher suite in KDF

### Session Encryption
- **Double Ratchet Algorithm**
  - Symmetric ratchet: XChaCha20-Poly1305 AEAD
  - Asymmetric ratchet: X25519 DH for PFS
  - KDF: BLAKE2b (via libsodium `crypto_generichash`)

### Message Authentication
- **Ed25519 Signatures**
  - SPK signatures prevent downgrade attacks
  - Identity key authenticity verification

---

## Security Guarantees

### 1. **Forward Secrecy (FS)**

**Mechanism:**  
Automatic DH ratchet rotation via `enforceDHRatchetPolicy()`:
- After **50 messages** sent
- After **10 minutes** of session time
- On demand (suspected compromise)

**Code Reference:**  
[`packages/sdk/ratchet/index.ts:330-357`](packages/sdk/ratchet/index.ts)

**Guarantee:**  
Compromise of current session keys does NOT reveal past messages.

---

### 2. **Post-Compromise Security (PCS)**

**Mechanism:**  
New DH ratchet step via `forceDHRatchet()` and `receiveNewDHPublicKey()`:
- Derives fresh root key from new DH output
- Clears all compromised chain keys
- Resets skipped message keys

**Code Reference:**  
[`packages/sdk/ratchet/index.ts:387-432`](packages/sdk/ratchet/index.ts)

**Guarantee:**  
System recovers confidentiality AFTER key compromise once new DH exchange completes.

---

### 3. **Trust On First Use (TOFU)**

**Mechanism:**  
Fingerprint-based identity binding via `verifyFingerprint()`:
- SHA-256 fingerprint of identity public key
- Stored on first connection (in-memory or PostgreSQL)
- Hard failure on fingerprint mismatch

**Code Reference:**  
[`packages/sdk/facade/tofu-manager.ts`](packages/sdk/facade/tofu-manager.ts)

**Guarantee:**  
Detects MITM attacks after first successful connection. Prevents key substitution.

**Limitation:**  
First connection is vulnerable to active MITM (standard TOFU weakness).

---

### 4. **Replay Protection**

**Mechanism:**  
Nonce-based duplicate detection via `validateMessageWithNonce()`:
- Nonce cache with 5-minute expiry
- Timestamp validation (rejects old messages)
- In-memory cache with automatic cleanup

**Code Reference:**  
[`packages/sdk/facade/replay-manager.ts`](packages/sdk/facade/replay-manager.ts)

**Guarantee:**  
Prevents replay attacks within 5-minute window. Rejects stale messages.

**DoS Protection:**  
- Max 10,000 cached nonces
- Automatic eviction of expired entries

---

### 5. **Zero-Knowledge Relay**

**Mechanism:**  
Server-side:
- Relay stores only ciphertext + headers
- No decryption capability (lacks session keys)
- No access to message plaintext

**Code Reference:**  
[`src/relay/server.ts`](src/relay/server.ts)  
[`src/routes/e2e.ts`](src/routes/e2e.ts)

**Guarantee:**  
Relay server cannot read message contents. End-to-end encryption maintained.

---

## Attack Resistance

| Attack Vector | Mitigation |
|---------------|------------|
| **Passive eavesdropping** | XChaCha20-Poly1305 AEAD encryption |
| **Active MITM (after first use)** | TOFU fingerprint verification |
| **Key compromise (past messages)** | Forward Secrecy via DH ratchet |
| **Key compromise (future messages)** | Post-Compromise Security |
| **Replay attacks** | Nonce-based validation + timestamps |
| **Message tampering** | Poly1305 MAC authentication |
| **Downgrade attacks** | SPK signature verification |
| **Out-of-order messages** | Skipped message keys (max 50/session) |
| **DoS via skipped keys** | Global limit (500 total) + eviction |

---

## Protocol Flow

### Session Establishment (X3DH)

```
Alice                                   Bob
-----                                   ---
1. Generate identity keypair (Ed25519 + X25519)
2. Generate SPK, sign with identity key
3. Generate OPK pool

4. Fetch Bob's public keys ────────────▶ 5. Publish IK, SPK, OPKs
6. Verify SPK signature
7. Perform 3 DH operations:
   DH1 = DH(SPK_alice, SPK_bob)
   DH2 = DH(IK_alice, OPK_bob)
   DH3 = DH(SPK_alice, OPK_bob)
8. Derive shared secret = BLAKE2b(DH1 || DH2 || DH3)
9. Derive root key = KDF(shared_secret, "x3dh-root-key")

Session established ──────────────────────
```

### Message Encryption (Double Ratchet)

```
Send:
1. Generate new ephemeral DH keypair
2. Perform DH with recipient's public key
3. Update root key = KDF(old_root, DH_output)
4. Derive chain key = KDF(new_root)
5. Derive message key = KDF(chain_key)
6. Encrypt: XChaCha20-Poly1305(plaintext, message_key, nonce)
7. Send: { ciphertext, header: { ephemeral_public, nonce } }

Receive:
1. Extract ephemeral public key from header
2. Perform DH with own private key
3. Update root key = KDF(old_root, DH_output)
4. Derive chain key = KDF(new_root)
5. Derive message key = KDF(chain_key)
6. Decrypt: XChaCha20-Poly1305_decrypt(ciphertext, message_key, nonce)
```

---

## Cryptographic Parameters

| Primitive | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Identity Key (signing) | Ed25519 | 256 bits | Long-term |
| Identity Key (DH) | X25519 | 256 bits | Curve25519 |
| Signed Pre-Key | X25519 | 256 bits | Semi-ephemeral |
| One-Time Pre-Key | X25519 | 256 bits | Single-use |
| Symmetric Encryption | XChaCha20-Poly1305 | 256 bits | AEAD |
| KDF | BLAKE2b | 256 bits | Generic hash |
| Fingerprint | SHA-256 (via BLAKE2b) | 256 bits | Identity binding |

---

## Known Limitations

### 1. **TOFU First-Use Vulnerability**
- **Risk:** Active MITM on first connection
- **Mitigation:** Manual fingerprint verification (out-of-band)
- **Future:** Consider Trust Establishment via Certificate Transparency

### 2. **In-Memory Storage (CRITICAL)**
- **Risk:** Session keys + fingerprints lost on restart
- **Impact:** 
  - Cannot decrypt old messages after restart
  - TOFU protection reset (vulnerable to MITM again)
  - All sessions must be re-established
- **Environments affected:**
  - Browser refresh/close
  - Mobile app background kill
  - Server restart
- **Future:** Add encrypted persistent storage (IndexedDB, Keychain)

### 3. **Replay Protection: In-Memory Only (DEMO-LEVEL)**
- **Status:** Proof-of-concept implementation
- **Limitations:**
  - ❌ **Process restart:** Nonce cache cleared, replay window reopens
  - ❌ **Clustered environments:** Each instance has separate cache (no shared state)
  - ❌ **Mobile background:** iOS/Android may kill process, clearing cache
  - ❌ **Multi-region:** No global nonce synchronization
- **Attack window:** 5 minutes after restart/cache clear
- **Production requirement:** Redis or distributed cache needed
- **Current status:** Acceptable for v2.1 single-instance deployments ONLY

### 4. **No Group Encryption**
- **Status:** Only 1:1 messaging supported
- **Future:** Implement Sender Keys for group chats

### 5. **Offline Message Queue**
- **Status:** Recipient must be online
- **Future:** Add relay-side encrypted message queue

### 6. **Identity Key Lifecycle**
- **Current:** Generated on first initialization, stored in memory only
- **Issue:** Reinstall = new identity = TOFU fingerprint mismatch for peers
- **Workaround:** Manual `trustNewFingerprint()` call required
- **Future:** Deterministic key derivation from user credentials

---

## Critical Assumptions

### System Requirements

#### 1. **Client-Side Assumptions**
- **libsodium availability:** WASM must be supported (all modern browsers ✅)
- **Memory constraints:** ~50KB per peer session (10 peers = 500KB)
- **Single-instance client:** No multi-device sync (each device = new identity)
- **JavaScript runtime:** Node.js ≥18 or modern browser

#### 2. **Deployment Assumptions**
- **Single process:** Replay protection cache NOT shared across instances
- **Stateful server:** In-memory caches (TOFU, replay) lost on restart
- **No load balancer:** Or requires sticky sessions for cache consistency
- **Redis/PostgreSQL optional:** Fallback to in-memory storage

#### 3. **Network Assumptions**
- **Relay availability:** Messages dropped if relay offline
- **WebSocket support:** Or HTTP long-polling as fallback
- **Latency tolerance:** X3DH handshake adds 2-3 RTTs to first message
- **Bandwidth:** ~1.5KB overhead per message (ratchet headers)

### Security Model Assumptions

#### 1. **Threat Model**
- **In scope:**
  - Passive network eavesdropping
  - Active MITM after first connection (TOFU)
  - Key compromise (forward secrecy + PCS)
  - Replay attacks (5-minute window)
  - Message tampering
- **Out of scope:**
  - Endpoint compromise (device malware)
  - Coerced key disclosure
  - Side-channel attacks (timing, power analysis)
  - Post-quantum adversaries (Shor's algorithm)

#### 2. **Trust Assumptions**
- **Relay server:** Trusted for availability, NOT for confidentiality
  - Can DOS (drop messages)
  - Can log metadata (from/to/timestamp)
  - CANNOT decrypt messages (zero-knowledge)
- **libsodium:** Trusted implementation (peer-reviewed, audited)
- **Browser/OS:** Trusted crypto.getRandomValues() / SecureRandom
- **User:** Responsible for out-of-band fingerprint verification

#### 3. **Backward Compatibility**
- **Server:** Must support BOTH legacy (JWK) and new (libsodium) formats
- **Client upgrade:** 
  - ⚠️ **Non-atomic:** Clients may upgrade at different times
  - ⚠️ **Grace period:** Old clients cannot decrypt ratchet messages
  - ⚠️ **Breaking change:** Session re-establishment required after upgrade
- **Migration path:** 
  - Server stores format version with registration
  - Clients negotiate highest common protocol version
  - Fallback to legacy AES-GCM if needed

#### 4. **Ratchet State Synchronization**
- **Assumption:** Messages arrive in order (or within skipped-key window)
- **Risk:** Network reordering beyond 50 messages = decryption failure
- **Mitigation:** Skipped message keys (max 50 per session)
- **Unhandled:** Complete session desync requires manual reset

### Operational Assumptions

#### 1. **Key Management**
- **No key escrow:** Lost keys = lost messages (by design)
- **No backup:** Identity keys not recoverable
- **No migration:** Device change = new identity = TOFU re-verification

#### 2. **Monitoring**
- **Prometheus metrics:** Available but not required
- **Error logging:** Client-side errors NOT sent to server
- **Audit trail:** Server logs metadata only (no plaintext)

---

## Compliance

### Recommended For:
- ✅ Healthcare (HIPAA)
- ✅ Finance (PCI DSS, GDPR)
- ✅ Enterprise (Zero-trust architecture)
- ✅ Privacy-focused applications

### Not Recommended For:
- ❌ Post-quantum threat model (use ML-KEM when available)
- ❌ Military/government (needs formal certification)

---

## Audit Status

| Aspect | Status |
|--------|--------|
| **Code Review** | Internal ✅ |
| **External Audit** | Pending |
| **Penetration Testing** | Pending |
| **Formal Verification** | Not performed |

---

## References

1. [Signal Protocol Specifications](https://signal.org/docs/)
2. [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
3. [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
4. [libsodium Documentation](https://doc.libsodium.org/)

---

**Last Updated:** February 4, 2026  
**Maintainer:** STVOR Security Team
