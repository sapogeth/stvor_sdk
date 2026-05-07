# STVOR Security

Security architecture and threat model.

---

## Executive Summary

STVOR is a **zero-knowledge messaging platform** using industry-standard cryptography (Signal Protocol: X3DH + Double Ratchet). The relay server **cannot access message content**, providing end-to-end encryption with perfect forward secrecy.

**Current Status**: Production-ready • Not yet independently audited • Zero-day disclosure policy in place

---

## Threat Model

### Assumptions

**We assume**:
- ✓ Server hardware is not compromised
- ✓ Network layer is secure (HTTPS/TLS)
- ✓ Clients have valid operating systems
- ✓ Time is approximately synchronized (NTP)

**We do NOT assume**:
- ✗ Server code is bug-free (defense in depth)
- ✗ Client devices are secure (assume breaches)
- ✗ Network operators are trustworthy (end-to-end encryption)

### Adversaries

| Threat | Capability | Mitigation |
|--------|-----------|-----------|
| **Network Attacker** | Observe encrypted traffic | TLS 1.3, HSTS |
| **Relay Server** | Access ciphertext | E2EE (X3DH + Double Ratchet) |
| **Compromised Device** | Access keys on that device | Perfect Forward Secrecy (per-message keys) |
| **Replay Attacker** | Inject old messages | Nonce + timestamp validation, Redis cache |
| **Active Attacker** | Modify messages | AEAD authentication (GCM tag) + ECDSA signatures |
| **Quantum Computer** | Break ECDH/ECDSA | Post-quantum migration planned (roadmap) |

---

## Cryptographic Primitives

### Key Exchange (X3DH)

**Algorithm**: Extended Triple Diffie-Hellman

**Curve**: NIST P-256 (secp256r1)

**Security Level**: 128 bits (against classical computers)

```
Alice's keys:
  - Identity: IK_A (static)
  - Prekey: PK_A (signed ephemeral)

Bob's keys:
  - Identity: IK_B (static)
  - Prekey: PK_B (signed ephemeral)

Shared secret = KDF(
  salt='STVOR-X3DH',
  ECDH(IK_A, IK_B) ||
  ECDH(PK_A, IK_B) ||
  ECDH(IK_A, PK_B) ||
  ECDH(PK_A, PK_B)
)
```

**Security Properties**:
- ✓ Perfect Forward Secrecy (if prekeys compromised)
- ✓ Mutual authentication (only both sides derive same secret)
- ✓ Resistance to key compromise (4 DH operations)

### Symmetric Encryption (AES-256-GCM)

**Algorithm**: Advanced Encryption Standard with Galois/Counter Mode

**Key Size**: 256 bits

**Nonce**: 96 bits (12 bytes), randomly generated per message

**Authenticated Data**: Sender || Recipient IDs

```
plaintext = JSON.stringify(data)
iv = random(12 bytes)
(ciphertext, tag) = AES_256_GCM.encrypt(plaintext, key, iv)
```

**Security Properties**:
- ✓ Confidentiality: AES-256 (NIST-approved)
- ✓ Authenticity: GCM mode includes authentication tag
- ✓ No PADDING ORACLE: Authenticated encryption prevents tampering
- ✓ Timing-attack resistant: Constant-time operations

### Message Authentication (ECDSA)

**Algorithm**: Elliptic Curve Digital Signature Algorithm

**Curve**: NIST P-256 (secp256r1)

**Hash**: SHA-256

```
payload = {to, ciphertext, iv, timestamp}
signature = ECDSA_P256.sign(
  message=SHA256(serialize(payload)),
  privateKey=senderPrivateKey
)
```

**Security Properties**:
- ✓ Authenticity: Signer is verified
- ✓ Non-repudiation: Signer cannot deny
- ✓ No key recovery: Secret key not recoverable from signature

### Key Derivation (HKDF-SHA-256)

**Algorithm**: HMAC-based Extract-and-Expand Key Derivation Function

**Hash Function**: SHA-256

```
PRK = HMAC_SHA256(salt, input_key_material)
OKM = HKDF_Expand(PRK, info, length)
```

**Usage**:
- X3DH → shared secret
- Double Ratchet → chain key advancement
- Per-message key derivation

**Security Properties**:
- ✓ IND-CPA secure (indistinguishability)
- ✓ Key separation (different info strings)
- ✓ Randomness extraction (salts)

---

## Message Flow Security

### Sending a Message

```
[SENDER] alice.send('bob', msg)

1. Fetch bob's public key from relay
   Risk: Relay could send wrong key
   Mitigation: TOFU - trust first identity

2. Perform X3DH key exchange
   Risk: MITM attacker could replace keys
   Mitigation: ECDSA signatures on keys

3. Derive shared secret (128 bits of entropy)
   Risk: Weak KDF
   Mitigation: HKDF-SHA-256 (NIST standard)

4. Initialize Double Ratchet
   Root Key = shared secret
   Risk: Key reuse across messages
   Mitigation: Per-message ratcheting

5. Advance ratchet → message key
   Risk: Key compromise
   Mitigation: Keys deleted after use

6. Serialize data to JSON
   Risk: Side-channel during serialization
   Mitigation: No secrets in serialization

7. Encrypt with AES-256-GCM
   Risk: IV reuse (nonce collision)
   Mitigation: Random IV, checked globally

8. Sign with ECDSA
   Risk: Deterministic ECDSA (RFC 6979)
   Mitigation: RFC 6979 (deterministic ECDSA)

9. POST /send
   Payload: {to, ciphertext, signature, timestamp, nonce}
   Risk: Replay attacks
   Mitigation: Nonce + timestamp in replay cache (Redis)

[RELAY] Validates request

10. Verify ECDSA signature
    Risk: Signature forgery
    Mitigation: ECDSA P-256-SHA-256

11. Check nonce not in cache
    Risk: Message replay
    Mitigation: Redis-backed nonce cache (5 min TTL)

12. Store in recipient's queue
    Risk: Long-term storage
    Mitigation: 10-minute TTL auto-cleanup

[RECIPIENT] bob polls /retrieve

13. GET /retrieve
    Response: [encrypted messages]
    Risk: Relay sends old messages
    Mitigation: Nonce cache prevents replay

14. Verify ECDSA signature
    Risk: Signature forgery
    Mitigation: ECDSA P-256-SHA-256

15. Decrypt with AES-256-GCM
    Risk: Ciphertext tampering
    Mitigation: GCM authentication tag verification

16. Deserialize JSON
    Risk: Prototype pollution (JSON)
    Mitigation: No user code in deserialization

17. Fire onMessage callback
    msg = {from, data, timestamp}
```

### Forward Secrecy Guarantee

```
Compromise of messageKey[n] → Exposure of:
  - plaintext[n] only
  - NOT plaintext[n-1] (old key deleted)
  - NOT plaintext[n+1] (derived independently)

Timeline:
  T0: Send msg[0] with key[0] → key[0] deleted
  T1: Send msg[1] with key[1] → key[1] deleted
  T2: **COMPROMISE** - attacker gets rootKey
  T3: Send msg[2] with key[2]

Attacker can:
  ✓ Decrypt msg[2] (rootKey compromised)
  ✓ Decrypt future messages

But:
  ✗ Cannot decrypt msg[0], msg[1] (keys deleted)
  
Recovery:
  T4: User reboots → generate new rootKey → msg[3] safe
```

---

## Known Limitations

### No Post-Quantum Cryptography (Yet)

- Current: ECDH P-256 (128-bit security)
- Risk: Quantum computers could break today's messages
- Roadmap: Kyber (key exchange) + Dilithium (signatures) in Q3 2026
- Mitigation: Store encrypted archives securely; use long-term secrets wisely

### No Group Chat (Yet)

- Current: 1-to-1 messaging only
- Risk: Requires key per recipient (n² key material)
- Roadmap: Signal Group Protocol (SGP) in Q2 2026

### No Message Deletion (Yet)

- Current: Messages stored on relay for 10 minutes
- Risk: Relay could persist messages longer (protocol violation)
- Mitigation: Trust relay's TTL policy; use Tor/VPN if paranoid
- Roadmap: End-to-end deletable messages in Q3 2026

### No Perfect Forward Secrecy for Relay

- Current: Relay stores ciphertext (encrypted blobs)
- Risk: If relay hacked, can steal all historical ciphertexts
- Mitigation: Ciphertexts unusable without private keys (E2EE)
- Roadmap: Perfect message deletion in Q3 2026

### No Offline Message Queue

- Current: Messages lost if recipient offline > 10 minutes
- Risk: Message delivery failures
- Mitigation: Recipient must be online to retrieve
- Roadmap: Offline message delivery in Q4 2026

---

## Security Best Practices

### For Application Developers

1. **Use HTTPS/TLS only**
   ```ts
   // ✓ Good
   const relay = 'https://relay.stvor.xyz';
   
   // ✗ Bad
   const relay = 'http://relay.stvor.xyz';
   ```

2. **Validate API tokens in environment**
   ```ts
   // ✓ Good
   const token = process.env.STVOR_APP_TOKEN;
   if (!token?.startsWith('stvor_')) throw 'Invalid token';
   
   // ✗ Bad
   const token = 'stvor_live_xxx';  // Hardcoded!
   ```

3. **Handle errors gracefully**
   ```ts
   // ✓ Good
   try {
     await client.send('bob', msg);
   } catch (err) {
     if (err.code === 'ERR_NETWORK') {
       // Retry with backoff
     }
   }
   ```

4. **Rotate API keys periodically**
   - Generate new key: `POST /projects/{id}/rotate-key`
   - Migrate clients to new key
   - Revoke old key: `DELETE /projects/{id}/keys/{keyId}`

5. **Monitor for suspicious activity**
   - High rate of failed sends
   - Sends to unknown recipients
   - Sends from unusual geographies
   - Sends at unusual hours

### For Relay Operators

1. **Enable TLS 1.3 only**
   ```nginx
   ssl_protocols TLSv1.3;
   ssl_ciphers AEAD;
   ```

2. **Use strong certificate (256-bit ECC)**
   ```bash
   openssl ecparam -name secp256r1 -genkey -out relay.key
   ```

3. **Enable HSTS**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000" always;
   ```

4. **Log access patterns (not messages)**
   ```
   ✓ Log: IP, timestamp, route, status_code, user_id
   ✗ Don't log: ciphertext, plaintext, message content
   ```

5. **Run regular backups**
   - Daily: Database snapshots
   - Off-site: Encrypted backups
   - Test: Restore backups quarterly

6. **Update dependencies**
   ```bash
   npm audit fix
   npm audit  # Should show 0 vulnerabilities
   ```

---

## Vulnerability Disclosure

**Security Issues**: Email izahii@protonmail.com

**Response Timeline**:
- Day 0: Acknowledge receipt
- Day 1: Confirm impact
- Day 7: Fix or workaround
- Day 30: Public disclosure

**Supported Versions**:
- Latest: v3.x (full support)
- Previous: v2.x (6 months security updates)
- Older: v1.x (no support)

---

## Audit Status

- ✗ **Not independently audited** (roadmap: Q3 2026)
- ✓ Continuous review by security community
- ✓ Open source (GitHub)
- ✓ Bug bounty program (TBD)

---

## Compliance

### GDPR

- ✓ No PII stored on relay
- ✓ Users control own keys
- ✓ Can request data export (encrypted)
- ✓ Right to deletion (keys/messages)

### HIPAA

- ⚠️ Not official BAA (Business Associate Agreement)
- ✓ Uses approved crypto (AES-256)
- ✓ Can be used in compliant architecture
- ⚠️ Requires legal review for specific use

### SOC 2

- ⚠️ Not officially certified
- ✓ Implements SOC 2 controls:
  - Access control (API keys)
  - Encryption (TLS + E2EE)
  - Audit logging
  - Incident response
  - Change management

---

## Testing & Verification

### Run Security Tests

```bash
# Encryption tests
npm run test:encryption

# Handshake tests
npm run test:handshake

# Replay protection tests
npm run test:replay

# E2EE tests
npm run test:e2ee

# All tests
npm test
```

### Verify Cryptography

```ts
import * as Ratchet from '@stvor/sdk/ratchet';

// Verify X3DH produces same shared secret
const alice = await Ratchet.X3DH.generateKeyPair();
const bob = await Ratchet.X3DH.generateKeyPair();

const sharedAlice = await Ratchet.X3DH.derive(alice, bob.publicKey);
const sharedBob = await Ratchet.X3DH.derive(bob, alice.publicKey);

console.assert(
  sharedAlice.equals(sharedBob),
  'X3DH failed'
);
```

---

## Future Security Roadmap

### Q2 2026
- [ ] Third-party security audit
- [ ] Bug bounty program launch
- [ ] Group messaging (SGP)

### Q3 2026
- [ ] Post-quantum cryptography (Kyber + Dilithium)
- [ ] Perfect message deletion
- [ ] SOC 2 Type II certification

### Q4 2026
- [ ] Offline message delivery
- [ ] End-to-end file transfer
- [ ] Hardware key support (Ledger/Trezor)

---

## References

- [Signal Protocol](https://signal.org/docs/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [X3DH: The Signal Protocol's Asynchronous Ratcheting Tree](https://signal.org/docs/specifications/x3dh/)
- [NIST SP 800-38D (GCM)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 6979 (Deterministic ECDSA)](https://tools.ietf.org/html/rfc6979)
- [HKDF (RFC 5869)](https://tools.ietf.org/html/rfc5869)

---

## FAQ

**Q: Can STVOR employees read my messages?**

A: No. End-to-end encryption means only sender/recipient can decrypt. Employees cannot access private keys.

**Q: What if someone hacks STVOR?**

A: Relay compromised = encrypted blobs exposed (useless without keys). Client compromised = keys exposed (your problem). Server code compromised = e2ee still works (cryptography doesn't change).

**Q: Is it vulnerable to man-in-the-middle?**

A: HTTPS/TLS prevents MITM on channel. ECDSA signatures + TOFU prevent MITM on key exchange.

**Q: What about timing attacks?**

A: Cryptographic operations use constant-time implementations. Network latency dominates timing channel.

**Q: Is it vulnerable to side-channel attacks?**

A: Not to known attacks on target algorithms. Possible in theory on uncommon platforms.

**Q: What if keys are stolen?**

A: Forward secrecy protects past messages. Future messages need new keys (automatic via ratchet advancement).

---

## License

MIT
