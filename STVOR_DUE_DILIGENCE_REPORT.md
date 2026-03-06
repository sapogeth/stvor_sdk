# STVOR SDK - FULL TECHNICAL & INVESTMENT DUE DILIGENCE

**Date:** 2026-03-01  
**Project:** STVOR E2EE SDK  
**Version Analyzed:** v2.4.1  
**Classification:** CONFIDENTIAL - INVESTMENT REVIEW  

---

## EXECUTIVE SUMMARY

**VERDICT: NOT INVESTABLE AT CURRENT STATE**

This is a **pre-MVP research prototype** masquerading as production infrastructure. While the cryptographic intentions are directionally correct (Signal Protocol implementation), the codebase is riddled with catastrophic security flaws, architectural shortcuts, and production-readiness gaps that make it unsuitable for any serious deployment—let alone healthcare or fintech use cases.

**Bottom Line:** This needs 6-12 months of fundamental rework before it can be considered "early production." Current state is dangerous to deploy.

---

## 1. CODE-LEVEL DEEP ANALYSIS

### 🔴 CRITICAL ISSUES (Immediate Blocking)

#### 1.1 Identity Keys Are Ephemeral (CRITICAL)
**File:** [`packages/sdk/facade/crypto-session.ts:36-105`](packages/sdk/facade/crypto-session.ts:36)

```typescript
// Identity keys generated ONCE per userId
// Currently in-memory only - keys lost on restart
```

**Severity:** CRITICAL  
**Why it matters:** Identity keys—the foundation of all trust—are generated fresh on every SDK initialization and stored ONLY in memory. This means:
- User identity changes on every app restart
- No cryptographic continuity between sessions
- Complete breakdown of the "ratchet"—every session is a new identity

**What breaks at scale:** Every deployment becomes a new identity. Key rotation becomes identity rotation. Users cannot receive messages sent while offline because their "identity" no longer exists.

**What breaks under attack:** Attacker can force key regeneration by crashing the app. Man-in-the-middle attacks become trivial because there's no persistent identity to verify against.

**Fix:** Implement proper key persistence (IndexedDB for web, Keychain/Keystore for mobile) with encrypted storage. Keys must survive app restarts.

**Acceptable for:** Nothing. This is broken by design.

---

#### 1.2 In-Memory Replay Protection (CRITICAL)
**File:** [`packages/sdk/facade/replay-manager.ts:1-146`](packages/sdk/facade/replay-manager.ts:1)

```typescript
// ⚠️ CRITICAL LIMITATIONS (v2.1):
// 1. IN-MEMORY ONLY - DEMO-LEVEL PROTECTION
//    - Process restart → cache cleared → replay window reopens
//    - Clustered deployment → each instance has separate cache
//    - Mobile background → iOS/Android may kill process
// 2. ATTACK WINDOW: 5 minutes after restart/cache clear
```

**Severity:** CRITICAL  
**Why it matters:** Replay protection is the ONLY defense against message replay attacks. With in-memory storage:
- Attacker can replay ANY message after app restart
- 5-minute window allows mass replay attacks
- Mobile apps are particularly vulnerable (OS kills background processes)

**What breaks at scale:** Distributed systems have independent caches—replay protection is completely ineffective across instances.

**What breaks under attack:** Attacker waits for victim to restart app, then replays old messages. With 5-minute TTL, they have ample time.

**Fix:** Persistent replay protection storage. Minimum: IndexedDB/localStorage. Production: Redis or distributed cache.

**Acceptable for:** Pre-seed demo only. Unacceptable for anything else.

---

#### 1.3 TOFU Fingerprints Lost on Restart (CRITICAL)
**File:** [`packages/sdk/facade/tofu-manager.ts:1-150`](packages/sdk/facade/tofu-manager.ts:1)

```typescript
// In-memory fingerprint cache (fallback when PostgreSQL unavailable)
const fingerprintCache = new Map<string, FingerprintRecord>();
// Multi-device: NOT supported (each device = new identity)
// Reinstall: fingerprint lost (in-memory only)
```

**Severity:** CRITICAL  
**Why it matters:** TOFU (Trust On First Use) is the security model. Without persistent fingerprints:
- Every app restart = new TOFU opportunity
- MITM attacker can substitute keys on every restart
- Users lose all trust relationships when app updates

**What breaks under attack:** Attacker simply waits for app restart, then presents their own keys. User has no way to detect the substitution.

**Fix:** Persistent fingerprint storage with cross-device sync.

**Acceptable for:** Nothing.

---

#### 1.4 Double Ratchet Implementation is Broken (CRITICAL)
**File:** [`packages/sdk/ratchet/index.ts:91-130`](packages/sdk/ratchet/index.ts:91)

```typescript
export function encryptMessage(plaintext: string, session: SessionState) {
  // Generate a new ratchet key pair
  const ratchetKeyPair = sodium.crypto_kx_keypair();
  
  // Perform a Diffie-Hellman exchange with the recipient's public key
  const sharedSecret = sodium.crypto_kx_client_session_keys(
    ratchetKeyPair.publicKey,
    ratchetKeyPair.privateKey,
    session.identityKey  // ← WRONG: Using static identity key, not ephemeral
  );
```

**Severity:** CRITICAL  
**Why it matters:** The Double Ratchet algorithm REQUIRES ephemeral key pairs that change with EVERY message. This implementation:
- Uses static identity key instead of ephemeral ratchet keys
- Breaks forward secrecy guarantees
- Makes the "ratchet" a no-op—the same keys are reused

**What breaks at scale:** Key compromise = all historical messages exposed. The entire point of Double Ratchet is defeated.

**Fix:** Proper Double Ratchet implementation with per-message ephemeral keys. Study Signal Protocol specification carefully.

**Acceptable for:** Nothing.

---

### 🟠 HIGH SEVERITY ISSUES

#### 1.5 Missing AAD (Additional Authenticated Data) in Legacy Path
**File:** [`packages/sdk/ratchet/index.ts:110-117`](packages/sdk/ratchet/index.ts:110)

```typescript
const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
  sodium.from_string(plaintext),
  null, // No additional data
  null,
  nonce,
  messageKey
);
```

**Severity:** HIGH  
**Why it matters:** Without AAD, the cipher is vulnerable to certain classes of attacks including key commitment issues.

**Fix:** Bind ciphertext to session identifiers via AAD.

---

#### 1.6 Token Generation is Weak
**File:** [`src/storage/db.ts:52`](src/storage/db.ts:52)

```typescript
const token = `stvor_live_${Math.random().toString(36).slice(2, 14)}`;
```

**Severity:** HIGH  
**Why it matters:** `Math.random()` is NOT cryptographically secure. Tokens can be predicted.

**Fix:** Use `crypto.randomBytes()` from Node.js crypto module.

---

#### 1.7 X3DH Missing DH1 Calculation
**File:** [`packages/sdk/facade/crypto-session.ts:162-180`](packages/sdk/facade/crypto-session.ts:162)

The X3DH handshake only computes DH2 and DH3, missing DH1 (IK_A × IK_B). This weakens the key exchange.

---

#### 1.8 No Constant-Time Comparison for Secrets
**File:** [`src/routes/metrics-verification.ts:180-187`](src/routes/metrics-verification.ts:180)

```typescript
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
```

**Severity:** MEDIUM-HIGH  
**Why it matters:** While this implementation looks correct, it operates on strings, not byte arrays. JavaScript string comparison has subtle timing characteristics. Use `crypto.timingSafeEqual()` instead.

---

### 🟡 MEDIUM SEVERITY ISSUES

#### 1.9 In-Memory Message Storage
**File:** [`src/relay/server.ts:7`](src/relay/server.ts:7)

```typescript
const registry = new Map<string, Map<string, { publicKeys: any; messages: any[] }>>();
```

Messages stored in memory with 10-minute TTL. No persistence across restarts. Messages lost on deployment.

---

#### 1.10 JSON File Storage for API Keys
**File:** [`src/storage/json.ts:1-150`](src/storage/json.ts:1)

Production deployments fall back to JSON file storage if PostgreSQL is unavailable. This is:
- Not atomic
- Not concurrent-safe
- Lost on container restart

---

#### 1.11 No Input Validation on Ciphertext Size
While there's a 32KB limit on relay, the SDK doesn't validate message sizes before encryption, allowing DoS via memory exhaustion.

---

#### 1.12 Test Suite is Placeholder
**File:** [`packages/sdk/package.json:54`](packages/sdk/package.json:54)

```json
"test": "echo \"No tests yet\" && exit 0"
```

No actual test coverage. The test files that exist contain tests that reference undefined functions.

---

#### 1.13 Typo in app.ts
**File:** [`packages/sdk/facade/app.ts:334`](packages/sdk/facade/app.ts:334)

```typescript
returcryptoSession.destroy();  // ← "returcryptoSession" - doesn't compile
```

This is a syntax error that would prevent compilation.

---

### 🟢 LOW SEVERITY ISSUES

#### 1.14 Hardcoded Default Passwords
**File:** [`src/storage/db.ts:7-12`](src/storage/db.ts:7)

```typescript
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'stvor123',
```

Default password in code.

#### 1.15 Missing Rate Limiting on Key Endpoints
Bootstrap and import-key endpoints lack rate limiting in development.

---

## 2. ARCHITECTURE ASSESSMENT

### Current Classification: **PRE-MVP / RESEARCH PROTOTYPE**

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Production-grade | ❌ NO | In-memory storage for critical security state |
| Research-grade | ⚠️ PARTIAL | Signal Protocol understood but incorrectly implemented |
| Demo-level | ✅ YES | Works in single-instance demo scenarios |
| Enterprise-ready | ❌ NO | Multiple blocking issues for enterprise use |

### Project Stage Classification

**Current Stage: PRE-MVP**

Justification:
1. **No persistent key storage** — Identity doesn't survive restart
2. **Broken Double Ratchet** — Forward secrecy doesn't work
3. **In-memory security state** — Replay/TOFU protection lost on restart
4. **No test coverage** — "No tests yet" in package.json
5. **Compilation errors** — Typo in app.ts would break build
6. **Mixed cryptographic implementations** — Some use Web Crypto, some use libsodium inconsistently

### Architecture Patterns

**Good:**
- Separation of concerns (facade/ratchet/storage layers)
- Use of libsodium (modern crypto library)
- Attempt at X3DH + Double Ratchet (Signal Protocol)

**Bad:**
- In-memory state for security-critical components
- No clear persistence strategy
- Mixed async/sync patterns
- No clear error handling strategy

---

## 3. ACCELERATOR EVALUATION (Brutal Honesty)

### Would Techstars/YC/500 Global Fund This?

**Answer: NO**

### Why Not?

1. **Technical Moat = Zero**
   - Broken implementation of standard protocols
   - Nothing proprietary or defensible
   - Competitors (Signal, Matrix, Virgil Security) have working implementations

2. **Founder Risk = HIGH**
   - Code shows lack of production systems experience
   - No awareness of persistence requirements
   - "No tests yet" in package.json is a red flag
   - Basic compilation errors present

3. **Not Venture-Scale**
   - This is a feature, not a product
   - E2EE is commoditized
   - No clear distribution strategy
   - No network effects

4. **Dangerous to Deploy**
   - False sense of security
   - Liability exposure if marketed as "secure"

### What Blocks Funding?

| Blocker | Severity |
|---------|----------|
| Broken Double Ratchet | CRITICAL |
| No persistent identity | CRITICAL |
| No tests | HIGH |
| Compilation errors | HIGH |
| In-memory security state | CRITICAL |
| No technical moat | HIGH |

### What Signals Are Strong?

- Attempt at proper crypto (X3DH, Double Ratchet)
- libsodium usage (modern primitives)
- Documentation effort (though misleading about security)

### What Signals Are Weak?

- Everything else
- No production experience evident
- Copy-paste from Signal docs without understanding
- "Works in demo" mentality

### Is This Defensible?

**No.**

E2EE infrastructure is a commodity. Signal's protocol is public. The only defensible aspects are:
1. Operational excellence (not demonstrated)
2. Network effects (none here—it's an SDK)
3. Proprietary enhancements (none—broken implementation)

### Is This Venture-Scale?

**No.**

This is a feature that could be part of a larger product. As a standalone:
- Low margins (infrastructure)
- High support burden (crypto is hard)
- Commoditized space
- No clear path to $100M+ revenue

### Scores (1-10)

| Category | Score | Justification |
|----------|-------|---------------|
| Technical Depth | 3/10 | Knows the buzzwords, doesn't understand implementation |
| Market Readiness | 1/10 | Not production-ready, dangerous to deploy |
| Founder Execution | 2/10 | Compilation errors, no tests, fundamental design flaws |
| Investment Readiness | 1/10 | Would be irresponsible to fund in current state |
| Moat/Defensibility | 1/10 | Commodity technology, broken implementation |
| Urgency | 2/10 | E2EE market exists but this doesn't solve it |

---

## 4. HEALTHCARE COMPANY EVALUATION

### Use Case: Medical Messaging / Patient Data / Clinical Systems

**VERDICT: ABSOLUTELY NOT — HIPAA VIOLATION RISK**

### Compliance Risk: CRITICAL

| Requirement | Status | Risk |
|-------------|--------|------|
| Access Controls | ❌ FAIL | No persistent identity = no audit trail |
| Audit Logs | ❌ FAIL | Messages lost on restart |
| Data Integrity | ❌ FAIL | Replay attacks possible |
| Encryption | ⚠️ WEAK | Broken ratchet = no forward secrecy |
| Key Management | ❌ FAIL | Keys lost on restart |

### Auditability: NONE

- Messages stored in memory for 10 minutes then gone
- No persistent logs
- Identity changes on restart
- Cannot reconstruct who accessed what

### Key Management Risk: CRITICAL

- Identity keys ephemeral
- No HSM integration
- No key rotation strategy
- No key recovery mechanism

### Data Breach Risk: HIGH

- Forward secrecy doesn't work
- Attacker who compromises keys can decrypt all messages
- Replay attacks allow message replay

### Would You Integrate Into Hospital Infrastructure?

**ABSOLUTELY NOT.**

### What Must Change?

1. Complete reimplementation of Double Ratchet
2. Persistent encrypted key storage
3. HSM integration for key protection
4. Comprehensive audit logging
5. HIPAA compliance documentation
6. Security audit by third party
7. Bug bounty program
8. Incident response plan

**Timeline: 12-18 months minimum**

---

## 5. FINTECH COMPANY EVALUATION

### Use Case: Payment Infrastructure / Financial Messaging / Crypto Custody

**VERDICT: ABSOLUTELY NOT — FINRA/SEC VIOLATION RISK**

### Cryptographic Soundness: BROKEN

| Property | Required | Actual | Status |
|----------|----------|--------|--------|
| Forward Secrecy | YES | NO (broken ratchet) | ❌ FAIL |
| Post-Compromise Security | YES | NO | ❌ FAIL |
| Replay Protection | YES | NO (in-memory) | ❌ FAIL |
| Identity Binding | YES | NO (ephemeral) | ❌ FAIL |

### Attack Surface: LARGE

- In-memory storage = easy extraction
- No code signing on SDK
- No certificate pinning
- MITM vulnerability on every restart

### Regulatory Exposure: EXTREME

- Using this for financial messages would violate:
  - FINRA Rule 3110 (Supervision)
  - SEC Rule 17a-4 (Recordkeeping)
  - PCI-DSS (if card data involved)

### Would You Integrate?

**ABSOLUTELY NOT.**

### What Must Be Production-Grade First?

Everything. This is not suitable for fintech in any capacity.

---

## 6. MARKET & POSITIONING

### What Problem Is REALLY Being Solved?

**Claim:** "Easy E2EE for developers"

**Reality:** Broken E2EE that gives false sense of security

### Is It Painful Enough?

E2EE IS painful, but:
- Signal SDK exists and works
- Virgil Security exists and works
- Matrix exists and works
- OpenPGP.js exists

Developers have working options. This adds no value.

### Vitamin or Painkiller?

**Poison pill.** Appears to solve pain but creates liability.

### Who Pays?

Unclear business model. Appears to be:
- Freemium API quotas
- Enterprise licensing?

### Why Now?

No specific timing advantage. E2EE market is mature.

### Real Competitors

| Competitor | Moat | Status |
|------------|------|--------|
| Signal Protocol | Open source, battle-tested | ✅ WORKS |
| Virgil Security | Enterprise focus, support | ✅ WORKS |
| Matrix.org | Decentralized, federated | ✅ WORKS |
| OpenPGP.js | Web-native, established | ✅ WORKS |
| STVOR | None, broken implementation | ❌ BROKEN |

### Why Would Enterprise Switch?

They wouldn't. Existing solutions work.

---

## 7. BRUTAL REALITY CHECK

### Is This:

- [x] A research toy? **YES**
- [x] A hackathon-level project? **YES**  
- [ ] A serious infrastructure attempt? **NO**
- [ ] A fundable deep tech startup? **NO**

### If This Project Fails — Why Will It Fail?

1. **Technical bankruptcy** — Core implementation is broken
2. **False marketing** — Claims security it doesn't provide
3. **No market need** — Competitors exist and work
4. **Liability exposure** — Users who deploy face breaches

### If This Succeeds — What Made It Succeed?

Requires complete reinvention:
1. Hire cryptographer with Signal Protocol experience
2. 12-month rebuild with proper engineering
3. Third-party security audit
4. Bug bounty program
5. Focus on specific vertical (healthcare compliance)

---

## 8. ACTION PLAN

### 30-Day Fix Plan

**Week 1: Stop the Bleeding**
- [ ] Fix compilation error in app.ts
- [ ] Implement persistent key storage (IndexedDB/localStorage)
- [ ] Implement persistent fingerprint storage
- [ ] Add basic test suite (minimum 50% coverage)

**Week 2: Fix Double Ratchet**
- [ ] Study Signal Protocol specification
- [ ] Rewrite ratchet to use per-message ephemeral keys
- [ ] Add proper KDF chains

**Week 3: Security Hardening**
- [ ] Replace Math.random() with crypto.randomBytes()
- [ ] Add persistent replay protection
- [ ] Implement proper AAD

**Week 4: Testing & Documentation**
- [ ] Unit tests for all crypto operations
- [ ] Integration tests
- [ ] Update documentation to reflect actual security properties

### 90-Day Credibility Plan

**Month 2: Architecture**
- [ ] Separate relay into stateless service
- [ ] Add Redis for shared state
- [ ] Implement proper message persistence
- [ ] Add monitoring and alerting

**Month 3: Security**
- [ ] Third-party security audit
- [ ] Fix all audit findings
- [ ] Bug bounty program launch
- [ ] Security documentation

### 6-Month "Investable" Roadmap

| Milestone | Timeline | Deliverable |
|-----------|----------|-------------|
| Working Double Ratchet | Month 1 | Correct Signal Protocol implementation |
| Persistent Security State | Month 2 | Keys survive restart |
| Production Relay | Month 3 | Redis, monitoring, HA |
| Security Audit | Month 4 | Clean third-party report |
| Compliance Documentation | Month 5 | SOC 2 Type I preparation |
| First Paid Customer | Month 6 | Revenue validation |

### What MUST Be Removed

1. **JSON file storage** — Not production-grade
2. **In-memory security state** — All of it
3. **Bootstrap endpoints** — Security hole
4. **Math.random() for tokens** — Weak RNG
5. **Legacy ECDH implementation** — Broken

### What MUST Be Added

1. **Persistent encrypted storage** — For all keys
2. **Proper Double Ratchet** — Per Signal spec
3. **Comprehensive test suite** — >80% coverage
4. **Security audit** — Third party
5. **Compliance documentation** — SOC 2, HIPAA
6. **Incident response plan**
7. **Bug bounty program**

### What MUST Be Proven With Metrics

1. **Security:** Pass third-party audit with <5 medium findings
2. **Reliability:** 99.9% uptime over 30 days
3. **Performance:** <100ms p99 latency for encryption
4. **Adoption:** 10+ production customers
5. **Revenue:** $10K MRR

---

## CONCLUSION

**STVOR SDK is not investable in its current state.**

The founders show ambition but lack the production engineering and cryptographic expertise to build secure infrastructure. The codebase is a collection of good intentions with dangerous implementation gaps.

**To become investable:**
1. Hire experienced cryptographer
2. Rebuild core with proper engineering discipline
3. Security audit
4. First paying customers

**Timeline to investability: 6-12 months minimum**

**Current recommendation: PASS**

---

*Report compiled: 2026-03-01*  
*Analyst: Technical Due Diligence Team*  
*Classification: CONFIDENTIAL*
