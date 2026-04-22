# STVOR Architecture

Complete technical architecture documentation.

---

## System Overview

```
┌────────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ Browser SDK  │  │ Node.js SDK  │  │ React/Vue Hooks  │ │
│  │ (@stvor/sdk) │  │ (@stvor/sdk) │  │ (useStvor)       │ │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
│         └──────────────────┼────────────────────┘           │
└────────────────────────────┼───────────────────────────────┘
                             │ HTTPS/WebSocket
┌────────────────────────────┼───────────────────────────────┐
│                    SERVER LAYER                            │
│         ┌────────────────────────────────────────┐         │
│         │  Fastify Application (Node.js)         │         │
│         │  ├─ API Routes (Port 3001)             │         │
│         │  ├─ Relay Routes (Port 3002)          │         │
│         │  ├─ WebSocket Handler (Port 8080)     │         │
│         │  └─ Middleware (Auth, CORS, Rate)     │         │
│         └────────────────┬───────────────────────┘         │
│                          │                                  │
│         ┌────────────────┼───────────────────────┐          │
│         │                │                       │          │
│  ┌──────▼──────┐  ┌─────▼─────┐  ┌────────────┐ │         │
│  │ Auth Module │  │ Relay Mgr  │  │ Analytics  │ │         │
│  │ (API Key)   │  │ (User Reg) │  │ Engine     │ │         │
│  └──────┬──────┘  └─────┬─────┘  └────┬───────┘ │         │
│         │                │             │         │         │
│         └────────────────┼─────────────┘         │         │
│                          │                       │         │
│              ┌───────────┴────────────┐          │         │
│              │   Storage Layer        │          │         │
│              │   ┌────────────────┐   │          │         │
│              │   │ PostgreSQL DB  │   │          │         │
│              │   │ (Persistent)   │   │          │         │
│              │   └────────────────┘   │          │         │
│              │   ┌────────────────┐   │          │         │
│              │   │ Redis Cache    │   │          │         │
│              │   │ (Replay Prot)  │   │          │         │
│              │   └────────────────┘   │          │         │
│              │   ┌────────────────┐   │          │         │
│              │   │ JSON Fallback  │   │          │         │
│              │   │ (No DB mode)   │   │          │         │
│              │   └────────────────┘   │          │         │
│              └───────────────────────┘          │         │
└───────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Client SDK (@stvor/sdk)

**Location**: `packages/sdk/`

**Main Entry Points**:
- `index.ts` - Node.js export (`Stvor` class)
- `web.ts` - Browser export (`StvorWebSDK` class)
- `react-hooks.ts` - React integration
- `vue-composition.ts` - Vue 3 integration

**Class Hierarchy**:

```
Stvor (Node.js interface)
├─ StvorApp (multi-user manager)
│   └─ StvorFacadeClient[] (per-user wrapper)
│       └─ CryptoSessionManager (encryption state)
│           ├─ X3DHHandshake (initial key exchange)
│           ├─ RatchetSession (message-level ratcheting)
│           └─ RelayClient (HTTP transport)
│
StvorWebSDK (Browser interface)
└─ Similar internal structure
```

**Key Classes**:

| Class | File | Purpose |
|-------|------|---------|
| `StvorApp` | `facade/app.ts` | Multi-user session manager |
| `CryptoSessionManager` | `facade/crypto-session.ts` | Encryption state machine |
| `RelayClient` | `facade/relay-client.ts` | HTTP/WebSocket transport |
| `RatchetSession` | `ratchet/session.ts` | Double Ratchet algorithm |
| `X3DHHandshake` | `ratchet/x3dh.ts` | X3DH key exchange |
| `MetricsAttestationEngine` | `facade/metrics-engine.ts` | Cryptographic metrics |
| `BatchEngine` | `facade/batch-engine.ts` | Message batching/queuing |

**Data Flow**:

```
connect() [config]
  ↓ Generate identity key pair (ECDH P-256)
  ↓ POST /register → Server stores public key
  ↓ Start polling /retrieve every 1000ms
  ↓ Return ready client
  
send(recipientId, data)
  ↓ If first message to recipient:
  │  ├─ Fetch recipient's public key
  │  ├─ Run X3DH(my_identity, recipient_public)
  │  └─ Establish shared secret
  ↓ Initialize Double Ratchet with shared secret
  ↓ Advance ratchet: get per-message key
  ↓ Encrypt data with AES-256-GCM
  ↓ Sign with ECDSA
  ↓ POST /send {to, ciphertext, signature}
  ↓ Relay stores in {to}'s queue
  
receive (polling /retrieve)
  ← Get encrypted message blobs
  ↓ Verify ECDSA signature
  ↓ Advance ratchet: derive per-message key
  ↓ Decrypt with AES-256-GCM
  ↓ Deserialize data
  ↓ Fire onMessage() callback
```

### 2. Backend Server

**Location**: `src/`

**Main Entry**: `src/server.ts`

```ts
// Initialization sequence:
1. Load environment (.env)
2. Initialize storage layer (DB/Redis/JSON)
3. Create Fastify instance
4. Register CORS middleware
5. Register authentication middleware
6. Register rate limiting
7. Mount routes (health, projects, relay)
8. Spawn RelayServer on separate port
9. Listen on PORT (default 3001)
```

#### 2.1 Authentication Module

**File**: `src/auth/apiKey.ts`

- Generates project-specific API keys
- Format: `stvor_live_<uuid>` or `stvor_test_<uuid>`
- Stored in PostgreSQL (encrypted)
- Validated on every request

**Middleware**: `src/middleware/auth.ts`

```ts
// Checks Authorization header
// Extracts Bearer token
// Validates against database
// Attaches project context to request
// Public routes bypass auth (health, bootstrap)
```

#### 2.2 Relay Server

**File**: `src/relay/server.ts`

**Responsibility**: Message storage and routing

**In-Memory Data Structure**:

```ts
// Per-project registry
{
  [projectId]: {
    [userId]: {
      identityKey: 'base64-public-key',
      messages: [
        {
          from: 'alice',
          ciphertext: 'base64-encrypted',
          signature: 'base64-ecdsa',
          timestamp: 1234567890,
          nonce: 'uuid',
        }
      ]
    }
  }
}

// Message lifecycle
Store (timestamp=now)
  ↓ wait 10 minutes
  ↓ Auto-delete (TTL cleanup)
  ↓ OR recipient retrieves
```

**Routes**:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/register` | User registration |
| POST | `/send` | Store encrypted message |
| GET | `/retrieve` | Get pending messages |
| GET | `/health` | Server status |

#### 2.3 API Routes

**File**: `src/routes/`

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Dashboard HTML (dev) |
| `GET /health` | Health check |
| `POST /bootstrap` | Create project + API key (dev) |
| `POST /projects` | Create project |
| `GET /projects/:id` | Get project info |
| `GET /usage` | Current quota usage |
| `GET /limits` | Rate limit info |
| `POST /api/metrics/attest` | Submit metrics |
| `GET /analytics/*` | Analytics endpoints |
| `GET /__routes` | List all routes (debug) |

#### 2.4 Middleware Stack

```
Request
  ↓ [1] CORS (fastify-cors)
  ↓ [2] Rate Limit (fastify-rate-limit)
  ↓ [3] Auth (apiKey validation)
  ↓ [4] Route Handler
  ↓
Response
```

**Rate Limiting**: 100 requests/minute per IP

**Error Handling**:
```ts
// All errors wrapped in StvorError
{
  code: 'ERR_INVALID_KEY' | 'ERR_RATE_LIMITED' | etc,
  message: 'Human readable',
  statusCode: 400 | 429 | 500,
}
```

### 3. Storage Layer

**Location**: `src/storage/`

**Architecture**: Multi-adapter pattern

```
Storage Interface (abstract)
├── PostgreSQL (primary)
├── Redis (cache layer)
├── JSON (fallback)
└── Memory (ephemeral)

Selection Logic:
1. PostgreSQL if available + healthy
2. Fall back to JSON if PG down
3. Redis optional (auto-enabled if available)
4. Memory used for active sessions (non-persistent)
```

#### 3.1 PostgreSQL (`src/storage/db.ts`)

**Schema** (see `migrations/`):

```sql
-- Projects
CREATE TABLE projects (
  id UUID PRIMARY KEY,
  name VARCHAR,
  api_key VARCHAR UNIQUE,
  created_at TIMESTAMP
);

-- Metrics (analytics)
CREATE TABLE metrics (
  id UUID PRIMARY KEY,
  project_id UUID REFERENCES projects,
  event_type VARCHAR,
  timestamp TIMESTAMP,
  data JSONB
);

-- Handshakes (security tracking)
CREATE TABLE handshakes (
  id UUID PRIMARY KEY,
  project_id UUID,
  initiator_id VARCHAR,
  responder_id VARCHAR,
  timestamp TIMESTAMP,
  status VARCHAR  -- 'success' | 'failed'
);
```

**Connection Pool**:
```ts
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,  // connections
});
```

#### 3.2 Redis Cache (`src/storage/redis-replay-cache.ts`)

**Purpose**: Replay protection

**Data Structure**:
```
Key: {projectId}:{nonce}
Value: {timestamp}
TTL: 5 minutes (auto-expire)

On message arrival:
  ↓ Check if nonce exists in Redis
  ↓ If exists: reject (replay)
  ↓ If not: SET with TTL, accept
```

#### 3.3 JSON Fallback (`src/storage/json.ts`)

**File**: `data/stvor.json`

**Structure**:
```json
{
  "projects": [
    {
      "id": "uuid",
      "name": "My App",
      "apiKey": "stvor_live_xxx",
      "metrics": []
    }
  ]
}
```

**When Used**:
- Local development
- PostgreSQL unavailable
- Testing/demos

### 4. Cryptography Implementation

**Location**: `packages/sdk/ratchet/`

#### 4.1 X3DH (Extended Triple Diffie-Hellman)

**File**: `ratchet/x3dh.ts`

**Algorithm**:
```
Alice → Bob:
  ↓ alice_identity = ECDH.generateKeyPair()  [P-256]
  ↓ alice_prekey = ECDH.generateKeyPair()    [P-256]
  ↓ POST /register {identityKey, prekey}
  ↓
Bob receives message from Alice:
  ↓ dh1 = ECDH(bob_identity, alice_identity)
  ↓ dh2 = ECDH(bob_prekey, alice_identity)
  ↓ dh3 = ECDH(bob_identity, alice_prekey)
  ↓ dh4 = ECDH(bob_prekey, alice_prekey)
  ↓
shared_secret = HKDF-SHA256(
  salt: 'STVOR-X3DH',
  input: dh1 || dh2 || dh3 || dh4,
  length: 32
)
```

**Security Properties**:
- ✓ Perfect forward secrecy (if bob_prekey compromised)
- ✓ Mutual authentication (both sides derive same secret)
- ✓ Requires no previous communication

#### 4.2 Double Ratchet

**File**: `ratchet/session.ts`

**State**:
```ts
{
  rootKey: Buffer,           // Shared secret (from X3DH)
  sendChainKey: Buffer,      // For outgoing messages
  recvChainKey: Buffer,      // For incoming messages
  sendCounter: number,       // Message sequence
  recvCounter: number,
  skippedKeys: Map,          // Out-of-order message keys
}
```

**Per-Message Ratchet**:
```
Message advancement:

sendChainKey[n]
  ↓ KDF(sendChainKey[n])
  ↓ → messageKey, sendChainKey[n+1]
  ↓
Use messageKey for AES-256-GCM encryption
Send sendChainKey[n+1] as input for next message
```

**Receiving**:
```
Receive message with counter=N

if counter < expected:
  ↓ Out-of-order message
  ↓ Check skippedKeys cache
  ↓ If found: decrypt + cache others
  ↓ If not found: drop (replay or missing)
  
if counter == expected:
  ↓ Advance chain: KDF(recvChainKey) → messageKey
  ↓ Decrypt message
  
if counter > expected:
  ↓ Save messageKey in skippedKeys
  ↓ Advance chain N times
```

**Forward Secrecy**:
- Compromise of messageKey[n] → no exposure of messageKey[n-1] or messageKey[n+1]
- Old messageKeys automatically deleted after TTL

#### 4.3 Encryption (AES-256-GCM)

**Algorithm**: AES-256-GCM (NIST approved)

```ts
plaintext = { text: 'Hello' }
serialized = JSON.stringify(plaintext)
iv = randomBytes(12)  // 96-bit, unique per message
ciphertext = AES-256-GCM.encrypt(
  key: messageKey,
  plaintext: serialized,
  iv: iv,
  aad: `${senderId}:${recipientId}`  // Authentication
)
result = {
  ciphertext: base64(ciphertext),
  iv: base64(iv),
  tag: base64(authTag)  // Built-in to GCM
}
```

**Decryption**: Validates authentication tag before returning plaintext

#### 4.4 Signatures (ECDSA P-256)

**Algorithm**: ECDSA P-256-SHA256

```ts
// On send
payload = { to, ciphertext, iv, timestamp }
signature = ECDSA_P256.sign(payload, senderPrivateKey)

// On receive
verified = ECDSA_P256.verify(payload, signature, senderPublicKey)
if (!verified) throw 'Invalid signature'
```

---

## Message Flow Diagram

### Full Happy Path

```
[INITIALIZATION]

alice.connect({userId: 'alice', appToken: 'xxx'})
  ↓
  ├─ Generate alice_identity = ECDH.generateKeyPair()
  ├─ Store in IndexedDB (browser) or file (Node.js)
  └─ POST /register {userId: 'alice', identityKey: alice_pub}
      └─ Relay stores {alice → alice_pub}
        
bob.connect({userId: 'bob', appToken: 'xxx'})
  ├─ Generate bob_identity = ECDH.generateKeyPair()
  ├─ Store locally
  └─ POST /register {userId: 'bob', identityKey: bob_pub}
      └─ Relay stores {bob → bob_pub}

Start polling: every 1000ms, alice.poll /retrieve, bob.poll /retrieve


[MESSAGE SEND]

alice.send('bob', 'Hello')
  ↓ [1] Fetch bob's identityKey from relay
  ↓ [2] X3DH key exchange
  │    ├─ dh1 = ECDH(alice_identity, bob_pub)
  │    ├─ dh2 = ECDH(alice_prekey, bob_pub)
  │    ├─ ... (4 DH operations)
  │    └─ shared_secret = HKDF(concat all)
  ↓ [3] Initialize RatchetSession with shared_secret
  ↓ [4] Advance ratchet: KDF(rootKey) → sendChainKey
  ↓ [5] KDF(sendChainKey) → messageKey_0
  ↓ [6] Serialize message: {text: 'Hello'}
  ↓ [7] Encrypt with AES-256-GCM
       iv = random(12)
       ct, tag = AES256GCM.encrypt(msg, messageKey_0, iv)
  ↓ [8] Sign payload with ECDSA
       sig = ECDSA.sign({to: 'bob', ciphertext, ...}, alice_priv)
  ↓ [9] POST /send {
         to: 'bob',
         ciphertext: base64(ct),
         signature: base64(sig),
         timestamp: now,
         nonce: uuid
       }
  └─ Relay validates sig, checks nonce, stores in bob's queue


[MESSAGE RECEIVE - polling]

Every 1000ms:
  bob.poll()
    ↓ GET /retrieve?userId=bob Authorization: Bearer xxx
    ← Relay returns [{from: 'alice', ciphertext, signature, ...}]
    ↓ [1] Verify ECDSA signature
         verified = ECDSA.verify(payload, sig, alice_pub)
    ↓ [2] Check replay protection
         if (nonce in replayCache) reject
         replayCache.add(nonce)
    ↓ [3] If first message from alice:
         └─ Perform X3DH on bob's side
            └─ shared_secret = same as alice computed!
    ↓ [4] Initialize RatchetSession
    ↓ [5] Advance ratchet to get messageKey_0
    ↓ [6] Decrypt AES-256-GCM
         plaintext = AES256GCM.decrypt(ct, messageKey_0, iv, tag)
    ↓ [7] Deserialize JSON
    ↓ [8] Fire onMessage callback
         bob.onMessage({from: 'alice', data: {text: 'Hello'}, timestamp})
```

---

## Security Guarantees

### Confidentiality
- **Encryption**: AES-256-GCM (symmetric, 256-bit key)
- **Key Derivation**: HKDF-SHA256 (PRF)
- **Key Exchange**: ECDH P-256 (asymmetric, 128-bit security)
- **Result**: Server cannot decrypt (no access to keys)

### Authenticity
- **Message Auth**: ECDSA P-256 signatures
- **Channel Auth**: API key (project-level)
- **Result**: Forgery detectable

### Integrity
- **AEAD**: AES-256-GCM includes authentication tag
- **Tampering**: Automatically rejected
- **Result**: No silent corruption

### Forward Secrecy
- **Per-Message Keys**: Double Ratchet
- **Compromise Impact**: Only current message exposed
- **Result**: Past messages remain secure

### Post-Compromise Security
- **Automatic Ratchet**: Forced advancement per message
- **Recovery Time**: 1 message latency
- **Result**: Future messages secure even if key stolen

---

## Performance Characteristics

### Latency

| Operation | Time | Notes |
|-----------|------|-------|
| X3DH handshake | ~10ms | One-time per peer |
| Message encrypt | ~2ms | Per message |
| Message decrypt | ~2ms | Per message |
| Network roundtrip | 50-200ms | Relay latency |
| **Total send-to-deliver** | 60-220ms | Mainly network |

### Throughput

- **Relay storage**: 10,000+ messages/sec per node
- **Client send rate**: 1000+ msg/sec per connection
- **Polling overhead**: <5ms per /retrieve call
- **Memory per session**: ~50KB (keys + ratchet state)

### Scalability

**Current Limits**:
- Rate limiting: 100 req/min per IP
- Per-project queue: 10,000 messages default
- Retention: 10 minutes (auto-clean)
- Concurrent users per relay: 10,000+ (tested)

---

## Data Models

### Core Entities

```ts
// Project
{
  id: UUID,
  name: string,
  apiKey: string,  // stvor_live_xxx or stvor_test_xxx
  createdAt: Date,
}

// User (SDK-side, not stored on relay)
{
  userId: string,
  identityKey: {
    publicKey: Buffer,
    privateKey: Buffer,
  },
  prekey: {
    publicKey: Buffer,
    privateKey: Buffer,
  },
}

// Message (in transit, encrypted)
{
  id: UUID,
  from: string,
  to: string,
  ciphertext: Buffer,
  iv: Buffer,
  signature: Buffer,
  timestamp: Date,
  nonce: UUID,  // Replay protection
}

// Session (client-side, in-memory)
{
  peerId: string,
  rootKey: Buffer,
  sendChainKey: Buffer,
  recvChainKey: Buffer,
  sendCounter: number,
  recvCounter: number,
  skippedKeys: Map<number, Buffer>,
}

// Metrics (stored in DB)
{
  id: UUID,
  projectId: UUID,
  eventType: string,  // 'handshake' | 'message_send' | 'message_recv' | 'error'
  timestamp: Date,
  data: object,  // event-specific
}
```

---

## Deployment Topology

### Single Node

```
┌─────────────────────────────────┐
│  stvor-api container            │
│  ├─ API (3001)                  │
│  ├─ Relay (3002)                │
│  └─ WS (8080)                   │
└──────┬──────────────┬──────┬────┘
       │              │      │
   ┌───▼──┐      ┌────▼─┐ ┌─▼────┐
   │ PG   │      │Redis │ │Files │
   └──────┘      └──────┘ └──────┘
```

### High Availability

```
┌────────────────┐  ┌────────────────┐
│ stvor-api (1)  │  │ stvor-api (2)  │
│ Port 3001      │  │ Port 3001      │
└────┬──────┬────┘  └────┬──────┬────┘
     │      │             │      │
     └──┬───┼─────┬───┬───┴──┬───┘
        │   │     │   │      │
   ┌────▼───▼─┐  ┌─┴──▼────┐
   │PostgreSQL│  │ Redis   │
   │Cluster   │  │Cluster  │
   └──────────┘  └─────────┘
```

**Load Balancer** (Nginx/HAProxy):
```nginx
upstream stvor {
  server 127.0.0.1:3001;
  server 127.0.0.1:3002;  # alt Relay
}
server {
  listen 443 ssl;
  location /send { proxy_pass http://stvor; }
  location /retrieve { proxy_pass http://stvor; }
}
```

---

## Deployment Checklist

- [ ] PostgreSQL 15+ with SSL
- [ ] Redis 7+ for replay protection
- [ ] Environment variables set
- [ ] TLS certificates configured
- [ ] Rate limiting rules verified
- [ ] Database migrations run
- [ ] Backup strategy in place
- [ ] Monitoring alerts configured
- [ ] Log aggregation setup
- [ ] Disaster recovery plan

---

## Future Roadmap

- [ ] Post-quantum cryptography (Kyber/Dilithium)
- [ ] Group chat (1-to-many messaging)
- [ ] End-to-end verified metrics
- [ ] Message reactions/receipts
- [ ] Typing indicators
- [ ] Offline message sync
- [ ] Third-party security audit
- [ ] Native mobile SDKs (iOS/Android)
- [ ] GraphQL API
- [ ] Webhook notifications
