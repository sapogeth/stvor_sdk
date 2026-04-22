# STVOR

End-to-end encrypted messaging platform. Zero-knowledge relay server.

**[stvor.xyz](https://stvor.xyz)** • **[GitHub](https://github.com/sapogeth/stvor_sdk)**

---

## What is STVOR?

STVOR is a drop-in encryption library that lets you add end-to-end encrypted messaging to any app. The relay server never sees message content—only encrypted ciphertext.

**Core guarantees:**
- **Zero-knowledge**: Server has no access to plaintext messages
- **Forward secrecy**: Compromised keys don't expose past messages
- **Post-compromise security**: Automatic key rotation protects future messages
- **Drop-in**: 3 lines of code to send encrypted messages

**Uses:** Signal Protocol (X3DH + Double Ratchet), AES-256-GCM, ECDSA P-256, HKDF-SHA-256.

---

## Quick Start

### Node.js

```bash
npm install @stvor/sdk
```

```ts
import { Stvor } from '@stvor/sdk';

const alice = await Stvor.connect({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

alice.onMessage(msg => {
  console.log(`${msg.from}: ${msg.data}`);
});

await alice.send('bob', 'Hello encrypted!');
```

### Browser

```ts
import { StvorWebSDK } from '@stvor/sdk/web';

const sdk = await StvorWebSDK.create({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

await sdk.send('bob', { text: 'Hello!' });
```

### React Hook

```tsx
import { useStvor } from '@stvor/sdk/react';

export function Chat() {
  const { connected, send, messages } = useStvor({
    userId: 'alice',
    appToken: 'stvor_live_xxx',
  });

  return (
    <div>
      {messages.map(m => <p key={m.id}>{m.from}: {m.data}</p>)}
      <button onClick={() => send('bob', 'Hi!')}>Send</button>
    </div>
  );
}
```

---

## How It Works

### The Protocol

1. **Identity**: Each user generates a persistent ECDH P-256 key pair.
2. **Session**: X3DH establishes a shared secret without central authority.
3. **Messages**: Double Ratchet advances per-message keys → perfect forward secrecy.
4. **Relay**: Server stores encrypted blob, never accesses plaintext.

```
alice.send('bob', msg)
  ↓ [encrypt with bob's key]
  ↓ POST /send
  → Relay stores {to: 'bob', ciphertext, ...}
  ← bob.poll /retrieve
  ← get encrypted blob
  ↓ [decrypt with alice's key]
  ↓ msg.onMessage() callback fires
```

### Why This Matters

- **Messenger**: End-to-end encrypted group chat without server access.
- **Banking**: Secure client-server communication where only client sees data.
- **Healthcare**: Patient data encrypted in transit and at rest on server.
- **Legal**: Attorney-client communications protected by cryptography, not policy.

---

## Core Architecture

### Three Components

```
┌─────────────────────────────┐
│  Client (@stvor/sdk)        │
│  Node.js / Browser          │
└──────────┬──────────────────┘
           │
      (HTTPS/WebSocket)
           │
┌──────────▼──────────────────┐
│  API + Relay Server         │
│  Port 3001 + 3002           │
└──────────┬──────────────────┘
           │
    ┌──────┴──────┐
    │             │
┌───▼─┐     ┌────▼────┐
│ PG  │     │  Redis  │
└─────┘     └─────────┘
```

### Services

| Service | Port | Purpose |
|---------|------|---------|
| **API Server** | 3001 | REST API: projects, metrics, health |
| **Relay Server** | 3002 | Message routing (stores encrypted blobs) |
| **WebSocket** | 8080 | Real-time message delivery (optional) |

### Data Flow

```
POST /register
  → Creates user account

POST /send {to, ciphertext, signature}
  → Relay verifies signature
  → Stores in {to}'s message queue

GET /retrieve
  → Returns pending encrypted messages
  → Auto-cleans 10+ min old messages

POST /api/metrics/attest
  → Cryptographically sign metrics
  → Store in analytics database
```

---

## Features

### Security

- ✓ **E2EE**: Messages encrypted end-to-end (server never sees plaintext)
- ✓ **Forward Secrecy**: Past messages safe if key stolen
- ✓ **Post-Compromise Security**: Future messages safe after key recovery
- ✓ **Perfect Forward Secrecy (PFS)**: ECDH prevents key compromise ripple
- ✓ **Authenticated Encryption**: AEAD (AES-256-GCM) prevents tampering
- ✓ **TOFU Verification**: Trust-on-first-use identity binding
- ✓ **Replay Protection**: Nonce + timestamp validation
- ✓ **Rate Limiting**: 100 req/min per IP
- ✓ **Circuit Breaker**: Prevents cascading failures

### Data Support

Send any JavaScript type without serialization overhead:
- Strings, numbers, booleans, null
- Objects, arrays, Maps, Sets
- Buffers, Uint8Array, ArrayBuffer
- Date, Error, custom objects

### Platforms

- **Node.js 20+** (with `node:crypto`, zero npm deps)
- **Browsers** (with Web Crypto API, zero deps)
- **React** (hooks: `useStvor()`, `useStvorMessage()`)
- **Vue 3** (composables: `useStvor()`, `useStvorMessage()`)
- **Framework-agnostic** (vanilla JS, Angular, Svelte, etc.)

### Storage

- **PostgreSQL**: Persistent metrics and analytics
- **Redis**: Replay protection cache, message deduplication
- **JSON fallback**: Works if DB unavailable
- **IndexedDB**: Browser-side key persistence

---

## Project Structure

```
stvor-api/
├── src/                      # Backend
│   ├── server.ts             # Main entry, Fastify setup
│   ├── relay/server.ts       # Message relay implementation
│   ├── auth/                 # Authentication
│   ├── routes/               # API endpoints
│   ├── storage/              # DB/Redis/JSON adapters
│   └── middleware/           # Auth, CORS, rate limiting
│
├── packages/sdk/             # @stvor/sdk library
│   ├── index.ts              # Main export
│   ├── facade/               # High-level API
│   │   ├── app.ts            # StvorApp manager
│   │   ├── crypto-session.ts # Encryption state
│   │   └── relay-client.ts   # HTTP communication
│   ├── ratchet/              # Double Ratchet implementation
│   ├── examples/             # Production examples
│   ├── react-hooks.ts        # React integration
│   └── vue-composition.ts    # Vue 3 integration
│
├── ui/                       # Admin dashboards
│   ├── dashboard.html        # Metrics & peer monitoring
│   ├── analytics.html        # Real-time analytics
│   └── dashboard-config.html # Configuration UI
│
├── migrations/               # Database schema
│   ├── 001_initial_schema.sql
│   ├── 002_metrics_schema.sql
│   ├── 003_analytics_schema.sql
│   └── 004_analytics_handshakes.sql
│
└── docker-compose.yml        # Local dev setup
```

---

## Installation & Setup

### Development (Docker)

```bash
docker-compose up
# API: http://localhost:3001
# Relay: http://localhost:3002
# Dashboard: http://localhost:3001/dashboard
```

### Manual Setup

```bash
# Install dependencies
npm install
cd packages/sdk && npm install

# Build
npm run build

# Run
npm start
# or with hot-reload:
npm run dev
```

### Environment

```bash
DATABASE_URL=postgresql://user:pass@localhost:5432/stvor
REDIS_URL=redis://localhost:6379
NODE_ENV=production
PORT=3001
```

---

## API Reference

### Client API

**Connect:**
```ts
const client = await Stvor.connect({
  userId: string,           // Unique user ID
  appToken: string,         // Bearer token (starts with 'stvor_')
  relayUrl: string,         // Relay server URL
  timeout?: number,         // Default: 10_000 ms
  pollIntervalMs?: number,  // Default: 1_000 ms
});
```

**Send:**
```ts
await client.send(recipientId, data, {
  timeout?: number  // Default: 10_000 ms
});
```

**Receive:**
```ts
const unsubscribe = client.onMessage(msg => {
  console.log(msg.from, msg.data, msg.timestamp);
});
```

**Disconnect:**
```ts
await client.disconnect();
```

### REST API (Relay)

**Register user:**
```
POST /register
Authorization: Bearer {appToken}
Content-Type: application/json

{
  "userId": "alice",
  "identityKey": "base64-encoded-public-key"
}
```

**Send message:**
```
POST /send
Authorization: Bearer {appToken}
Content-Type: application/json

{
  "to": "bob",
  "ciphertext": "base64-encoded-encrypted-data",
  "signature": "base64-encoded-ecdsa-signature"
}
```

**Retrieve messages:**
```
GET /retrieve?userId=alice
Authorization: Bearer {appToken}
```

**Health check:**
```
GET /health
```

---

## Deployment

### Docker

```bash
docker build -t stvor-api .
docker run -p 3001:3001 -p 3002:3002 \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  stvor-api
```

### Vercel (API only)

```bash
vercel deploy
# Points to src/server.ts
```

### PM2

```bash
pm2 start ecosystem.config.js
pm2 logs
```

---

## Examples

### Simple Chat

```ts
// alice.ts
import { Stvor } from '@stvor/sdk';

const alice = await Stvor.connect({
  userId: 'alice',
  appToken: process.env.APP_TOKEN,
  relayUrl: 'http://localhost:3002',
});

alice.onMessage(msg => console.log(`${msg.from}: ${msg.data}`));

await alice.send('bob', 'Hello Bob!');
```

### React Chat Component

```tsx
import { useStvor } from '@stvor/sdk/react';

export function ChatApp() {
  const { connected, messages, send } = useStvor({
    userId: 'alice',
    appToken: 'stvor_live_xxx',
  });

  const [text, setText] = useState('');

  return (
    <div style={styles.container}>
      {messages.map(m => (
        <div key={m.id} style={styles.message}>
          <strong>{m.from}:</strong> {m.data}
        </div>
      ))}
      <input
        value={text}
        onChange={e => setText(e.target.value)}
        placeholder="Message..."
        style={styles.input}
      />
      <button onClick={() => send('bob', text)}>Send</button>
    </div>
  );
}
```

### Vue 3 Chat

```vue
<template>
  <div>
    <div v-for="m in messages" :key="m.id">
      <strong>{{ m.from }}:</strong> {{ m.data }}
    </div>
    <input v-model="text" placeholder="Message..." />
    <button @click="send('bob', text)">Send</button>
  </div>
</template>

<script setup>
import { useStvor } from '@stvor/sdk/vue';

const { messages, send } = useStvor({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
});

const text = ref('');
</script>
```

---

## Security

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Relay sees messages** | End-to-end encryption (X3DH + Double Ratchet) |
| **Man-in-middle attacker** | ECDSA signatures + TOFU verification |
| **Replay attacks** | Nonce + timestamp validation |
| **Key compromise** | Forward secrecy (per-message ratcheting) |
| **Quantum computers** | Post-quantum migration planned |

### Cryptographic Primitives

- **Key Exchange**: ECDH P-256 (X3DH)
- **Encryption**: AES-256-GCM (NIST standard)
- **Authentication**: ECDSA P-256, HMAC-SHA-256
- **Key Derivation**: HKDF-SHA-256
- **Random**: Cryptographically secure (OS entropy)

### Audit Status

- ⚠️ **Not yet independently audited** (roadmap Q3 2026)
- ✓ Production-ready cryptography (NIST standards)
- ✓ Continuously reviewed by security community
- ✓ Responsible disclosure: security@stvor.xyz

---

## License

MIT

---

## Contributing

Open issues and pull requests on [GitHub](https://github.com/sapogeth/stvor_sdk).

For security issues, email security@stvor.xyz.

---

## Community

- **GitHub**: https://github.com/sapogeth/stvor_sdk
- **Discord**: [Join](https://discord.gg/stvor)
- **Twitter**: [@stvor_dev](https://twitter.com/stvor_dev)
