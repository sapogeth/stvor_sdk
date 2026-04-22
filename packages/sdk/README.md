# @stvor/sdk

End-to-end encryption for any app. Drop-in library — no cryptography knowledge required.

Uses **X3DH + Double Ratchet** (Signal Protocol) with AES-256-GCM, ECDSA P-256, and HKDF-SHA-256. Node.js uses `node:crypto` (zero native deps). Browser uses Web Crypto API (zero dependencies at all).

## Install

```bash
npm install @stvor/sdk
```

## Quickstart

### Node.js

```ts
import { Stvor } from '@stvor/sdk';

const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_live_xxx',   // from dashboard
  relayUrl: 'https://relay.example.com',
});

const bob = await Stvor.connect({
  userId:   'bob',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.example.com',
});

bob.onMessage(msg => {
  console.log(`From ${msg.from}:`, msg.data);
});

// Sends any type — string, object, Buffer, Date, Set, Map…
await alice.send('bob', { text: 'Hello!' });

await alice.disconnect();
await bob.disconnect();
```

### Browser

```ts
import { StvorWebSDK } from '@stvor/sdk/web';

const sdk = await StvorWebSDK.create({
  userId:   'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.example.com',
});

sdk.onMessage((from, data) => console.log(from, data));

await sdk.send('bob', { text: 'Hello from browser!' });
sdk.disconnect();
```

Keys are persisted in IndexedDB — identity survives page refreshes.

## How it works

1. Each user generates an identity key pair (ECDH P-256) on first connect.
2. Session is established via **X3DH** — both sides derive the same shared secret without a central server.
3. Every message advances the **Double Ratchet** — compromise of one key doesn't expose past or future messages.
4. The relay server only ever sees ciphertext.

## API — `Stvor` (Node.js)

### `Stvor.connect(config)`

```ts
const client = await Stvor.connect({
  userId:         string,   // any unique identifier
  appToken:       string,   // starts with 'stvor_'
  relayUrl:       string,
  timeout?:       number,   // ms, default: 10 000
  pollIntervalMs?: number,  // message polling, default: 1 000
});
```

### `client.send(recipientId, data, options?)`

```ts
await client.send('bob', 'Hello');
await client.send('bob', { amount: 100, currency: 'USD' });
await client.send('bob', Buffer.from([1, 2, 3]));          // binary
await client.send('bob', 'Hey', { timeout: 30_000 });      // wait up to 30s
```

Supports any JS type: string, number, boolean, null, object, Buffer, Uint8Array, Date, Set, Map.

### `client.onMessage(handler)`

```ts
const unsubscribe = client.onMessage(msg => {
  // msg.from      — sender userId
  // msg.data      — decrypted value (original type preserved)
  // msg.timestamp — Date
  // msg.id        — unique string
});

unsubscribe(); // stop listening
```

### `client.waitForUser(userId, timeoutMs?)`

```ts
const online = await client.waitForUser('bob', 15_000);
// true = registered, false = timeout
```

### `client.disconnect()`

```ts
await client.disconnect();
```

## API — `StvorWebSDK` (Browser)

Same shape as the Node.js client:

```ts
const sdk = await StvorWebSDK.create({ userId, appToken, relayUrl, pollIntervalMs? });

await sdk.send(recipientId, data);
sdk.onMessage((from, data) => { ... });
await sdk.waitForUser(userId, timeoutMs?);
sdk.disconnect();
sdk.getUserId();
```

## TOFU (Trust On First Use)

On first contact with a peer, the SDK stores their identity key fingerprint. If the fingerprint changes on a later contact, the SDK throws — protecting against MITM attacks. Works automatically.

```ts
import { revokeTrust } from '@stvor/sdk';
await revokeTrust('bob'); // trigger re-trust after intentional key rotation
```

## Persistence (Node.js)

By default, keys live in memory. To persist across restarts:

```ts
import { Stvor, CryptoSessionManager, FileIdentityStore, FileSessionStore } from '@stvor/sdk';

const manager = new CryptoSessionManager(
  'alice',
  new FileIdentityStore('./keys'),
  new FileSessionStore('./sessions'),
);
```

## Production replay protection (Redis)

```ts
import { initializeReplayProtection, RedisReplayCache } from '@stvor/sdk';
import Redis from 'ioredis';

initializeReplayProtection(new RedisReplayCache(new Redis(), { ttlSeconds: 300 }));
```

## Security properties

| Property | Implementation |
|---|---|
| Forward Secrecy | Double Ratchet — new key per message |
| Post-Compromise Security | DH ratchet rotation every message |
| Replay protection | Nonce + timestamp per message |
| TOFU | Identity binding on first contact |
| Zero-knowledge relay | Server only stores ciphertext |

## CLI

```bash
# Show relay status
STVOR_RELAY_URL=http://localhost:3002 STVOR_APP_TOKEN=stvor_live_xxx stvor-cli status

# Health check
stvor-cli health --relay http://localhost:3002

# Export stats
stvor-cli export csv --token stvor_live_xxx
```

## Self-hosting the relay

```bash
git clone https://github.com/sapogeth/stvor_sdk
cd stvor-api && npm install

RELAY_PORT=3002 node dist/relay/server.js
```

## License

MIT
