# @stvor/sdk

End-to-end encryption for any app. Drop-in library — no cryptography knowledge required.

Signal Protocol (X3DH + Double Ratchet) with AES-256-GCM, ECDSA P-256, and HKDF-SHA-256.
Optional **post-quantum protection** via ML-KEM-768 (NIST FIPS 203).
Node.js uses `node:crypto` only — zero external dependencies.

## Install

```bash
npm install @stvor/sdk
```

## Quickstart

### 1-to-1 messaging

```ts
import { Stvor } from '@stvor/sdk';

const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

const bob = await Stvor.connect({
  userId:   'bob',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

bob.onMessage(msg => console.log(msg.from, msg.data));
await alice.send('bob', { text: 'Hello!' });

await alice.disconnect();
await bob.disconnect();
```

### Post-quantum protection (ML-KEM-768)

```ts
const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
  pqc:      true,   // enables ML-KEM-768 hybrid key exchange
});
```

When `pqc: true`:
- ML-KEM-768 key pair is generated on connect
- Key exchange uses **hybrid X3DH + ML-KEM-768** — secure if either classical or PQC is unbroken
- Session root key = `HKDF(X3DH_secret ‖ ML-KEM_contribution)`
- Falls back to classical if the peer doesn't support PQC

### Group chats

```ts
await alice.createGroup('team', ['bob', 'charlie']);
await alice.sendToGroup('team', { text: 'Hello team!' });

bob.onGroupMessage(msg => {
  console.log(msg.groupId, msg.from, msg.data);
});

await alice.addGroupMember('team', 'dave');
await alice.removeGroupMember('team', 'charlie'); // auto-ratchets sender key
```

### Sealed sender (metadata protection)

```ts
const alice = await Stvor.connect({
  userId:       'alice',
  appToken:     'stvor_live_xxx',
  relayUrl:     'https://relay.stvor.xyz',
  sealedSender: true,  // relay sees `to` but never `from`
});
```

### Local development

```bash
npx @stvor/sdk mock-relay   # port 4444, no account needed
```

```ts
const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_dev_test123',
  relayUrl: 'http://localhost:4444',
});
```

### Browser

```ts
import { StvorWebSDK } from '@stvor/sdk/web';

const sdk = await StvorWebSDK.create({
  userId:   'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

sdk.onMessage((from, data) => console.log(from, data));
await sdk.send('bob', { text: 'Hello from browser!' });
```

Keys are persisted in IndexedDB — identity survives page refreshes.

## API

### `Stvor.connect(config)`

```ts
const client = await Stvor.connect({
  userId:          string,   // any unique identifier
  appToken:        string,   // starts with 'stvor_'
  relayUrl:        string,   // 'https://relay.stvor.xyz' or self-hosted
  timeout?:        number,   // ms, default: 10 000
  pollIntervalMs?: number,   // polling interval ms, default: 1 000
  sealedSender?:   boolean,  // hide sender from relay, default: false
  pqc?:            boolean,  // ML-KEM-768 hybrid key exchange, default: false
});
```

### `client.send(recipientId, data, options?)`

```ts
await client.send('bob', 'Hello');
await client.send('bob', { amount: 100, currency: 'USD' });
await client.send('bob', Buffer.from([1, 2, 3]));
await client.send('bob', new Date());
await client.send('bob', 'Hey', { timeout: 30_000 });
await client.send('bob', 'Hey', { waitForRecipient: false });
```

### `client.onMessage(handler)`

```ts
const unsubscribe = client.onMessage(msg => {
  // msg.from      — sender userId
  // msg.data      — decrypted value (original type preserved)
  // msg.timestamp — Date
  // msg.id        — string
});
unsubscribe();
```

### Group API

```ts
await client.createGroup(groupId, memberIds)
await client.sendToGroup(groupId, data)
const unsub = client.onGroupMessage(msg => { /* msg.groupId, msg.from, msg.data */ })
await client.addGroupMember(groupId, memberId)
await client.removeGroupMember(groupId, memberId)  // auto-ratchets
```

### GDPR

```ts
await client.deleteMyData()   // Art. 17 — right to erasure
await client.exportMyData()   // Art. 20 — data portability
```

### `client.waitForUser(userId, timeoutMs?)` / `client.disconnect()`

```ts
const online = await client.waitForUser('bob', 15_000); // true / false
await client.disconnect();
```

## Supported data types

| Type | Example |
|------|---------|
| `string` | `'Hello'` |
| `number` | `42`, `3.14` |
| `boolean` | `true`, `false` |
| `null` | `null` |
| `Uint8Array` / `Buffer` | Binary files, images |
| `object` / `array` | `{ key: 'val' }`, `[1,2,3]` |
| `Date` | `new Date()` |
| `Set` | `new Set([1,2,3])` |
| `Map` | `new Map([['a',1]])` |

## Security properties

| Property | Implementation |
|---|---|
| Forward Secrecy | Double Ratchet — new key per message |
| Post-Compromise Security | DH ratchet rotation |
| Post-Quantum (optional) | ML-KEM-768 hybrid key exchange — `pqc: true` |
| Replay protection | Nonce + timestamp per message |
| TOFU | Identity binding, throws on key change |
| Zero-knowledge relay | Relay stores only ciphertext |
| Sealed sender (optional) | Hides sender from relay — `sealedSender: true` |
| Group E2EE | Sender Keys — O(1) encryption per message |
| GDPR | Right to erasure + data portability built in |

## Relay options

```ts
relayUrl: 'https://relay.stvor.xyz'  // hosted, no setup
```

```bash
npx @stvor/sdk mock-relay             # local dev, port 4444
```

```bash
git clone https://github.com/sapogeth/sdk-relay && node server.js  # self-hosted
```

## Docs

**[sdk.stvor.xyz](https://sdk.stvor.xyz/docs)**

## License

MIT
