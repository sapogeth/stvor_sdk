# @stvor/sdk

End-to-end encryption for any app. Drop-in library — no cryptography knowledge required.

Uses **X3DH + Double Ratchet** (Signal Protocol) with AES-256-GCM, ECDSA P-256, and HKDF-SHA-256. Node.js uses `node:crypto` (zero native deps). Browser uses Web Crypto API (zero dependencies at all).

## Install

```bash
npm install @stvor/sdk
```

## Quickstart

### Node.js — 1-to-1

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

bob.onMessage(msg => {
  console.log(`From ${msg.from}:`, msg.data);
});

await alice.send('bob', { text: 'Hello!' });

await alice.disconnect();
await bob.disconnect();
```

### Group chats

```ts
// Alice creates a group and invites members
await alice.createGroup('team-chat', ['bob', 'charlie']);

// Send to the group — one encryption, all members receive
await alice.sendToGroup('team-chat', { text: 'Hello team!' });

// Receive group messages
bob.onGroupMessage(msg => {
  console.log(msg.groupId, msg.from, msg.data);
});

// Manage members (auto-ratchets sender key on removal)
await alice.addGroupMember('team-chat', 'dave');
await alice.removeGroupMember('team-chat', 'charlie');
```

### Sealed sender (metadata protection)

```ts
// Relay sees `to` but never `from` — sender identity is hidden
const alice = await Stvor.connect({
  userId:       'alice',
  appToken:     'stvor_live_xxx',
  relayUrl:     'https://relay.stvor.xyz',
  sealedSender: true,
});
```

### Local development

```bash
# Start local relay — no account needed
npx @stvor/sdk mock-relay
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
sdk.disconnect();
```

Keys are persisted in IndexedDB — identity survives page refreshes.

## How it works

1. Each user generates an identity key pair (ECDH P-256) on first connect.
2. Session is established via **X3DH** — both sides derive the same shared secret without a central server.
3. Every message advances the **Double Ratchet** — compromise of one key doesn't expose past or future messages.
4. The relay server only ever sees ciphertext.

## Supported data types

Send any JavaScript value — the original type is preserved on the receiving end:

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

## API — `Stvor` (Node.js)

### `Stvor.connect(config)`

```ts
const client = await Stvor.connect({
  userId:          string,   // any unique identifier
  appToken:        string,   // starts with 'stvor_'
  relayUrl:        string,   // e.g. 'https://relay.stvor.xyz'
  timeout?:        number,   // ms, default: 10 000
  pollIntervalMs?: number,   // message polling interval, default: 1 000
  sealedSender?:   boolean,  // hide sender from relay, default: false
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
  // msg.id        — unique string
});

unsubscribe(); // stop listening
```

### `client.createGroup(groupId, memberIds)`

```ts
await client.createGroup('room-1', ['bob', 'charlie']);
```

### `client.sendToGroup(groupId, data)`

```ts
await client.sendToGroup('room-1', { text: 'Hello group!' });
```

### `client.onGroupMessage(handler)`

```ts
const unsubscribe = client.onGroupMessage(msg => {
  // msg.groupId   — group identifier
  // msg.from      — sender userId
  // msg.data      — decrypted value
  // msg.timestamp — Date
  // msg.id        — unique string
});
```

### `client.addGroupMember(groupId, memberId)`

```ts
await client.addGroupMember('room-1', 'dave');
```

### `client.removeGroupMember(groupId, memberId)`

```ts
// Automatically ratchets sender key — removed member cannot decrypt future messages
await client.removeGroupMember('room-1', 'charlie');
```

### `client.waitForUser(userId, timeoutMs?)`

```ts
const online = await client.waitForUser('bob', 15_000);
// true = registered, false = timeout
```

### `client.deleteMyData()`

```ts
// GDPR Art. 17 — erases all relay-side data for this user
await client.deleteMyData();
```

### `client.exportMyData()`

```ts
// GDPR Art. 20 — returns what the relay stores about this user
const data = await client.exportMyData();
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
sdk.onMessage((from, data) => { /* ... */ });
await sdk.waitForUser(userId, timeoutMs?);
sdk.disconnect();
sdk.getUserId();
```

## TOFU (Trust On First Use)

On first contact with a peer, the SDK stores their identity key fingerprint. If the fingerprint changes on a later contact, the SDK throws — protecting against MITM attacks. Works automatically.

## Security properties

| Property | Implementation |
|---|---|
| Forward Secrecy | Double Ratchet — new key per message |
| Post-Compromise Security | DH ratchet rotation every message |
| Replay protection | Nonce + timestamp per message |
| TOFU | Identity binding on first contact |
| Zero-knowledge relay | Server only stores ciphertext |
| Sealed sender | Optional — hides sender from relay (ephemeral ECDH) |
| Simultaneous send | Both sides can send before receiving |
| Group E2EE | Sender Keys — one encryption per message regardless of group size |
| GDPR compliance | Right to erasure + data portability built in |

## Relay options

### Hosted relay (recommended)

```ts
relayUrl: 'https://relay.stvor.xyz'
```

No setup needed. Accepts any `stvor_*` token.

### Local relay (development)

```bash
npx @stvor/sdk mock-relay          # port 4444
PORT=9000 npx @stvor/sdk mock-relay
```

### Self-hosted relay

```bash
git clone https://github.com/sapogeth/sdk-relay
cd sdk-relay
node server.js
```

Set `PORT` and `STVOR_VERBOSE=1` as needed.

## Docs

Full documentation: **[sdk.stvor.xyz](https://sdk.stvor.xyz/docs)**

## License

MIT
