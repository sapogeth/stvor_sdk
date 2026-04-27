# @stvor/sdk

**End-to-end encryption for any app.** Drop-in library — no cryptography expertise required.

Stvor SDK implements the **Signal Protocol** (X3DH + Double Ratchet) and optionally **ML-KEM-768** (post-quantum, NIST FIPS 203) using only Node.js built-in APIs — zero external dependencies.

---

## Why Stvor?

Most E2EE libraries ask you to understand key exchange, ratchets, and nonces. Stvor gives you a three-line API and handles all of it:

- **`Stvor.connect()`** — generates identity keys, registers with relay, starts polling
- **`client.send()`** — X3DH session + Double Ratchet, type-preserving serialization
- **`client.onMessage()`** — decrypted messages delivered to your handler

---

## Install

```bash
npm install @stvor/sdk
```

**Requirements:** Node.js ≥ 18 or any modern browser. Zero npm dependencies.

---

## Quickstart

### 1-to-1 messaging (Node.js)

```ts
import { Stvor } from '@stvor/sdk';

const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_live_xxx',   // any token starting with stvor_
  relayUrl: 'https://relay.stvor.xyz',
});

const bob = await Stvor.connect({
  userId:   'bob',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

bob.onMessage(msg => {
  console.log(`From ${msg.from}:`, msg.data);
  // From alice: { text: 'Hello!' }
});

// Sends any JavaScript value — type preserved on arrival
await alice.send('bob', { text: 'Hello!' });

await alice.disconnect();
await bob.disconnect();
```

### Browser

```ts
import { StvorWebSDK } from '@stvor/sdk/web';

const alice = await StvorWebSDK.create({
  userId:   'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

alice.onMessage((from, data) => console.log(from, data));
await alice.send('bob', { text: 'Hello from browser!' });
alice.disconnect();
```

Identity keys are persisted in IndexedDB — survive page refreshes automatically.

### Local development (no account needed)

```bash
npx @stvor/sdk mock-relay   # starts relay on port 4444
```

```ts
const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_dev_test123',
  relayUrl: 'http://localhost:4444',
});
```

---

## Group chats (Sender Keys)

```ts
// Create an encrypted group
await alice.createGroup('team-chat', ['bob', 'charlie']);

// Send to everyone — one encryption, all members receive
await alice.sendToGroup('team-chat', { text: 'Hello team!' });

// Receive group messages
bob.onGroupMessage(msg => {
  console.log(msg.groupId, msg.from, msg.data);
});

// Manage members
await alice.addGroupMember('team-chat', 'dave');
await alice.removeGroupMember('team-chat', 'charlie');
// Removing a member automatically ratchets the sender key —
// the removed member cannot decrypt any future messages
```

---

## Post-quantum encryption (ML-KEM-768)

```ts
const alice = await Stvor.connect({
  userId:   'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
  pqc:      true,   // enables ML-KEM-768 hybrid key exchange
});
```

When `pqc: true`:

1. An ML-KEM-768 key pair is generated on connect (encapsulation key: 1184 bytes)
2. On first message, the sender encapsulates a secret to the recipient's ML-KEM key
3. The recipient decapsulates to recover the same secret
4. Both sides compute: `root_key = HKDF(X3DH_secret ‖ ML-KEM_secret)`
5. All Double Ratchet messages use this hybrid root key

**Verified against NIST ACVTS official test vectors** — KeyGen, Encap, and Decap all pass.

Falls back to classical X3DH if the peer doesn't support PQC — no error, no incompatibility.

---

## Sealed sender (metadata protection)

```ts
const alice = await Stvor.connect({
  userId:       'alice',
  appToken:     'stvor_live_xxx',
  relayUrl:     'https://relay.stvor.xyz',
  sealedSender: true,
});
```

Without sealed sender, the relay sees `{ to: "bob", from: "alice", ciphertext: "..." }`.

With sealed sender, the relay sees `{ to: "bob", ciphertext: "<opaque envelope>" }` — the sender identity is hidden inside the envelope using ephemeral ECDH + AES-256-GCM. A fresh ephemeral key pair is generated per message — no linkability.

---

## GDPR compliance

```ts
// Art. 17 — right to erasure
// Deletes public keys, queued messages, and registration from the relay
await alice.deleteMyData();

// Art. 20 — data portability
// Returns what the relay stores about this user (metadata only — no plaintext)
const data = await alice.exportMyData();
```

---

## Full API reference

### `Stvor.connect(config)`

```ts
const client = await Stvor.connect({
  userId:          string,   // any unique identifier — email, UUID, username
  appToken:        string,   // must start with 'stvor_'
  relayUrl:        string,   // 'https://relay.stvor.xyz' or self-hosted
  timeout?:        number,   // request timeout ms — default: 10 000
  pollIntervalMs?: number,   // message polling interval — default: 1 000
  sealedSender?:   boolean,  // hide sender from relay — default: false
  pqc?:            boolean,  // ML-KEM-768 hybrid key exchange — default: false
});
```

### `client.send(recipientId, data, options?)`

```ts
await client.send('bob', 'Hello');
await client.send('bob', { amount: 100, currency: 'USD' });
await client.send('bob', Buffer.from([1, 2, 3]));
await client.send('bob', new Date());
await client.send('bob', new Map([['key', 'val']]));

// Options
await client.send('bob', data, { timeout: 30_000 });           // wait up to 30s
await client.send('bob', data, { waitForRecipient: false });   // fail immediately
```

### `client.onMessage(handler)`

```ts
const unsubscribe = client.onMessage(msg => {
  // msg.from      — sender userId
  // msg.data      — original type preserved (string, object, Date, Map, ...)
  // msg.timestamp — Date
  // msg.id        — unique message id
});

unsubscribe(); // stop listening
```

### Group API

```ts
await client.createGroup(groupId, memberIds)
await client.sendToGroup(groupId, data)
const stop = client.onGroupMessage(msg => {
  // msg.groupId, msg.from, msg.data, msg.timestamp, msg.id
})
await client.addGroupMember(groupId, memberId)
await client.removeGroupMember(groupId, memberId)  // auto-ratchets sender key
```

### Other

```ts
const online = await client.waitForUser('bob', 15_000)   // true / false
await client.disconnect()
client.getUserId()
await client.deleteMyData()
const data = await client.exportMyData()
```

---

## Supported data types

| Type | Example |
|------|---------|
| `string` | `'Hello'` |
| `number` | `42`, `3.14` |
| `boolean` | `true`, `false` |
| `null` | `null` |
| `Uint8Array` / `Buffer` | Binary files, images |
| `object` / `array` | `{ key: 'val' }`, `[1, 2, 3]` |
| `Date` | `new Date()` |
| `Set` | `new Set([1, 2, 3])` |
| `Map` | `new Map([['a', 1]])` |

---

## Security properties

| Property | Detail |
|---|---|
| **Forward Secrecy** | Double Ratchet — new key every message; past messages safe even if current key leaks |
| **Post-Compromise Security** | DH ratchet rotation; future messages safe after key compromise |
| **Post-Quantum (optional)** | ML-KEM-768 hybrid — NIST FIPS 203, verified against official test vectors |
| **Replay protection** | Nonce + timestamp validation per message |
| **TOFU** | SHA-256 fingerprint binding on first contact; throws on key change |
| **Zero-knowledge relay** | Relay stores only ciphertext — never sees plaintext or keys |
| **Sealed sender (optional)** | Hides sender identity from relay — ephemeral ECDH + AES-256-GCM per message |
| **Group E2EE** | Sender Keys — O(1) encryption regardless of group size |
| **One-time prekeys** | Full X3DH with OPK pool — forward secrecy before first Double Ratchet step |
| **GDPR built-in** | Right to erasure (Art. 17) + data portability (Art. 20) |

---

## Cryptography

All cryptographic operations use **Node.js built-in `node:crypto`** (zero external dependencies):

| Primitive | Use |
|---|---|
| **ECDH P-256** | X3DH key agreement |
| **ECDSA P-256** | Signed prekey verification |
| **AES-256-GCM** | AEAD encryption (header as AAD) |
| **HKDF-SHA-256** | Key derivation |
| **HMAC-SHA-256** | Chain key ratcheting |
| **SHA3-512** | X3DH key generation (G function) |
| **SHAKE-128** | ML-KEM matrix generation (SampleNTT) |
| **SHAKE-256** | ML-KEM noise sampling (PRF) |
| **SHA-256** | TOFU fingerprinting, GDPR hashing |
| **ML-KEM-768** | Post-quantum KEM (NIST FIPS 203, implemented from scratch) |

---

## Relay options

### Hosted (recommended)

```ts
relayUrl: 'https://relay.stvor.xyz'
```

No account, no setup. Accepts any `stvor_*` token.

### Local development

```bash
npx @stvor/sdk mock-relay          # port 4444
PORT=9000 npx @stvor/sdk mock-relay
```

### Self-hosted

```bash
git clone https://github.com/sapogeth/sdk-relay
node server.js
```

---

## Docs

Full documentation: **[sdk.stvor.xyz](https://sdk.stvor.xyz/docs)**

## License

MIT
