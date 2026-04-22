# @stvor/sdk API Reference

Complete SDK documentation.

---

## Installation

```bash
npm install @stvor/sdk
```

### Environment

- **Node.js**: 20+ (uses `node:crypto`)
- **Browsers**: Modern (uses Web Crypto API)
- **Dependencies**: 0 (zero npm dependencies)

---

## Quick Start

### Node.js

```ts
import { Stvor } from '@stvor/sdk';

const client = await Stvor.connect({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

client.onMessage(msg => {
  console.log(`${msg.from}: ${msg.data}`);
});

await client.send('bob', 'Hello');
await client.disconnect();
```

### Browser (ES Modules)

```ts
import { StvorWebSDK } from '@stvor/sdk/web';

const sdk = await StvorWebSDK.create({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});

sdk.onMessage((from, data) => console.log(from, data));
await sdk.send('bob', { text: 'Hi!' });
sdk.disconnect();
```

### Browser (CommonJS / HTML)

```html
<script src="https://cdn.jsdelivr.net/npm/@stvor/sdk/dist/web.js"></script>
<script>
  const sdk = await StvorWebSDK.create({...});
  await sdk.send('bob', 'Hello');
</script>
```

---

## API: `Stvor` (Node.js)

### `Stvor.connect(config)`

Create a new encrypted client connection.

**Parameters**:

```ts
interface ConnectConfig {
  userId: string;              // Unique user identifier
  appToken: string;            // Bearer token (stvor_xxx)
  relayUrl: string;            // Relay server URL
  timeout?: number;            // Request timeout (ms), default: 10_000
  pollIntervalMs?: number;     // Message poll interval (ms), default: 1_000
}
```

**Returns**: `Promise<Stvor>`

**Example**:

```ts
const alice = await Stvor.connect({
  userId: 'alice',
  appToken: process.env.APP_TOKEN,
  relayUrl: 'http://localhost:3002',
  timeout: 30_000,
  pollIntervalMs: 500,  // Poll faster
});
```

**Throws**:
- `StvorError` with code `ERR_INVALID_TOKEN` if appToken invalid
- `StvorError` with code `ERR_NETWORK` if relay unreachable

**Side Effects**:
- Generates identity key pair (if first time)
- Persists keys locally (IndexedDB/disk)
- Registers user on relay
- Starts polling for messages

---

### `client.send(recipientId, data, options?)`

Send encrypted message to another user.

**Parameters**:

```ts
send(
  recipientId: string,
  data: any,                   // Any JS type
  options?: {
    timeout?: number;          // Request timeout (ms)
  }
): Promise<void>
```

**Data Types**:

Transparently supports any JavaScript type:

```ts
// Primitives
await client.send('bob', 'Hello');           // string
await client.send('bob', 42);                // number
await client.send('bob', true);              // boolean
await client.send('bob', null);              // null
await client.send('bob', undefined);         // undefined

// Complex types
await client.send('bob', { name: 'Alice' });         // object
await client.send('bob', [1, 2, 3]);                // array
await client.send('bob', new Date());               // Date
await client.send('bob', new Set([1, 2, 3]));       // Set
await client.send('bob', new Map([['a', 1]]));      // Map
await client.send('bob', Buffer.from('bin'));       // Buffer
await client.send('bob', new Uint8Array([1, 2]));   // Uint8Array

// Even custom classes (with caveat)
class Transaction {
  constructor(public id: string, public amount: number) {}
}
await client.send('bob', new Transaction('tx1', 100));
```

**Returns**: `Promise<void>` (resolves when relay ACKs)

**Throws**:
- `StvorError` with code `ERR_NOT_CONNECTED` if client disconnected
- `StvorError` with code `ERR_RECIPIENT_NOT_FOUND` if recipient not registered
- `StvorError` with code `ERR_TIMEOUT` if relay doesn't respond in time
- `StvorError` with code `ERR_RATE_LIMITED` if rate limited (100 req/min per IP)

**Example**:

```ts
try {
  await client.send('bob', { amount: 100, currency: 'USD' });
  console.log('Message sent');
} catch (err) {
  if (err.code === 'ERR_RATE_LIMITED') {
    console.log('Too many requests, wait before retry');
  }
}
```

---

### `client.onMessage(handler)`

Subscribe to incoming encrypted messages.

**Parameters**:

```ts
interface IncomingMessage {
  from: string;          // Sender userId
  data: any;             // Decrypted data (original type preserved)
  timestamp: Date;       // When message was sent
  id: string;            // Message ID
}

onMessage(
  handler: (msg: IncomingMessage) => void | Promise<void>
): () => void  // Unsubscribe function
```

**Returns**: Unsubscribe function (removes listener)

**Example**:

```ts
// Single listener
const unsubscribe = client.onMessage(msg => {
  console.log(`${msg.from}: ${msg.data}`);
  console.log(`Sent at: ${msg.timestamp}`);
});

// Multiple listeners (all fire)
client.onMessage(msg => sendToUI(msg));
client.onMessage(msg => logToDatabase(msg));

// Async handlers
client.onMessage(async msg => {
  await processMessage(msg);
});

// Unsubscribe
unsubscribe();
```

---

### `client.disconnect()`

Close the connection and stop polling.

**Parameters**: None

**Returns**: `Promise<void>`

**Example**:

```ts
await client.disconnect();
// No more messages will be received
```

---

### `client.connected`

Check if client is currently connected.

**Type**: `boolean` (readonly)

**Example**:

```ts
if (client.connected) {
  await client.send('bob', 'Hi');
} else {
  console.log('Not connected');
}
```

---

### `client.userId`

Get the user's ID.

**Type**: `string` (readonly)

**Example**:

```ts
console.log(`Logged in as: ${client.userId}`);
```

---

## API: `StvorWebSDK` (Browser)

Similar to Node.js API with small differences.

### `StvorWebSDK.create(config)`

Browser equivalent of `Stvor.connect()`.

```ts
const sdk = await StvorWebSDK.create({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://relay.stvor.xyz',
});
```

### `sdk.send(recipientId, data, options?)`

Identical to Node.js version.

### `sdk.onMessage(handler)`

Identical to Node.js version.

### `sdk.disconnect()`

Identical to Node.js version.

### Key Persistence

Browser version automatically persists keys in **IndexedDB**:

```
Database: 'stvor'
Store: 'keys'
Key: '{userId}'
Value: {
  identityKey: { publicKey, privateKey },
  prekey: { publicKey, privateKey },
}
```

**Behavior**:
- Keys survive page refreshes
- Keys survive browser restarts
- Clearing IndexedDB = reset keys
- Different origin = separate key storage

---

## React Hooks

### `useStvor(config)`

React hook for encrypted messaging.

**Parameters**:

```ts
interface UseStvorConfig {
  userId: string;
  appToken: string;
  relayUrl?: string;  // Default: current origin
}
```

**Returns**:

```ts
interface UseStvorReturn {
  connected: boolean;
  messages: IncomingMessage[];
  send: (recipientId: string, data: any) => Promise<void>;
  error: Error | null;
  disconnect: () => void;
}
```

**Example**:

```tsx
import { useStvor } from '@stvor/sdk/react';

export function ChatWindow() {
  const { connected, messages, send, error } = useStvor({
    userId: 'alice',
    appToken: 'stvor_live_xxx',
  });

  return (
    <div>
      {error && <div style={{color: 'red'}}>Error: {error.message}</div>}
      <div>
        {messages.map(m => (
          <div key={m.id}>
            <strong>{m.from}:</strong> {String(m.data)}
          </div>
        ))}
      </div>
      <button 
        onClick={() => send('bob', 'Hello')}
        disabled={!connected}
      >
        Send
      </button>
    </div>
  );
}
```

### `useStvorMessage(recipientId)`

Subscribe to messages from specific user.

**Parameters**:

```ts
useStvorMessage(recipientId: string): IncomingMessage[]
```

**Returns**: Array of messages from that user

**Example**:

```tsx
export function ChatWith({ userId }: { userId: string }) {
  const messages = useStvorMessage(userId);
  
  return (
    <div>
      {messages.map(m => <p key={m.id}>{m.data}</p>)}
    </div>
  );
}
```

---

## Vue 3 Composables

### `useStvor(config)`

Vue composition API equivalent.

**Parameters**:

```ts
interface UseStvorConfig {
  userId: string;
  appToken: string;
  relayUrl?: string;
}
```

**Returns**:

```ts
{
  connected: Ref<boolean>,
  messages: Ref<IncomingMessage[]>,
  send: (recipientId: string, data: any) => Promise<void>,
  error: Ref<Error | null>,
  disconnect: () => void,
}
```

**Example**:

```vue
<template>
  <div>
    <div v-for="m in messages" :key="m.id">
      <strong>{{ m.from }}:</strong> {{ m.data }}
    </div>
    <button @click="send('bob', 'Hello')" :disabled="!connected">
      Send
    </button>
  </div>
</template>

<script setup>
import { useStvor } from '@stvor/sdk/vue';

const { connected, messages, send } = useStvor({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
});
</script>
```

---

## Error Handling

All errors are instances of `StvorError`.

```ts
interface StvorError extends Error {
  code: string;          // Error code
  message: string;       // Human-readable message
  statusCode?: number;   // HTTP status if applicable
  cause?: Error;         // Original error
}
```

**Common Error Codes**:

| Code | Meaning | Recovery |
|------|---------|----------|
| `ERR_INVALID_TOKEN` | Token invalid/expired | Get new token |
| `ERR_NOT_CONNECTED` | Client disconnected | Call `.connect()` |
| `ERR_RECIPIENT_NOT_FOUND` | Recipient not registered | Recipient must connect first |
| `ERR_TIMEOUT` | Request timed out | Retry with longer timeout |
| `ERR_RATE_LIMITED` | Too many requests (100/min) | Wait and retry |
| `ERR_NETWORK` | Network unreachable | Check internet/relay URL |
| `ERR_DECRYPT_FAILED` | Message decryption failed | Message corrupted? |
| `ERR_SIGNATURE_INVALID` | Message signature invalid | Possible tampering |
| `ERR_REPLAY_DETECTED` | Message is a replay | Duplicate, ignored |

**Example**:

```ts
try {
  await client.send('bob', 'Hello');
} catch (err) {
  if (err instanceof StvorError) {
    console.log(`Error: ${err.code} - ${err.message}`);
    
    switch (err.code) {
      case 'ERR_RATE_LIMITED':
        // Exponential backoff
        await sleep(1000 * Math.pow(2, retryCount));
        break;
      case 'ERR_RECIPIENT_NOT_FOUND':
        // Retry in 5 seconds
        setTimeout(() => client.send('bob', 'Hello'), 5000);
        break;
      default:
        console.error(err);
    }
  }
}
```

---

## Advanced Usage

### Custom Relay URL

```ts
const client = await Stvor.connect({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  relayUrl: 'https://custom-relay.example.com',  // Override
});
```

### Polling Rate

```ts
const client = await Stvor.connect({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  pollIntervalMs: 500,  // Poll every 500ms (default 1000)
});
```

### Request Timeout

```ts
const client = await Stvor.connect({
  userId: 'alice',
  appToken: 'stvor_live_xxx',
  timeout: 30_000,  // 30 second timeout
});
```

### Ratchet API (Low-level)

For advanced cryptography use cases:

```ts
import * as Ratchet from '@stvor/sdk/ratchet';

// Manual X3DH
const aliceKeys = await Ratchet.X3DH.generateKeyPair();
const bobKeys = await Ratchet.X3DH.generateKeyPair();
const sharedSecret = await Ratchet.X3DH.derive(
  aliceKeys,
  bobKeys.publicKey
);

// Manual Double Ratchet
const session = new Ratchet.RatchetSession({
  rootKey: sharedSecret,
  sendChainKey: Buffer.alloc(32),
  recvChainKey: Buffer.alloc(32),
});

const { messageKey } = session.advanceSend();
const encrypted = await Ratchet.encryptMessage(msg, messageKey);
```

### CLI Tool

```bash
# Install
npm install -g @stvor/sdk

# Create project (dev server)
stvor bootstrap

# Debug messaging
stvor debug --relay http://localhost:3002 --user alice

# Export keys
stvor export-keys > keys.json
```

---

## Examples

### Simple Two-User Chat

See `examples/web-chat-react.tsx`

```tsx
import { useStvor } from '@stvor/sdk/react';

export function TwoUserChat() {
  const { messages, send } = useStvor({
    userId: 'alice',
    appToken: 'stvor_live_xxx',
  });

  return (
    <div>
      {messages.map(m => (
        <div key={m.id}>
          {m.from}: {m.data}
        </div>
      ))}
      <input 
        onKeyPress={e => {
          if (e.key === 'Enter') {
            send('bob', e.currentTarget.value);
            e.currentTarget.value = '';
          }
        }}
        placeholder="Message..."
      />
    </div>
  );
}
```

### Group Chat (Multi-recipient)

```ts
async function sendToGroup(client, group, message) {
  await Promise.all(
    group.map(userId => client.send(userId, message))
  );
}

// Usage
const group = ['alice', 'bob', 'charlie'];
await sendToGroup(client, group, 'Hello everyone!');
```

### Message Batching

```ts
const messages = [];

function scheduleMessage(data) {
  messages.push(data);
  if (messages.length >= 10) {
    flushMessages();
  }
}

async function flushMessages() {
  await client.send('bob', { batch: messages });
  messages.length = 0;
}

setInterval(flushMessages, 1000);  // Flush every 1 second
```

### Error Handling with Retry

```ts
async function sendWithRetry(
  client,
  recipientId,
  data,
  maxRetries = 3
) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await client.send(recipientId, data);
      return;
    } catch (err) {
      if (i === maxRetries - 1) throw err;
      
      const delay = 1000 * Math.pow(2, i);  // Exponential backoff
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}
```

### Persistence (Node.js)

```ts
import * as fs from 'fs';
import { Stvor } from '@stvor/sdk';

interface StoredClient {
  userId: string;
  appToken: string;
}

async function loadOrCreateClient(filePath: string) {
  if (fs.existsSync(filePath)) {
    const { userId, appToken } = JSON.parse(
      fs.readFileSync(filePath, 'utf-8')
    );
    return Stvor.connect({ userId, appToken, relayUrl: 'http://localhost:3002' });
  }

  const client = await Stvor.connect({
    userId: `user_${Date.now()}`,
    appToken: process.env.APP_TOKEN,
    relayUrl: 'http://localhost:3002',
  });

  fs.writeFileSync(filePath, JSON.stringify({
    userId: client.userId,
    appToken: process.env.APP_TOKEN,
  }));

  return client;
}

const client = await loadOrCreateClient('.stvor-client.json');
```

---

## Performance Tips

1. **Polling Rate**: Default 1000ms is good. Increase if you don't need real-time.
2. **Message Batching**: Send related data in one message instead of many.
3. **Key Caching**: First connect (X3DH) takes ~10ms. Reuse client for multiple sends.
4. **Compression**: Large payloads? Compress before sending.

```ts
import { compress, decompress } from 'brotli';

const large = JSON.stringify(hugeObject);
const compressed = compress(large);
await client.send('bob', { type: 'compressed', data: compressed });
```

---

## FAQ

**Q: Can I send binary data?**

A: Yes! Send `Buffer` or `Uint8Array`.

```ts
await client.send('bob', Buffer.from('binary data'));
```

**Q: Can messages be ordered?**

A: Generally yes, due to polling sequential nature. But out-of-order delivery is theoretically possible.

**Q: What's the message size limit?**

A: ~10MB (limited by relay server config). Practical limit ~1MB for mobile.

**Q: Can users have multiple sessions?**

A: Yes. Each `Stvor.connect()` creates independent session. Same user can connect from different devices.

**Q: Are message read receipts supported?**

A: Not yet. Send explicit acknowledgment: `await client.send(sender, { ack: true })`.

**Q: Can I access raw cryptographic keys?**

A: Advanced: use `sdk/ratchet` API for lower-level access.

**Q: What happens if I lose internet?**

A: Messages fail with `ERR_NETWORK`. Retry automatically or manually.

**Q: How long are messages stored on relay?**

A: 10 minutes TTL. After that, auto-deleted.

---

## License

MIT
