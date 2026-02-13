---
title: STVOR SDK — Troubleshooting
description: Common errors and their solutions
---

# Troubleshooting

This guide covers the most common errors developers encounter when integrating
the STVOR SDK and how to fix them.

---

## Table of Contents

1. [ERR_PACKAGE_PATH_NOT_EXPORTED](#err_package_path_not_exported)
2. [Relay handshake timeout](#relay-handshake-timeout)
3. [Timed out waiting for user](#timed-out-waiting-for-user)
4. [INVALID_APP_TOKEN](#invalid_app_token)
5. [AUTH_FAILED](#auth_failed)
6. [RECIPIENT_NOT_FOUND](#recipient_not_found)
7. [DELIVERY_FAILED](#delivery_failed)
8. [QUOTA_EXCEEDED](#quota_exceeded)
9. [CommonJS vs ESM issues](#commonjs-vs-esm)
10. [Cannot find module 'ws'](#cannot-find-module-ws)

---

## ERR_PACKAGE_PATH_NOT_EXPORTED

```
Error [ERR_PACKAGE_PATH_NOT_EXPORTED]: Package subpath './dist/...' is not
defined by "exports" in .../node_modules/@stvor/sdk/package.json
```

### Cause

You are importing a sub-path of the SDK that is not listed in `exports`.
The package only exports its main entry point (`@stvor/sdk`).

### Solution

Import from the package root only:

```typescript
// ✅ Correct
import { Stvor } from '@stvor/sdk';

// ❌ Wrong — deep imports are not exported
import { Stvor } from '@stvor/sdk/dist/facade/app';
```

If you are using CommonJS (`require`), ensure your Node.js version is ≥ 18
and use the async loader pattern:

```javascript
// CommonJS usage (Node.js ≥ 18)
const sdk = require('@stvor/sdk');

async function main() {
  const { Stvor } = await sdk.load();
  const app = await Stvor.init({ appToken: 'stvor_dev_...' });
}
main();
```

Or switch to ESM (recommended):

```javascript
// ESM usage — just use import
import { Stvor } from '@stvor/sdk';
```

See [CommonJS vs ESM](#commonjs-vs-esm) for full details.

---

## Relay handshake timeout

```
StvorError [RELAY_UNAVAILABLE]: Relay handshake timeout
```

### Cause

The SDK could not establish a WebSocket connection to the relay server
within the configured timeout period.

### Common reasons

1. **Relay server is not running** — If using local development, start the
   mock relay first.
2. **Wrong relay URL** — Check the `relayUrl` parameter.
3. **Network/firewall issues** — The relay host may be blocked.
4. **Timeout too short** — For slow connections, increase the timeout.

### Solution

```typescript
// 1. Start the mock relay server (for local development)
//    Terminal: npx @stvor/sdk mock-relay
//    Or:      npm run mock-relay

// 2. Use the correct URL for local dev:
const app = await Stvor.init({
  appToken: 'stvor_dev_test123',
  relayUrl: 'ws://localhost:4444',   // mock relay default port
  timeout: 15000,                     // increase if needed
});

// 3. Verify the relay is reachable:
//    curl http://localhost:4444/health
```

### Using the Mock Relay

The SDK ships with a built-in mock relay server for local development:

```bash
# Start mock relay (default port 4444)
npx @stvor/sdk mock-relay

# Custom port
PORT=9000 npx @stvor/sdk mock-relay

# Verbose logging
STVOR_MOCK_VERBOSE=1 npx @stvor/sdk mock-relay
```

---

## Timed out waiting for user

```
StvorError [RECIPIENT_TIMEOUT]: Timed out waiting for user "bob@example.com"
after 10000ms
```

### Cause

The `send()` method waits for the recipient's public keys to appear on the
relay server. If the recipient hasn't connected in time, this error fires.

### Solution

```typescript
// Option 1: Increase the timeout
await alice.send('bob@example.com', 'Hello!', { timeout: 30000 });

// Option 2: Skip waiting (throws RECIPIENT_NOT_FOUND immediately)
await alice.send('bob@example.com', 'Hello!', { waitForRecipient: false });

// Option 3: Explicitly wait before sending
const available = await alice.waitForUser('bob@example.com', 60000);
if (available) {
  await alice.send('bob@example.com', 'Hello!');
} else {
  console.log('Bob is not online');
}

// Option 4: Listen for user availability (event-based)
alice.onUserAvailable((userId) => {
  console.log(`${userId} is now available`);
});
```

### Why this happens

Both sender and recipient must be connected to the relay at the same time
(or the recipient must have registered recently). The relay does not persist
keys indefinitely.

---

## INVALID_APP_TOKEN

```
StvorError [INVALID_APP_TOKEN]: Invalid AppToken format. AppToken must start
with "stvor_".
```

### Cause

The `appToken` value you provided does not follow the required format.

### Solution

```typescript
// ✅ Valid tokens start with "stvor_"
const app = await Stvor.init({
  appToken: 'stvor_dev_abc123',        // dev token
  // appToken: 'stvor_live_xyz789',    // production token
});

// ❌ Invalid
const app = await Stvor.init({
  appToken: 'sk_live_abc123',          // wrong prefix
});
```

For local development, you can use any string starting with `stvor_dev_` or
`stvor_local_`. The mock relay accepts all `stvor_*` tokens.

---

## AUTH_FAILED

```
StvorError [AUTH_FAILED]: The AppToken is invalid or has been revoked.
```

### Cause

The relay server rejected your AppToken. This happens in production when:
- The token was revoked from the dashboard
- The token has expired
- The token belongs to a different environment

### Solution

1. Log in to the [STVOR Dashboard](https://dashboard.stvor.io)
2. Check your AppToken status
3. Regenerate a new token if needed
4. Update your environment variable: `STVOR_APP_TOKEN=stvor_live_newtoken...`

---

## RECIPIENT_NOT_FOUND

```
StvorError [RECIPIENT_NOT_FOUND]: User "bob@example.com" not found.
```

### Cause

The recipient's public keys are not available on the relay. They have not
called `app.connect()` yet, or they disconnected.

### Solution

Make sure the recipient connects before the sender tries to send:

```typescript
// Recipient side
const bob = await app.connect('bob@example.com');
// Bob is now registered on the relay — alice can send to bob

// Sender side — use waitForRecipient (enabled by default)
await alice.send('bob@example.com', 'Hello!');
```

---

## DELIVERY_FAILED

```
StvorError [DELIVERY_FAILED]: Failed to deliver message to bob@example.com.
```

### Cause

The relay accepted the message but could not deliver it. Reasons:
- Relay internal error
- Message too large
- Recipient disconnected mid-delivery

### Solution

This error is **retryable**. Simply retry the send:

```typescript
try {
  await alice.send('bob@example.com', 'Hello!');
} catch (err) {
  if (err instanceof StvorError && err.retryable) {
    // Wait and retry
    await new Promise(r => setTimeout(r, 2000));
    await alice.send('bob@example.com', 'Hello!');
  }
}
```

---

## QUOTA_EXCEEDED

```
StvorError [QUOTA_EXCEEDED]: Message quota exceeded for this AppToken.
```

### Cause

Your AppToken has exceeded its monthly message limit.

### Solution

1. Check your usage on the dashboard
2. Upgrade your plan for higher limits
3. For local development, use `stvor_dev_*` or `stvor_local_*` tokens —
   these skip quota checks

---

## CommonJS vs ESM

The STVOR SDK is published as an **ES Module** (`"type": "module"`).
Starting from v2.4.0, it also ships CommonJS wrappers for compatibility.

### ESM (Recommended)

```json
// package.json
{
  "type": "module"
}
```

```typescript
// app.ts or app.mjs
import { Stvor } from '@stvor/sdk';

const app = await Stvor.init({ appToken: 'stvor_dev_...' });
```

### CommonJS

```json
// package.json
{
  "type": "commonjs"
  // or omit "type" entirely
}
```

```javascript
// app.js or app.cjs
const sdk = require('@stvor/sdk');

async function main() {
  const { Stvor } = await sdk.load();
  const app = await Stvor.init({ appToken: 'stvor_dev_...' });
  const alice = await app.connect('alice@example.com');
  await alice.send('bob@example.com', 'Hello from CJS!');
}

main().catch(console.error);
```

### TypeScript

```json
// tsconfig.json
{
  "compilerOptions": {
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "esModuleInterop": true
  }
}
```

```typescript
import { Stvor } from '@stvor/sdk';
```

### Common mistakes

| Problem | Solution |
|---------|----------|
| `Cannot use import` in `.js` file | Add `"type": "module"` to package.json or rename to `.mjs` |
| `require is not defined` | You're in ESM context — use `import` instead |
| `ERR_PACKAGE_PATH_NOT_EXPORTED` | Import from `'@stvor/sdk'`, not from sub-paths |
| `ERR_REQUIRE_ESM` | Use `await sdk.load()` instead of direct destructuring |

---

## Cannot find module 'ws'

```
Error: Cannot find module 'ws'
```

### Cause

The `ws` package (WebSocket for Node.js) is a dependency of the SDK but
was not installed.

### Solution

```bash
npm install ws
# or
pnpm add ws
```

The SDK declares `ws` as a dependency, so it should be installed automatically.
If you see this error, try:

```bash
rm -rf node_modules package-lock.json
npm install
```

---

## Still stuck?

1. **Enable verbose logging** — Set `STVOR_MOCK_VERBOSE=1` when running the
   mock relay
2. **Check the relay health** — `curl http://localhost:4444/health`
3. **Try the demo** — Run `packages/sdk/demo/run-demo.sh` for a working
   end-to-end example
4. **File an issue** — https://github.com/sapogeth/stvor_sdk/issues
