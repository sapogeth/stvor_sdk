/**
 * STVOR SDK — TypeScript Example
 *
 * Prerequisites:
 *   1. npm install @stvor/sdk
 *   2. Start mock relay: npx @stvor/sdk mock-relay
 *   3. Compile & run:    npx tsx examples/typescript-example.ts
 *
 * tsconfig.json should have:
 *   {
 *     "compilerOptions": {
 *       "module": "NodeNext",
 *       "moduleResolution": "NodeNext",
 *       "esModuleInterop": true,
 *       "target": "ES2020"
 *     }
 *   }
 */

import { Stvor, StvorError, StvorFacadeClient } from '@stvor/sdk';
import type { DecryptedMessage, StvorAppConfig } from '@stvor/sdk';

const config: StvorAppConfig = {
  appToken: process.env.STVOR_APP_TOKEN || 'stvor_dev_ts_example',
  relayUrl: process.env.RELAY_URL || 'ws://localhost:4444',
  timeout: 10_000,
};

async function main(): Promise<void> {
  // Initialize
  const app = await Stvor.init(config);

  // Connect two users
  const alice: StvorFacadeClient = await app.connect('alice@example.com');
  const bob: StvorFacadeClient = await app.connect('bob@example.com');

  // Type-safe message handler
  bob.onMessage((from: string, msg: string | Uint8Array) => {
    console.log(`Bob received from ${from}:`, msg);
  });

  // Send with full type support
  await alice.send('bob@example.com', 'Hello from TypeScript!');

  // Send with options
  await alice.send('bob@example.com', 'With timeout', {
    timeout: 5000,
    waitForRecipient: true,
  });

  // Error handling with type narrowing
  try {
    await alice.send('unknown@example.com', 'test', {
      waitForRecipient: false,
    });
  } catch (error: unknown) {
    if (error instanceof StvorError) {
      // Full IntelliSense for StvorError properties
      const { code, message, action, retryable } = error;
      console.log(`Error [${code}]: ${message}`);
      console.log(`Action: ${action}, Retryable: ${retryable}`);
    }
  }

  await app.disconnect();
}

main().catch(console.error);
