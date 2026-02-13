#!/usr/bin/env node
/**
 * STVOR SDK — ESM Example (ECMAScript Modules)
 *
 * This example works with:
 *   - package.json containing "type": "module"
 *   - .mjs files (regardless of package.json type)
 *   - TypeScript with "module": "NodeNext"
 *
 * Prerequisites:
 *   1. npm install @stvor/sdk
 *   2. Start mock relay: npx @stvor/sdk mock-relay
 *   3. Run this file:    node examples/esm-example.mjs
 */

import { Stvor, StvorError } from '@stvor/sdk';

const RELAY_URL = process.env.RELAY_URL || 'ws://localhost:4444';
const APP_TOKEN = process.env.STVOR_APP_TOKEN || 'stvor_dev_example123';

async function main() {
  console.log('=== STVOR SDK — ESM Example ===\n');

  // ── 1. Initialize SDK ──────────────────────────────────────────
  console.log('1. Initializing SDK...');
  const app = await Stvor.init({
    appToken: APP_TOKEN,
    relayUrl: RELAY_URL,
    timeout: 10000,
  });
  console.log('   ✓ SDK initialized\n');

  // ── 2. Connect Alice ───────────────────────────────────────────
  console.log('2. Connecting as Alice...');
  const alice = await app.connect('alice@example.com');
  console.log(`   ✓ Connected as ${alice.getUserId()}\n`);

  // ── 3. Connect Bob ─────────────────────────────────────────────
  console.log('3. Connecting as Bob...');
  const bob = await app.connect('bob@example.com');
  console.log(`   ✓ Connected as ${bob.getUserId()}\n`);

  // ── 4. Set up message handler ──────────────────────────────────
  console.log('4. Setting up message handlers...');
  const unsubBob = bob.onMessage((from, msg) => {
    console.log(`   📨 Bob received from ${from}: ${msg}`);
  });
  const unsubAlice = alice.onMessage((from, msg) => {
    console.log(`   📨 Alice received from ${from}: ${msg}`);
  });
  console.log('   ✓ Handlers registered\n');

  // ── 5. Send message (auto-waits for recipient) ─────────────────
  console.log('5. Alice sends message to Bob...');
  await alice.send('bob@example.com', 'Hello Bob! This is E2E encrypted.');
  console.log('   ✓ Message sent\n');

  // ── 6. Send with explicit options ──────────────────────────────
  console.log('6. Bob sends message to Alice (with custom timeout)...');
  await bob.send('alice@example.com', 'Hi Alice!', {
    timeout: 5000,
    waitForRecipient: true,   // default — auto-waits
  });
  console.log('   ✓ Message sent\n');

  // Wait for message delivery
  await new Promise(r => setTimeout(r, 1000));

  // ── 7. Cleanup ─────────────────────────────────────────────────
  console.log('7. Disconnecting...');
  unsubBob();
  unsubAlice();
  await app.disconnect();
  console.log('   ✓ Done\n');
}

// ── Error handling ─────────────────────────────────────────────────
main().catch((error) => {
  if (error instanceof StvorError) {
    console.error(`\n❌ StvorError [${error.code}]: ${error.message}`);
    if (error.action) console.error(`   Action: ${error.action}`);
    if (error.retryable) console.error('   (This error is retryable)');
  } else {
    console.error('\n❌ Unexpected error:', error);
  }
  process.exit(1);
});
