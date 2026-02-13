#!/usr/bin/env node
/**
 * STVOR SDK — CommonJS Example
 *
 * This example works with:
 *   - package.json WITHOUT "type": "module" (or with "type": "commonjs")
 *   - .cjs files (regardless of package.json type)
 *   - Older Node.js projects using require()
 *
 * Prerequisites:
 *   1. npm install @stvor/sdk
 *   2. Start mock relay: npx @stvor/sdk mock-relay
 *   3. Run this file:    node examples/commonjs-example.cjs
 *
 * Note: Since @stvor/sdk is an ES Module, CommonJS usage requires the
 * async sdk.load() pattern. This is transparent and works on Node.js ≥ 18.
 */

'use strict';

const RELAY_URL = process.env.RELAY_URL || 'ws://localhost:4444';
const APP_TOKEN = process.env.STVOR_APP_TOKEN || 'stvor_dev_example123';

async function main() {
  console.log('=== STVOR SDK — CommonJS Example ===\n');

  // ── 1. Load the SDK (async step required for CJS) ─────────────
  console.log('1. Loading SDK...');
  const sdk = require('@stvor/sdk');
  const { Stvor, StvorError } = await sdk.load();
  console.log('   ✓ SDK loaded\n');

  // ── 2. Initialize ─────────────────────────────────────────────
  console.log('2. Initializing SDK...');
  const app = await Stvor.init({
    appToken: APP_TOKEN,
    relayUrl: RELAY_URL,
    timeout: 10000,
  });
  console.log('   ✓ SDK initialized\n');

  // ── 3. Connect users ──────────────────────────────────────────
  console.log('3. Connecting users...');
  const alice = await app.connect('alice@example.com');
  console.log('   ✓ Alice connected');
  const bob = await app.connect('bob@example.com');
  console.log('   ✓ Bob connected\n');

  // ── 4. Message handlers ───────────────────────────────────────
  console.log('4. Setting up message handlers...');
  bob.onMessage(function(from, msg) {
    console.log('   [Bob received] ' + from + ': ' + msg);
  });
  alice.onMessage(function(from, msg) {
    console.log('   [Alice received] ' + from + ': ' + msg);
  });
  console.log('   ✓ Handlers registered\n');

  // ── 5. Send messages ──────────────────────────────────────────
  console.log('5. Alice sends message to Bob...');
  await alice.send('bob@example.com', 'Hello from CommonJS!');
  console.log('   ✓ Message sent\n');

  console.log('6. Bob replies to Alice...');
  await bob.send('alice@example.com', 'Got it! CJS works great.');
  console.log('   ✓ Reply sent\n');

  // Wait for delivery
  await new Promise(function(resolve) { setTimeout(resolve, 1000); });

  // ── 6. Cleanup ─────────────────────────────────────────────────
  console.log('7. Disconnecting...');
  await app.disconnect();
  console.log('   ✓ Done\n');
}

main().catch(function(error) {
  console.error('\nError:', error.message || error);
  if (error.code) console.error('Code:', error.code);
  if (error.action) console.error('Action:', error.action);
  process.exit(1);
});
