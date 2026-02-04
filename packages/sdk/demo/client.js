#!/usr/bin/env node
import { Stvor } from '../dist/index.js';

const USER = process.argv[2] || 'alice@example.com';
const PEER = process.argv[3] || (USER === 'alice' ? 'bob@example.com' : 'alice@example.com');

async function run() {
  const app = await Stvor.init({ appToken: 'stvor_demo_token', relayUrl: process.env.RELAY || 'ws://localhost:8080' });
  const client = await app.connect(USER);
  console.log(`${USER} connected`);

  client.onMessage((from, msg) => {
    console.log(`[${USER}] message from ${from}:`, msg);
  });

  if (USER.startsWith('bob')) {
    // bob sends to alice
    await new Promise(r => setTimeout(r, 500));
    console.log(`[${USER}] sending hello to ${PEER}`);
    await client.send(PEER, `Hello from ${USER}`);
  }
}

run().catch(err => { console.error(err); process.exit(1); });
