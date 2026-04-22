/**
 * P2P Direct Messaging Example
 * 
 * Demonstrates peer-to-peer E2EE messaging without a relay
 * Suitable for:
 * - Desktop apps with direct peer discovery
 * - WebRTC-based applications
 * - LAN messaging
 * - QR code based key exchange
 * 
 * User Flow:
 * 1. Both peers generate keypairs
 * 2. Exchange public keys via QR code, NFC, or manual entry
 * 3. Each peer manually adds the other's key using addPeerKey()
 * 4. Messages are encrypted and sent via custom transport
 */

import { Stvor } from '@stvor/sdk';

// --- Example 1: Direct P2P with Manual Key Exchange ---

async function p2pDirectMessaging() {
  // Alice initializes (no relay needed)
  const alice = await Stvor.init({
    appToken: 'stvor_dev_alice_local', // Can be any dummy token
    relayUrl: 'wss://localhost:0', // Not used
  });

  const aliceClient = await alice.connect('alice');
  console.log('Alice\'s public key (share via QR code or NFC):');
  console.log(aliceClient.getPublicKey());

  // Bob initializes
  const bob = await Stvor.init({
    appToken: 'stvor_dev_bob_local',
    relayUrl: 'wss://localhost:0',
  });

  const bobClient = await bob.connect('bob');
  console.log('\nBob\'s public key:');
  console.log(bobClient.getPublicKey());

  // --- Key Exchange Phase ---
  // In reality, this would happen via QR code scanning, NFC, or secure channel
  const alicePubKey = aliceClient.getPublicKey();
  const bobPubKey = bobClient.getPublicKey();

  // Both peers add each other's key
  aliceClient.addPeerKey('bob', bobPubKey);
  bobClient.addPeerKey('alice', alicePubKey);

  console.log('\n✅ Keys exchanged!');

  // --- Messaging Phase ---
  // Bob encrypts a message for Alice
  const encrypted = await bobClient.encryptMessage('alice', 'Hi Alice, no relay needed!');

  // In a real app, send this via WebRTC datachannel, HTTP, file transfer, etc.
  console.log('\nEncrypted message (can be sent via any transport):');
  console.log(JSON.stringify(encrypted, null, 2));

  // Alice receives and decrypts
  const decrypted = await aliceClient.decryptMessage(encrypted);
  console.log('\n✅ Alice received:', decrypted);
}

// --- Example 2: QR Code Based Key Exchange ---

async function qrCodeKeyExchange() {
  // In a real app, use a QR code library like 'qrcode'
  const QRCode = require('qrcode');

  const alice = await Stvor.init({
    appToken: 'stvor_dev',
    relayUrl: 'wss://localhost:0',
  });

  const aliceClient = await alice.connect('alice');
  const alicePubKey = aliceClient.getPublicKey();

  // Generate QR code from Alice's public key
  const qrCodeData = {
    userId: 'alice',
    publicKey: alicePubKey,
    timestamp: Date.now(),
  };

  const qrCode = await QRCode.toDataURL(JSON.stringify(qrCodeData));
  console.log('Alice displays this QR code for others to scan:');
  console.log(qrCode);

  // Bob scans the QR code
  const scannedData = JSON.parse('...'); // Simulated QR scan result
  bobClient.addPeerKey(scannedData.userId, scannedData.publicKey);

  console.log('✅ Bob successfully added Alice\'s key from QR code');
}

// --- Example 3: HTTP-based Secure Key Exchange ---

async function httpKeyExchange() {
  // Setup HTTPS server for secure key exchange
  import express from 'express';
  import https from 'https';
  import fs from 'fs';

  const app = express();
  app.use(express.json());

  const userKeys = new Map<string, string>();

  // Endpoint to upload your public key
  app.post('/register', (req, res) => {
    const { userId, publicKey } = req.body;

    if (!userId || !publicKey) {
      return res.status(400).json({ error: 'Missing userId or publicKey' });
    }

    userKeys.set(userId, publicKey);
    console.log(`📍 Registered: ${userId}`);
    res.json({ ok: true });
  });

  // Endpoint to fetch someone's public key
  app.get('/users/:userId/key', (req, res) => {
    const { userId } = req.params;
    const publicKey = userKeys.get(userId);

    if (!publicKey) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ userId, publicKey });
  });

  // Start HTTPS server (use self-signed cert for demo)
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
  };

  https.createServer(options, app).listen(3001, () => {
    console.log('✅ Key exchange server on https://localhost:3001');
  });
}

// --- Example 4: CLI-based P2P Chat ---

async function p2pCliChat() {
  import readline from 'readline';

  const alice = await Stvor.init({
    appToken: 'stvor_dev',
    relayUrl: 'wss://localhost:0',
  });

  const aliceClient = await alice.connect('alice');

  // Display Alice's public key for Bob to copy
  console.log('\n=== Alice (sender) ===');
  console.log('Your public key (give to Bob):');
  console.log(aliceClient.getPublicKey());

  // Read Bob's public key from stdin
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const bobPubKey = await new Promise<string>(resolve => {
    rl.question('\nEnter Bob\'s public key: ', resolve);
  });

  aliceClient.addPeerKey('bob', bobPubKey);
  console.log('✅ Bob\'s key added');

  // Chat loop
  const sendMessage = () => {
    rl.question('\nYour message (or "exit" to quit): ', async (msg) => {
      if (msg === 'exit') {
        rl.close();
        return;
      }

      try {
        const encrypted = await aliceClient.encryptMessage('bob', msg);
        console.log('\n📤 Encrypted message (send this to Bob):');
        console.log(JSON.stringify(encrypted));
        sendMessage();
      } catch (error) {
        console.error('Encryption failed:', error);
        sendMessage();
      }
    });
  };

  sendMessage();
}

// --- Run Examples ---

// Uncomment to run:
// p2pDirectMessaging();
// qrCodeKeyExchange();
// httpKeyExchange();
// p2pCliChat();

export { p2pDirectMessaging, qrCodeKeyExchange, httpKeyExchange, p2pCliChat };
