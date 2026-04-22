/**
 * Socket.io Relay Example
 * 
 * Demonstrates how to use STVOR SDK with Socket.io for custom transport
 * This is suitable for web chats, collaborative apps, real-time messaging
 * 
 * User Flow:
 * 1. Alice connects to Socket.io server
 * 2. Alice's client generates keypair and shares public key via Socket.io
 * 3. Bob connects and gets Alice's key
 * 4. Bob encrypts a message using encryptMessage()
 * 5. Bob sends encrypted message via Socket.io
 * 6. Alice receives encrypted message and decrypts with decryptMessage()
 */

import { Stvor } from '@stvor/sdk';
import { io } from 'socket.io-client';

// --- CLIENT SIDE ---

async function setupAliceClient() {
  // Initialize STVOR (no relay needed - we use Socket.io)
  // Pass a dummy relay URL since we're not using it
  const alice = await Stvor.init({
    appToken: 'stvor_...',
    relayUrl: 'wss://dummy.local', // We override this with Socket.io
  });

  // Connect to Socket.io server
  const socket = io('http://localhost:3000');
  
  // Create Alice's connection
  const aliceClient = await alice.connect('alice@example.com');

  // Share Alice's public key when connected
  socket.on('connect', () => {
    const pubKey = aliceClient.getPublicKey();
    socket.emit('register', {
      userId: 'alice@example.com',
      publicKey: pubKey,
    });
  });

  // Handle incoming encrypted messages from Socket.io
  socket.on('message', async (data: any) => {
    try {
      // Decrypt the message
      const decrypted = await aliceClient.decryptMessage(data.encrypted);
      console.log(`📨 From ${data.from}:`, decrypted);
      
      // Optional: send read receipt
      socket.emit('message:read', { messageId: data.id });
    } catch (error) {
      console.error('Failed to decrypt message:', error);
    }
  });

  return { alice, aliceClient, socket };
}

async function setupBobClient() {
  const bob = await Stvor.init({
    appToken: 'stvor_...',
    relayUrl: 'wss://dummy.local',
  });

  const socket = io('http://localhost:3000');
  const bobClient = await bob.connect('bob@example.com');

  // Register Bob and request Alice's public key
  socket.on('connect', () => {
    const pubKey = bobClient.getPublicKey();
    socket.emit('register', {
      userId: 'bob@example.com',
      publicKey: pubKey,
    });

    // Request Alice's public key
    socket.emit('get-user-key', { userId: 'alice@example.com' });
  });

  // Receive Alice's public key
  socket.on('user-key', (data: any) => {
    // Add Alice's key to our known peers
    bobClient.addPeerKey('alice@example.com', data.publicKey);
    console.log('✅ Got Alice\'s public key');
  });

  return { bob, bobClient, socket };
}

async function sendMessageFromBobToAlice() {
  const { bob, bobClient, socket } = await setupBobClient();

  // Wait a bit for setup
  await new Promise(resolve => setTimeout(resolve, 500));

  // Encrypt message manually
  const encrypted = await bobClient.encryptMessage(
    'alice@example.com',
    'Hello Alice, this is Bob!'
  );

  // Send via Socket.io (not STVOR relay)
  socket.emit('message', {
    to: 'alice@example.com',
    from: 'bob@example.com',
    encrypted: encrypted,
    id: Date.now().toString(),
  });

  console.log('✉️ Sent encrypted message via Socket.io');
}

// --- SERVER SIDE ---

import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';

const app = express();
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: '*' },
});

// In-memory user registry
const users = new Map<string, { socket: any; publicKey: string }>();

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  // User registration with public key
  socket.on('register', (data) => {
    const { userId, publicKey } = data;
    users.set(userId, { socket, publicKey });
    console.log(`📍 User registered: ${userId}`);

    // Broadcast user online status
    io.emit('user-online', { userId, publicKey });
  });

  // Get user's public key
  socket.on('get-user-key', (data) => {
    const { userId } = data;
    const user = users.get(userId);
    if (user) {
      socket.emit('user-key', {
        userId,
        publicKey: user.publicKey,
      });
    } else {
      socket.emit('error', { message: 'User not found' });
    }
  });

  // Relay encrypted message
  socket.on('message', (data) => {
    const { to, from, encrypted, id } = data;
    const recipient = users.get(to);

    if (recipient) {
      // Relay the encrypted message (server cannot decrypt it)
      recipient.socket.emit('message', {
        from,
        id,
        encrypted,
      });
      console.log(`📬 Relayed message from ${from} to ${to}`);
    } else {
      socket.emit('error', { message: 'Recipient not found' });
    }
  });

  // Message read receipt
  socket.on('message:read', (data) => {
    // Implement as needed
  });

  socket.on('disconnect', () => {
    // Remove user
    for (const [userId, user] of users.entries()) {
      if (user.socket.id === socket.id) {
        users.delete(userId);
        console.log(`❌ User disconnected: ${userId}`);
        io.emit('user-offline', { userId });
        break;
      }
    }
  });
});

httpServer.listen(3000, () => {
  console.log('✅ Socket.io server listening on :3000');
});
