/**
 * Custom HTTP Transport Example
 * 
 * Demonstrates using STVOR SDK with a custom HTTP-based message delivery
 * Suitable for:
 * - REST API based messaging
 * - Mobile apps with custom backend
 * - IoT devices
 * - Bandwidth-constrained environments
 * 
 * Benefits over STVOR relay:
 * - Your own server controls message delivery
 * - No external dependencies
 * - Integration with existing systems
 * - Complete control over storage and delivery
 */

import { Stvor, EncryptedMessage } from '@stvor/sdk';
import axios from 'axios';

// --- CLIENT SIDE ---

class CustomTransportClient {
  private client: any;
  private userId: string;
  private baseUrl: string;

  constructor(userId: string, appToken: string, baseUrl: string) {
    this.userId = userId;
    this.baseUrl = baseUrl;
  }

  async initialize() {
    const app = await Stvor.init({
      appToken: 'stvor_dev_' + this.userId,
      relayUrl: 'wss://localhost:0', // Not used
    });

    this.client = await app.connect(this.userId);

    // Register this user on the custom server
    await this.registerWithServer();

    return this;
  }

  private async registerWithServer() {
    const pubKey = this.client.getPublicKey();
    await axios.post(`${this.baseUrl}/users/register`, {
      userId: this.userId,
      publicKey: pubKey,
    });

    console.log(`✅ ${this.userId} registered on custom server`);
  }

  async sendMessage(recipientId: string, content: string) {
    // Step 1: Fetch recipient's public key from server
    const { data } = await axios.get(`${this.baseUrl}/users/${recipientId}/key`);
    const recipientPubKey = data.publicKey;

    // Step 2: Add recipient's key if not known
    if (!this.client.isUserAvailable(recipientId)) {
      this.client.addPeerKey(recipientId, recipientPubKey);
    }

    // Step 3: Encrypt message
    const encrypted = await this.client.encryptMessage(recipientId, content);

    // Step 4: Send encrypted message via custom HTTP API
    await axios.post(`${this.baseUrl}/messages`, {
      to: recipientId,
      from: this.userId,
      encrypted,
    });

    console.log(`✉️ Message sent to ${recipientId}`);
  }

  async fetchMessages() {
    const { data } = await axios.get(`${this.baseUrl}/messages/${this.userId}`);

    const decrypted = [];
    for (const msg of data.messages) {
      try {
        const content = await this.client.decryptMessage(msg.encrypted);
        decrypted.push({
          from: msg.from,
          content,
          timestamp: msg.timestamp,
        });
      } catch (error) {
        console.error(`Failed to decrypt message from ${msg.from}`);
      }
    }

    return decrypted;
  }

  async pollMessages(intervalMs: number = 5000) {
    console.log(`\n📥 Polling for messages every ${intervalMs}ms...`);

    const poll = async () => {
      try {
        const messages = await this.fetchMessages();
        for (const msg of messages) {
          console.log(`\n📨 From ${msg.from}: ${msg.content}`);
        }
      } catch (error) {
        console.error('Failed to fetch messages:', error);
      }

      setTimeout(poll, intervalMs);
    };

    poll();
  }
}

// --- SERVER SIDE (Node.js/Express) ---

import express from 'express';

const app = express();
app.use(express.json());

// In-memory storage
const users = new Map<string, { publicKey: string; createdAt: Date }>();
const messages = new Map<string, any[]>();

// Register endpoint
app.post('/users/register', (req, res) => {
  const { userId, publicKey } = req.body;

  if (!userId || !publicKey) {
    return res.status(400).json({ error: 'Missing userId or publicKey' });
  }

  users.set(userId, {
    publicKey,
    createdAt: new Date(),
  });

  console.log(`📍 User registered: ${userId}`);
  res.json({ ok: true });
});

// Get user's public key
app.get('/users/:userId/key', (req, res) => {
  const { userId } = req.params;
  const user = users.get(userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ userId, publicKey: user.publicKey });
});

// Send encrypted message
app.post('/messages', (req, res) => {
  const { to, from, encrypted } = req.body;

  if (!to || !from || !encrypted) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  // Validate both users exist
  if (!users.has(to)) {
    return res.status(404).json({ error: `Recipient '${to}' not found` });
  }

  if (!users.has(from)) {
    return res.status(404).json({ error: `Sender '${from}' not found` });
  }

  // Store message (server cannot decrypt it)
  if (!messages.has(to)) {
    messages.set(to, []);
  }

  messages.get(to)!.push({
    from,
    encrypted,
    timestamp: new Date().toISOString(),
    id: `${Date.now()}-${Math.random()}`,
  });

  console.log(`📬 Message stored: ${from} → ${to}`);
  res.json({ ok: true, messageId: messages.get(to)!.at(-1)?.id });
});

// Fetch encrypted messages for user
app.get('/messages/:userId', (req, res) => {
  const { userId } = req.params;

  if (!users.has(userId)) {
    return res.status(404).json({ error: 'User not found' });
  }

  const userMessages = messages.get(userId) || [];

  // Don't delete messages here - let client decide
  // This allows offline delivery and re-fetching

  res.json({
    userId,
    messages: userMessages,
    count: userMessages.length,
  });
});

// Delete specific message (after client confirms receipt)
app.delete('/messages/:userId/:messageId', (req, res) => {
  const { userId, messageId } = req.params;

  const userMessages = messages.get(userId) || [];
  const index = userMessages.findIndex((m) => m.id === messageId);

  if (index === -1) {
    return res.status(404).json({ error: 'Message not found' });
  }

  userMessages.splice(index, 1);
  res.json({ ok: true });
});

// Stats endpoint
app.get('/stats', (req, res) => {
  res.json({
    users: users.size,
    totalMessages: Array.from(messages.values()).reduce((sum, msgs) => sum + msgs.length, 0),
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Custom HTTP transport server on http://localhost:${PORT}`);
});

// --- USAGE EXAMPLE ---

async function example() {
  // Alice sends message to Bob
  const alice = new CustomTransportClient('alice', 'stvor_dev', 'http://localhost:3000');
  await alice.initialize();

  const bob = new CustomTransportClient('bob', 'stvor_dev', 'http://localhost:3000');
  await bob.initialize();

  // Bob polls for messages
  bob.pollMessages(2000);

  // Alice sends message
  await alice.sendMessage('bob', 'Hello Bob, using custom HTTP transport!');

  // Wait a bit for polling
  await new Promise(resolve => setTimeout(resolve, 3000));
}

// Uncomment to run:
// example().catch(console.error);

export { CustomTransportClient };
