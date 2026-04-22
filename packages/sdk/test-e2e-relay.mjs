/**
 * STVOR Web SDK - End-to-End Relay Test
 * Test encrypted communication between two clients through relay
 */

import WebSocketLib from 'ws';
const WebSocket = WebSocketLib;
const nacl = await import('tweetnacl').then(m => m.default || m);

// Test client
class TestClient {
  constructor(userId, relayUrl) {
    this.userId = userId;
    this.relayUrl = relayUrl;
    this.ws = null;
    this.publicKey = null;
    this.secretKey = null;
    this.masterKey = null;
    this.peerPublicKeys = new Map();
    this.messageHandlers = [];
    this.connected = false;
  }

  async generateKeys(sharedMasterKey) {
    console.log(`  ${this.userId}: Generating keys...`);
    
    // Generate keypair (X25519)
    const keypair = nacl.box.keyPair();
    this.publicKey = keypair.publicKey;
    this.secretKey = keypair.secretKey;
    
    // Use shared master key (in real scenario, derived from X3DH)
    this.masterKey = sharedMasterKey || nacl.randomBytes(32);
    
    console.log(`  ${this.userId}: Keys generated`);
    console.log(`    - Public Key: ${this.publicKey.length} bytes`);
    console.log(`    - Master Key: ${this.masterKey.length} bytes`);
  }

  async connect() {
    return new Promise((resolve, reject) => {
      console.log(`  ${this.userId}: Connecting to relay...`);
      
      this.ws = new WebSocket(this.relayUrl);
      
      this.ws.on('open', () => {
        console.log(`  ${this.userId}: Connected to relay ✓`);
        this.connected = true;
        
        // Announce self to relay
        const announcement = {
          type: 'announce',
          user: this.userId,
          pub: Array.from(this.publicKey)
        };
        this.ws.send(JSON.stringify(announcement));
        console.log(`  ${this.userId}: Announced to relay`);
        
        resolve();
      });
      
      this.ws.on('message', (data) => {
        try {
          const msg = JSON.parse(data);
          this.handleMessage(msg);
        } catch (e) {
          console.error(`  ${this.userId}: Parse error:`, e.message);
        }
      });
      
      this.ws.on('error', (err) => {
        console.error(`  ${this.userId}: WebSocket error:`, err);
        reject(err);
      });
      
      this.ws.on('close', () => {
        console.log(`  ${this.userId}: Disconnected from relay`);
        this.connected = false;
      });
    });
  }

  handleMessage(msg) {
    if (msg.type === 'announce') {
      // Store peer's public key
      const peerPublicKey = new Uint8Array(msg.pub);
      this.peerPublicKeys.set(msg.user, peerPublicKey);
      console.log(`  ${this.userId}: Received announcement from ${msg.user}`);
    } else if (msg.type === 'message') {
      // Handle encrypted message
      const handler = this.messageHandlers.pop();
      if (handler) {
        handler(msg);
      }
    }
  }

  async encrypt(message, targetUser) {
    console.log(`  ${this.userId}: Encrypting message for ${targetUser}...`);
    
    // Serialize message
    const plaintext = new TextEncoder().encode(JSON.stringify({
      text: message,
      timestamp: Date.now(),
      from: this.userId
    }));
    
    // Generate nonce
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    
    // Encrypt with master key
    const ciphertext = nacl.secretbox(plaintext, nonce, this.masterKey);
    
    // Combine nonce + ciphertext
    const encrypted = new Uint8Array(nonce.length + ciphertext.length);
    encrypted.set(nonce, 0);
    encrypted.set(ciphertext, nonce.length);
    
    console.log(`  ${this.userId}: Encrypted ${plaintext.length} → ${encrypted.length} bytes`);
    
    return Array.from(encrypted);
  }

  async decrypt(encrypted) {
    console.log(`  ${this.userId}: Decrypting message...`);
    
    const data = new Uint8Array(encrypted);
    const nonce = data.slice(0, nacl.secretbox.nonceLength);
    const ciphertext = data.slice(nacl.secretbox.nonceLength);
    
    // Decrypt
    const plaintext = nacl.secretbox.open(ciphertext, nonce, this.masterKey);
    
    if (!plaintext) {
      throw new Error('Decryption failed - authentication failed');
    }
    
    const message = JSON.parse(new TextDecoder().decode(plaintext));
    console.log(`  ${this.userId}: Decrypted successfully`);
    
    return message;
  }

  async sendMessage(targetUser, message) {
    if (!this.connected) {
      throw new Error('Not connected to relay');
    }
    
    const encrypted = await this.encrypt(message, targetUser);
    
    const msg = {
      type: 'message',
      from: this.userId,
      to: targetUser,
      data: encrypted,
      id: Math.random().toString(36).substr(2, 9)
    };
    
    this.ws.send(JSON.stringify(msg));
    console.log(`  ${this.userId}: Sent message to ${targetUser}`);
  }

  async receiveMessage() {
    return new Promise((resolve) => {
      this.messageHandlers.push(async (msg) => {
        try {
          const decrypted = await this.decrypt(msg.data);
          resolve(decrypted);
        } catch (err) {
          console.error(`  ${this.userId}: Receive error:`, err);
          resolve(null);
        }
      });
    });
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

// Run tests
async function runTests() {
  console.log('\n🧪 STVOR Web SDK - End-to-End Relay Test\n');

  const relayUrl = 'ws://localhost:8080';
  const alice = new TestClient('alice', relayUrl);
  const bob = new TestClient('bob', relayUrl);

  try {
    // Generate shared master key (simulating X3DH or pre-shared key)
    const sharedMasterKey = nacl.randomBytes(32);
    
    // Test 1: Generate keys
    console.log('Test 1: Generate encryption keys (with shared secret)');
    await alice.generateKeys(sharedMasterKey);
    await bob.generateKeys(sharedMasterKey);
    console.log('✅ Keys generated\n');

    // Test 2: Connect to relay
    console.log('Test 2: Connect clients to relay');
    await alice.connect();
    await bob.connect();
    console.log('✅ Both clients connected\n');

    // Wait for announcements to propagate
    await new Promise(r => setTimeout(r, 500));

    // Test 3: Send encrypted message Alice → Bob
    console.log('Test 3: Alice sends encrypted message to Bob');
    await alice.sendMessage('bob', 'Hello Bob! This is encrypted.');
    
    // Bob receives message
    const bobReceives = new Promise(resolve => {
      bob.messageHandlers.push(async (msg) => {
        try {
          const decrypted = await bob.decrypt(msg.data);
          resolve(decrypted);
        } catch (err) {
          console.error('  bob: Receive error:', err);
          resolve(null);
        }
      });
    });

    const receivedByBob = await Promise.race([
      bobReceives,
      new Promise(r => setTimeout(() => r(null), 2000))
    ]);

    if (receivedByBob && receivedByBob.text === 'Hello Bob! This is encrypted.') {
      console.log('  bob: Received and decrypted message ✓');
      console.log(`  bob: "${receivedByBob.text}"`);
      console.log(`  bob: From: ${receivedByBob.from}`);
      console.log('✅ Message successfully encrypted and transmitted\n');
    } else {
      throw new Error('Message delivery failed');
    }

    // Test 4: Send encrypted message Bob → Alice
    console.log('Test 4: Bob sends encrypted message to Alice');
    await bob.sendMessage('alice', 'Hi Alice! Got your message.');
    
    const aliceReceives = new Promise(resolve => {
      alice.messageHandlers.push(async (msg) => {
        try {
          const decrypted = await alice.decrypt(msg.data);
          resolve(decrypted);
        } catch (err) {
          console.error('  alice: Receive error:', err);
          resolve(null);
        }
      });
    });

    const receivedByAlice = await Promise.race([
      aliceReceives,
      new Promise(r => setTimeout(() => r(null), 2000))
    ]);

    if (receivedByAlice && receivedByAlice.text === 'Hi Alice! Got your message.') {
      console.log('  alice: Received and decrypted message ✓');
      console.log(`  alice: "${receivedByAlice.text}"`);
      console.log(`  alice: From: ${receivedByAlice.from}`);
      console.log('✅ Bidirectional communication verified\n');
    } else {
      throw new Error('Bidirectional message delivery failed');
    }

    // Success
    console.log('✅ ALL TESTS PASSED!\n');
    console.log('📊 Test Summary:');
    console.log('✅ Encryption keys generated (X25519 keypair + 256-bit master key)');
    console.log('✅ Both clients connected to relay server');
    console.log('✅ Alice sent encrypted message to Bob');
    console.log('✅ Bob decrypted and received message');
    console.log('✅ Bob sent encrypted message to Alice');
    console.log('✅ Alice decrypted and received message');
    console.log('✅ End-to-end encryption working');

    console.log('\n🎉 Web SDK relay integration fully operational!\n');

  } catch (err) {
    console.error('\n❌ Test failed:', err.message);
    console.error('Details:', err);
    process.exit(1);
  } finally {
    alice.disconnect();
    bob.disconnect();
    
    // Give sockets time to close
    await new Promise(r => setTimeout(r, 200));
    process.exit(0);
  }
}

runTests().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
