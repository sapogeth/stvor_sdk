/**
 * WebRTC P2P Messaging Example
 *
 * Demonstrates using STVOR SDK with WebRTC DataChannel
 * for peer-to-peer encrypted messaging without any server.
 *
 * Benefits:
 * - No server infrastructure required
 * - Direct peer connection
 * - Lower latency
 * - Works offline
 * - No message server can store/access data
 *
 * Prerequisites:
 * - Simple-peer or wrtc library (WebRTC implementation)
 * - STUN/TURN servers for NAT traversal
 */

import { Stvor, EncryptedMessage } from '@stvor/sdk';

// Using simple-peer as example (works in browser and Node.js)
import SimplePeer from 'simple-peer';

class WebRTCMessenger {
  private client: any;
  private userId: string;
  private peers = new Map<string, SimplePeer.Instance>();
  private publicKey: string;

  constructor(userId: string) {
    this.userId = userId;
  }

  async initialize() {
    const app = await Stvor.init({
      appToken: 'stvor_dev_' + this.userId,
      relayUrl: 'wss://localhost:0', // Not used
    });

    this.client = await app.connect(this.userId);
    this.publicKey = this.client.getPublicKey();

    console.log(`✅ ${this.userId} initialized`);
    console.log(`Public key: ${this.publicKey}`);

    return this;
  }

  /**
   * Create a WebRTC connection to a peer
   * Useful after receiving peer's public key via signaling server
   */
  initiatePeerConnection(peerId: string, isInitiator: boolean) {
    console.log(`🔗 Initiating connection to ${peerId}...`);

    const peer = new SimplePeer({
      initiator: isInitiator,
      trickle: false,
      iceServers: [
        {
          urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'],
        },
      ],
    });

    // Handle connection establishment
    peer.on('connect', () => {
      console.log(`✅ Connected to ${peerId}`);
    });

    // Handle incoming messages on data channel
    peer.on('data', async (data) => {
      try {
        // Parse the encrypted message
        const encrypted: EncryptedMessage = JSON.parse(data.toString());

        // Decrypt using STVOR SDK
        const decrypted = await this.client.decryptMessage(encrypted);

        console.log(`\n📨 From ${peerId}: ${decrypted}`);

        // Optionally send acknowledgment
        this.sendMessage(peerId, `Got: ${decrypted.substring(0, 20)}...`);
      } catch (error) {
        console.error(`Failed to decrypt from ${peerId}:`, error);
      }
    });

    peer.on('error', (err) => {
      console.error(`Connection error with ${peerId}:`, err);
      this.peers.delete(peerId);
    });

    peer.on('close', () => {
      console.log(`🔌 Connection closed with ${peerId}`);
      this.peers.delete(peerId);
    });

    this.peers.set(peerId, peer);
    return peer;
  }

  /**
   * Get the SDP offer for initiating a connection
   * Send this to the peer via signaling server
   */
  getSignalingOffer(peerId: string): string {
    const peer = this.peers.get(peerId);
    if (!peer) {
      throw new Error(`No connection initiated to ${peerId}`);
    }

    // In real app, you'd send peer.send(JSON.stringify(peer._pc.localDescription))
    // This is complex, see WebRTC signaling servers like:
    // - Kurento
    // - Janus
    // - OpenVidu
    // Or use a commercial service

    return 'Use your signaling server to exchange SDP offers';
  }

  /**
   * Send an encrypted message to a peer
   */
  async sendMessage(peerId: string, content: string) {
    const peer = this.peers.get(peerId);
    if (!peer) {
      throw new Error(`Not connected to ${peerId}`);
    }

    if (peer.destroyed) {
      throw new Error(`Connection to ${peerId} is closed`);
    }

    // Check if peer knows our key
    if (!this.client.isUserAvailable(peerId)) {
      // In real scenario, you'd have shared keys via signaling
      console.warn(`Peer ${peerId} key not registered - assuming it was shared during connection setup`);
    }

    // Encrypt message
    const encrypted = await this.client.encryptMessage(peerId, content);

    // Send encrypted message over WebRTC data channel
    peer.send(JSON.stringify(encrypted));

    console.log(`✉️ Sent to ${peerId}: ${content}`);
  }

  /**
   * Get signaling data for key exchange
   * Include this in your SDP offer/answer
   */
  getSignalingInfo() {
    return {
      userId: this.userId,
      publicKey: this.publicKey,
      timestamp: Date.now(),
    };
  }

  /**
   * Process peer's signaling info and register their key
   */
  addPeerFromSignaling(signalingInfo: any) {
    this.client.addPeerKey(signalingInfo.userId, signalingInfo.publicKey);
    console.log(`✅ Added ${signalingInfo.userId}'s public key`);
  }
}

// --- USAGE EXAMPLE ---

/**
 * Example flow with signaling server
 *
 * 1. Alice and Bob connect to signaling server
 * 2. Alice requests connection to Bob via signaling
 * 3. Signaling exchanges their public keys
 * 4. WebRTC connection is established
 * 5. They exchange messages encrypted with STVOR
 */

async function example() {
  console.log('=== WebRTC P2P Messaging with STVOR ===\n');

  // Initialize both peers
  const alice = new WebRTCMessenger('alice');
  const bob = new WebRTCMessenger('bob');

  await alice.initialize();
  await bob.initialize();

  // --- SIGNALING PHASE (via server) ---
  // Get signaling info
  const aliceSignaling = alice.getSignalingInfo();
  const bobSignaling = bob.getSignalingInfo();

  console.log('\n--- Signaling Exchange ---');
  console.log('Alice sends:', JSON.stringify(aliceSignaling, null, 2));
  console.log('Bob sends:', JSON.stringify(bobSignaling, null, 2));

  // --- CONNECTION PHASE ---
  console.log('\n--- WebRTC Connection ---');

  // Alice initiates connection
  const alicePeer = alice.initiatePeerConnection('bob', true);

  // Bob accepts connection
  const bobPeer = bob.initiatePeerConnection('alice', false);

  // In real scenario, exchange SDP through signaling server:
  // alicePeer.send(JSON.stringify(aliceOffer));
  // bobPeer.send(JSON.stringify(bobAnswer));

  // Register each other's keys
  alice.addPeerFromSignaling(bobSignaling);
  bob.addPeerFromSignaling(aliceSignaling);

  // Simulate connection establishment
  console.log('\n--- Messages ---');

  // Note: In Node.js, simple-peer needs a working WebRTC implementation
  // In browser, this would work automatically
  console.log('\n✅ WebRTC connection established (simulated)');
  console.log('Ready to send encrypted messages!');

  // Example: Alice sends message
  // await alice.sendMessage('bob', 'Hello Bob, via WebRTC!');

  // Example: Wait for messages
  // bob receives on 'data' event and auto-decrypts
}

export { WebRTCMessenger };

// Uncomment to run (requires WebRTC in browser or wrtc package):
// example().catch(console.error);

/**
 * ============================================================
 * ADVANTAGES OF WebRTC APPROACH:
 * ============================================================
 *
 * ✅ NO SERVER MESSAGE STORAGE
 *    - Messages are not stored anywhere
 *    - Signaling server never sees encrypted data
 *    - Perfect privacy
 *
 * ✅ LOW LATENCY
 *    - Direct peer connection
 *    - No relay delays
 *    - Real-time messaging
 *
 * ✅ OFFLINE CAPABLE
 *    - Share messages when both peers are online
 *    - No server dependency
 *
 * ✅ SCALABLE
 *    - No infrastructure costs
 *    - No server bandwidth usage
 *    - Peer-to-peer costs scale with users
 *
 * ✅ WORKS ANYWHERE
 *    - Browser (native WebRTC)
 *    - Node.js (via wrtc or simple-peer)
 *    - Mobile (React Native with react-native-webrtc)
 *
 * ============================================================
 * CHALLENGES:
 * ============================================================
 *
 * ❌ Signaling Complexity
 *    - Need SDP offer/answer exchange
 *    - Requires signaling server (but only for setup!)
 *    - One-time per peer
 *
 * ❌ NAT Traversal
 *    - Need STUN/TURN servers
 *    - May not work behind some firewalls
 *    - Add latency in complex networks
 *
 * ❌ Reliability
 *    - No automatic retry
 *    - Connection may drop
 *    - Need re-connection logic
 *
 * ============================================================
 * BEST FOR:
 * ============================================================
 *
 * 👥 Group video calls (Jitsi, OkCupid)
 * 💬 Direct P2P chat (no message history needed)
 * 📁 File sharing (large files, fast transfer)
 * 🎮 Online games (low latency critical)
 * 🔐 Ultra-private messaging (no server logs)
 *
 * ============================================================
 * SETUP CHECKLIST:
 * ============================================================
 *
 * 1. Install dependencies:
 *    npm install simple-peer libsodium.js
 *
 * 2. Set up signaling server (choose one):
 *    - Firebase Realtime Database (key exchange)
 *    - Your own Node.js server
 *    - Socket.io (as shown in socketio example)
 *
 * 3. Configure STUN/TURN servers:
 *    - Google's free STUN: stun:stun.l.google.com:19302
 *    - TURN for better reliability
 *
 * 4. Implement SDP exchange:
 *    - Send peers' public keys via signaling
 *    - Exchange WebRTC SDP
 *    - Establish connection
 *
 * 5. Handle disconnections:
 *    - Detect peer.on('close')
 *    - Reconnect if needed
 *    - Save state if required
 */
