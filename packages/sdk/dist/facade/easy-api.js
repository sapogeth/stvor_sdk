/**
 * STVOR Easy-to-Use High-Level API
 *
 * Simple, intuitive interface for end-to-end encryption
 * - Works with ANY data type (strings, objects, binary, files)
 * - Automatic type preservation
 * - One-line messaging
 *
 * @example
 * import { StvorEasyAPI } from '@stvor/sdk';
 *
 * // Initialize
 * const api = await StvorEasyAPI.init({
 *   appToken: 'stvor_live_...',
 *   userId: 'alice@example.com'
 * });
 *
 * // Send ANY data type - automatically encrypted & type-preserved
 * await api.send('bob@example.com', { message: 'Hello', file: Buffer.from([1,2,3]) });
 * await api.send('bob@example.com', 'Simple text message');
 * await api.send('bob@example.com', 42);
 * await api.send('bob@example.com', { complex: { nested: { data: true } } });
 *
 * // Receive with automatic type restoration
 * api.onMessage((from, data) => {
 *   console.log(`Got from ${from}:`, data); // Data is automatically typed!
 * });
 */
import { CryptoSessionManager } from './crypto-session.js';
import { RelayClient } from './relay-client.js';
import { encodeData, decodeData } from './data-codec.js';
/**
 * High-level STVOR API that abstracts away cryptography
 *
 * Handles:
 * - Automatic type encoding/decoding
 * - Session management
 * - Message routing
 * - Error handling
 */
export class StvorEasyAPI {
    constructor(userId, cryptoManager, relayClient) {
        this.messageHandlers = new Set();
        this.polling = null;
        this.userId = userId;
        this.cryptoManager = cryptoManager;
        this.relayClient = relayClient;
    }
    /**
     * Initialize the API
     */
    static async init(config) {
        const cryptoManager = new CryptoSessionManager(config.userId);
        await cryptoManager.initialize();
        const relayUrl = config.relayUrl || 'http://localhost:3002';
        const relayClient = new RelayClient(relayUrl, config.appToken);
        // Register with relay
        const publicKeys = cryptoManager.getPublicKeys();
        await relayClient.register(config.userId, publicKeys);
        const api = new StvorEasyAPI(config.userId, cryptoManager, relayClient);
        // Start polling for messages
        api.startPolling();
        return api;
    }
    /**
     * Send ANY data type to peer - automatically encrypted
     *
     * @example
     * await api.send('bob@example.com', 'Hello Bob');
     * await api.send('bob@example.com', { greeting: 'Hello', emoji: '👋' });
     * await api.send('bob@example.com', 42);
     * await api.send('bob@example.com', Buffer.from([1, 2, 3]));
     */
    async send(peerId, data) {
        // Ensure session exists
        if (!this.cryptoManager.hasSession(peerId)) {
            // Need to establish session first
            const peerPublicKeys = await this.relayClient.getPublicKeys(peerId);
            if (!peerPublicKeys) {
                throw new Error(`Peer ${peerId} not found on relay`);
            }
            await this.cryptoManager.establishSession(peerId, peerPublicKeys);
        }
        // Encode data to binary, then to base64 for transport
        const encoded = encodeData(data);
        const plaintext = encoded.toString('base64');
        // Encrypt
        const { ciphertext, header } = this.cryptoManager.encryptForPeer(peerId, plaintext);
        // Send via relay
        await this.relayClient.send({
            to: peerId,
            from: this.userId,
            ciphertext,
            header,
        });
    }
    /**
     * Register handler for incoming messages
     * Data is automatically decoded to original type
     *
     * @example
     * api.onMessage((from, data) => {
     *   console.log(`From ${from}:`, data);
     *   // data is automatically typed (string, object, number, etc.)
     * });
     */
    onMessage(handler) {
        this.messageHandlers.add(handler);
    }
    /**
     * Remove message handler
     */
    offMessage(handler) {
        this.messageHandlers.delete(handler);
    }
    /**
     * Get user's public keys (for registering with peers)
     */
    getPublicKeys() {
        return this.cryptoManager.getPublicKeys();
    }
    /**
     * Connect to a peer (establish session)
     */
    async connectToPeer(peerId) {
        if (this.cryptoManager.hasSession(peerId)) {
            return; // Already connected
        }
        const peerPublicKeys = await this.relayClient.getPublicKeys(peerId);
        if (!peerPublicKeys) {
            throw new Error(`Cannot connect to ${peerId}: peer not found`);
        }
        await this.cryptoManager.establishSession(peerId, peerPublicKeys);
    }
    /**
     * Check if connected to peer
     */
    isConnected(peerId) {
        return this.cryptoManager.hasSession(peerId);
    }
    /**
     * Disconnect and stop polling
     */
    async disconnect() {
        this.stopPolling();
        this.messageHandlers.clear();
    }
    /* Private methods */
    startPolling() {
        // Poll for messages every 2 seconds
        this.polling = setInterval(() => {
            this.checkMessages().catch(console.error);
        }, 2000);
    }
    stopPolling() {
        if (this.polling) {
            clearInterval(this.polling);
            this.polling = null;
        }
    }
    async checkMessages() {
        try {
            const messages = await this.relayClient.fetchMessages(this.userId);
            for (const msg of messages) {
                try {
                    // Ensure session with sender
                    if (!this.cryptoManager.hasSession(msg.from)) {
                        const peerKeys = await this.relayClient.getPublicKeys(msg.from);
                        if (peerKeys) {
                            await this.cryptoManager.establishSession(msg.from, peerKeys);
                        }
                        else {
                            console.error(`Cannot establish session with ${msg.from}`);
                            continue;
                        }
                    }
                    // Decrypt
                    const plaintextB64 = this.cryptoManager.decryptFromPeer(msg.from, msg.ciphertext, msg.header);
                    // Convert base64 back to Buffer, then decode to original type
                    const plaintext = Buffer.from(plaintextB64, 'base64');
                    const data = decodeData(plaintext);
                    // Call handlers
                    for (const handler of this.messageHandlers) {
                        try {
                            await handler(msg.from, data);
                        }
                        catch (e) {
                            console.error('Message handler error:', e);
                        }
                    }
                    // Mark as processed (delete from relay)
                    if (msg.id) {
                        await this.relayClient.deleteMessage(msg.id).catch(() => {
                            // Ignore delete errors
                        });
                    }
                }
                catch (e) {
                    console.error(`Error processing message from ${msg.from}:`, e);
                }
            }
        }
        catch (e) {
            // Polling errors are non-fatal
            // console.error('Polling error:', e);
        }
    }
}
/**
 * Quick initialization shorthand
 *
 * @example
 * const api = await stvorInit({
 *   appToken: process.env.STVOR_TOKEN,
 *   userId: 'user@example.com'
 * });
 */
export async function stvorInit(config) {
    return StvorEasyAPI.init(config);
}
/**
 * Create minimal example
 *
 * @example
 * const api = await stvorInit({ appToken: 'token', userId: 'alice' });
 * await api.send('bob', 'Hello!');
 * api.onMessage((from, msg) => console.log(`From ${from}: ${msg}`));
 */
export async function quickStart(token, userId) {
    return StvorEasyAPI.init({ appToken: token, userId });
}
