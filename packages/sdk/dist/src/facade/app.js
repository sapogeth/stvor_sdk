import { Errors, StvorError } from './errors.js';
import { RelayClient } from './relay-client.js';
import { CryptoSession } from './crypto.js';
/** Default timeout for waiting for recipient keys (ms) */
const DEFAULT_RECIPIENT_TIMEOUT = 10000;
/** Polling interval for key resolution (ms) */
const KEY_POLL_INTERVAL = 100;
export class StvorFacadeClient {
    constructor(userId, relay, defaultTimeout = DEFAULT_RECIPIENT_TIMEOUT) {
        this.userId = userId;
        this.relay = relay;
        this.defaultTimeout = defaultTimeout;
        this.handlers = [];
        this.userAvailableHandlers = [];
        this.knownPubKeys = new Map();
        this.pendingKeyResolvers = new Map();
        this.crypto = new CryptoSession();
        // listen relay messages
        this.relay.onMessage((m) => this.handleRelayMessage(m));
        // announce our public key
        this.relay.send({ type: 'announce', user: this.userId, pub: this.crypto.exportPublic() });
    }
    async handleRelayMessage(m) {
        if (!m || typeof m !== 'object')
            return;
        if (m.type === 'announce' && m.user && m.pub) {
            const wasKnown = this.knownPubKeys.has(m.user);
            this.knownPubKeys.set(m.user, m.pub);
            // Notify pending resolvers
            const resolvers = this.pendingKeyResolvers.get(m.user);
            if (resolvers) {
                resolvers.forEach(resolve => resolve());
                this.pendingKeyResolvers.delete(m.user);
            }
            // Notify user available handlers (only for new users)
            if (!wasKnown) {
                for (const h of this.userAvailableHandlers) {
                    try {
                        h(m.user);
                    }
                    catch { }
                }
            }
            return;
        }
        if (m.type === 'message' && m.to === this.userId && m.payload) {
            const payload = m.payload;
            const sender = m.from;
            try {
                const plain = this.crypto.decrypt(payload, payload.senderPub);
                const text = new TextDecoder().decode(plain);
                for (const h of this.handlers)
                    h(sender, text);
            }
            catch (e) {
                // ignore decryption errors
            }
        }
    }
    async internalInitialize() {
        // nothing for now; announce already sent in constructor
    }
    /**
     * Check if a user's public key is available locally
     */
    isUserAvailable(userId) {
        return this.knownPubKeys.has(userId);
    }
    /**
     * Get list of all known users (whose public keys we have)
     */
    getAvailableUsers() {
        return Array.from(this.knownPubKeys.keys()).filter(id => id !== this.userId);
    }
    /**
     * Wait until a specific user's public key becomes available.
     * This is the recommended way to ensure you can send messages.
     *
     * @param userId - The user to wait for
     * @param timeoutMs - Maximum time to wait (default: 10000ms)
     * @throws StvorError with RECIPIENT_TIMEOUT if timeout expires
     *
     * @example
     * ```typescript
     * await alice.waitForUser('bob@example.com');
     * await alice.send('bob@example.com', 'Hello!');
     * ```
     */
    async waitForUser(userId, timeoutMs = this.defaultTimeout) {
        // Already available
        if (this.knownPubKeys.has(userId)) {
            return;
        }
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                // Remove from pending
                const resolvers = this.pendingKeyResolvers.get(userId);
                if (resolvers) {
                    const idx = resolvers.indexOf(resolveHandler);
                    if (idx >= 0)
                        resolvers.splice(idx, 1);
                    if (resolvers.length === 0)
                        this.pendingKeyResolvers.delete(userId);
                }
                reject(new StvorError(Errors.RECIPIENT_TIMEOUT, `Timed out waiting for user "${userId}" after ${timeoutMs}ms. ` +
                    `The user may not be connected to the relay. ` +
                    `Ensure both parties are online before sending messages.`, 'Verify the recipient is connected, or increase timeout', true));
            }, timeoutMs);
            const resolveHandler = () => {
                clearTimeout(timeout);
                resolve();
            };
            // Add to pending resolvers
            if (!this.pendingKeyResolvers.has(userId)) {
                this.pendingKeyResolvers.set(userId, []);
            }
            this.pendingKeyResolvers.get(userId).push(resolveHandler);
        });
    }
    /**
     * Send an encrypted message to a recipient.
     *
     * If the recipient's public key is not yet available, this method will
     * automatically wait up to `timeoutMs` for the key to arrive via the relay.
     *
     * @param recipientId - The recipient's user ID
     * @param content - Message content (string or Uint8Array)
     * @param options - Optional: { timeout: number, waitForRecipient: boolean }
     * @throws StvorError with RECIPIENT_TIMEOUT if recipient key doesn't arrive in time
     *
     * @example
     * ```typescript
     * // Auto-waits for recipient (recommended)
     * await alice.send('bob@example.com', 'Hello!');
     *
     * // Skip waiting (throws immediately if not available)
     * await alice.send('bob@example.com', 'Hello!', { waitForRecipient: false });
     * ```
     */
    async send(recipientId, content, options) {
        const { timeout = this.defaultTimeout, waitForRecipient = true } = options ?? {};
        // Validate inputs
        if (!recipientId || typeof recipientId !== 'string' || recipientId.trim().length === 0) {
            throw new StvorError(Errors.INVALID_INPUT, 'Recipient ID must be a non-empty string', 'Provide a valid user ID for the recipient');
        }
        if (recipientId === this.userId) {
            throw new StvorError(Errors.INVALID_INPUT, 'Cannot send message to yourself', 'Provide a different recipient ID');
        }
        if (!content || (typeof content === 'string' && content.length === 0) || (content instanceof Uint8Array && content.length === 0)) {
            throw new StvorError(Errors.INVALID_INPUT, 'Message content cannot be empty', 'Provide message content to send');
        }
        // Try to resolve recipient key
        let recipientPub = this.knownPubKeys.get(recipientId);
        if (!recipientPub) {
            if (!waitForRecipient) {
                throw new StvorError(Errors.RECIPIENT_NOT_FOUND, `Recipient "${recipientId}" is not available. ` +
                    `Their public key has not been announced to the relay. ` +
                    `Use waitForUser() or enable waitForRecipient option.`, 'Call waitForUser(recipientId) before sending, or ensure recipient is connected', false);
            }
            // Wait for recipient key with timeout
            await this.waitForUser(recipientId, timeout);
            recipientPub = this.knownPubKeys.get(recipientId);
            if (!recipientPub) {
                // Should not happen, but safety check
                throw new StvorError(Errors.RECIPIENT_NOT_FOUND, `Recipient "${recipientId}" key resolution failed unexpectedly.`, 'This is an internal error, please report it', false);
            }
        }
        try {
            const plain = typeof content === 'string' ? new TextEncoder().encode(content) : content;
            const payload = this.crypto.encrypt(plain, recipientPub);
            const msg = { type: 'message', to: recipientId, from: this.userId, payload };
            this.relay.send(msg);
        }
        catch (e) {
            throw new StvorError(Errors.ENCRYPTION_FAILED, `Failed to encrypt message: ${e?.message || 'unknown error'}`, 'Ensure recipient public key is valid and your key is not corrupted');
        }
    }
    /**
     * Register a handler for incoming messages
     */
    onMessage(handler) {
        this.handlers.push(handler);
        return () => {
            const i = this.handlers.indexOf(handler);
            if (i >= 0)
                this.handlers.splice(i, 1);
        };
    }
    /**
     * Register a handler that fires when a new user becomes available.
     * This is triggered when we receive a user's public key announcement.
     *
     * **Edge-triggered**: Fires only ONCE per user, on first key discovery.
     * Will NOT fire again if user reconnects with same identity.
     *
     * @example
     * ```typescript
     * client.onUserAvailable((userId) => {
     *   console.log(`${userId} is now available for messaging`);
     * });
     * ```
     */
    onUserAvailable(handler) {
        this.userAvailableHandlers.push(handler);
        return () => {
            const i = this.userAvailableHandlers.indexOf(handler);
            if (i >= 0)
                this.userAvailableHandlers.splice(i, 1);
        };
    }
    /**
     * Encrypt a message for custom transport
     * Use this when you want to deliver encrypted messages yourself (Socket.io, HTTP, custom protocol)
     *
     * @example
     * ```typescript
     * // Encrypt manually, send via Socket.io
     * const encrypted = await client.encryptMessage('alice', 'Hello!');
     * socket.emit('message', encrypted);
     *
     * // Recipient receives and decrypts
     * socket.on('message', async (encrypted) => {
     *   const decrypted = await bobClient.decryptMessage(encrypted);
     *   console.log('Got:', decrypted); // 'Hello!'
     * });
     * ```
     */
    async encryptMessage(recipientId, content) {
        // Validate inputs
        if (!recipientId || typeof recipientId !== 'string' || recipientId.trim().length === 0) {
            throw new StvorError(Errors.INVALID_INPUT, 'Recipient ID must be a non-empty string');
        }
        if (recipientId === this.userId) {
            throw new StvorError(Errors.INVALID_INPUT, 'Cannot encrypt message to yourself');
        }
        // Get recipient's public key
        let recipientPub = this.knownPubKeys.get(recipientId);
        if (!recipientPub) {
            throw new StvorError(Errors.RECIPIENT_NOT_FOUND, `Recipient "${recipientId}" public key not available. Call waitForUser() first.`);
        }
        try {
            const plain = typeof content === 'string' ? new TextEncoder().encode(content) : content;
            const encrypted = this.crypto.encrypt(plain, recipientPub);
            return encrypted;
        }
        catch (e) {
            throw new StvorError(Errors.ENCRYPTION_FAILED, `Failed to encrypt message: ${e?.message || 'unknown error'}`);
        }
    }
    /**
     * Decrypt a message from custom transport
     * Use this to decrypt messages received outside the relay (Socket.io, HTTP, custom protocol)
     *
     * @example
     * ```typescript
     * const decrypted = await client.decryptMessage(encryptedMessage);
     * console.log(decrypted); // 'Hello!'
     * ```
     */
    async decryptMessage(encrypted) {
        if (!encrypted || typeof encrypted !== 'object') {
            throw new StvorError(Errors.INVALID_INPUT, 'Invalid encrypted message format');
        }
        try {
            const plain = this.crypto.decrypt(encrypted, encrypted.senderPub);
            // Try to decode as UTF-8 text, fallback to bytes
            try {
                return new TextDecoder().decode(plain);
            }
            catch {
                return plain;
            }
        }
        catch (e) {
            throw new StvorError(Errors.MESSAGE_INTEGRITY_FAILED, `Failed to decrypt message: ${e?.message || 'authentication tag verification failed'}`);
        }
    }
    /**
     * Get your public key for sharing with others
     * Use this when establishing peer-to-peer communication
     *
     * @example
     * ```typescript
     * const myPubKey = client.getPublicKey();
     * // Share with peers via QR code, API, or other means
     * sendToPeer({ userId: 'alice', publicKey: myPubKey });
     * ```
     */
    getPublicKey() {
        return this.crypto.exportPublic();
    }
    /**
     * Manually add a known peer's public key
     * Use this for peer-to-peer or custom key exchange scenarios
     *
     * @example
     * ```typescript
     * // Peer shares their key via QR code or API
     * client.addPeerKey('alice', 'base64encodedkey...');
     *
     * // Now you can encrypt messages to alice without relay
     * const encrypted = await client.encryptMessage('alice', 'Hello!');
     * ```
     */
    addPeerKey(userId, publicKeyBase64) {
        if (!userId || typeof userId !== 'string') {
            throw new StvorError(Errors.INVALID_INPUT, 'User ID must be a non-empty string');
        }
        if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
            throw new StvorError(Errors.INVALID_INPUT, 'Public key must be a base64 string');
        }
        this.knownPubKeys.set(userId, publicKeyBase64);
        // Trigger user available handlers
        for (const h of this.userAvailableHandlers) {
            try {
                h(userId);
            }
            catch { }
        }
    }
}
export class StvorApp {
    constructor(config) {
        this.config = config;
        this.clients = new Map();
    }
    async connect(userId) {
        const existing = this.clients.get(userId);
        if (existing)
            return existing;
        const relay = new RelayClient(this.config.relayUrl ?? 'wss://stvor.xyz/relay', this.config.appToken, this.config.timeout ?? 10000);
        // Wait for relay handshake - throws if API key is invalid
        await relay.init();
        const client = new StvorFacadeClient(userId, relay, this.config.timeout ?? 10000);
        await client.internalInitialize();
        this.clients.set(userId, client);
        return client;
    }
    /**
     * Get a connected client by user ID
     */
    getClient(userId) {
        return this.clients.get(userId);
    }
    /**
     * Check if a user is connected locally
     */
    isConnected(userId) {
        return this.clients.has(userId);
    }
    async disconnect(userId) {
        if (userId) {
            const client = this.clients.get(userId);
            if (client) {
                // Unsubscribe from all handlers
                this.clients.delete(userId);
            }
            return;
        }
        this.clients.clear();
    }
    /**
     * Get connection statistics
     */
    getStats() {
        return {
            connectedClients: this.clients.size,
            clientIds: Array.from(this.clients.keys()),
        };
    }
}
export async function init(config) {
    if (!config.appToken.startsWith('stvor_')) {
        throw new StvorError(Errors.INVALID_APP_TOKEN, 'Invalid app token');
    }
    return new StvorApp(config);
}
// Alias for createApp
export const createApp = init;
export const Stvor = {
    init,
    createApp,
};
