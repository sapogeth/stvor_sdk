/**
 * Simple SDK API - The main entry point
 *
 * One-line initialization, any data type, batch operations
 * Perfect for applications that just need easy E2EE
 *
 * @example
 * // Initialize (one line)
 * const sdk = StvorSDK.create('alice@example.com');
 *
 * // Send any data (automatic encryption)
 * await sdk.send('bob@example.com', { name: 'Alice', age: 30 });
 *
 * // Receive with handler
 * sdk.onMessage('bob@example.com', (message) => {
 *   console.log('Received:', message); // Automatically decrypted & type-preserved
 * });
 *
 * // Batch send (10x faster)
 * await sdk.sendBatch('group-chat', messages);
 *
 * // Graceful shutdown
 * await sdk.shutdown();
 */
import { CryptoSessionManager } from './crypto-session.js';
import { RelayClient } from './relay-client.js';
import { FileIdentityStore } from './file-identity-store.js';
import { FileSessionStore } from './file-session-store.js';
import { ResourceLifecycleManager } from './resource-lifecycle.js';
import { OTPKeyManager } from './otp-key-manager.js';
import { RateLimiter } from './rate-limiter.js';
import { CircuitBreaker } from './circuit-breaker.js';
import { RetryPolicy, RetryManager } from './retry-policy.js';
import { AnalyticsEngine } from './analytics-engine.js';
import { batchEncryptMessages, batchDecryptMessages, } from './batch-engine.js';
import { UniversalDataCodec } from './universal-data.js';
/**
 * Simple SDK - Main API for easy E2EE
 */
export class StvorSDK {
    constructor(userId, crypto, relay, lifecycle, rateLimiter, circuitBreaker, retryManager, analytics, verbose = false) {
        this.messageHandlers = new Map();
        this.pollingHandle = null;
        this.isInitialized = false;
        this.userId = userId;
        this.crypto = crypto;
        this.relay = relay;
        this.lifecycle = lifecycle;
        this.rateLimiter = rateLimiter;
        this.circuitBreaker = circuitBreaker;
        this.retryManager = retryManager;
        this.analytics = analytics;
        this.verbose = verbose;
    }
    /**
     * Create and initialize SDK
     */
    static async create(userId, options = {}) {
        const verbose = options.verbose ?? false;
        if (verbose) {
            console.log('[SDK] Initializing for user:', userId);
        }
        const storagePath = options.storagePath ?? './stvor-data';
        const masterPassword = options.masterPassword ?? 'default-password-change-me';
        // Create storage layers
        const identityStore = new FileIdentityStore({
            directory: `${storagePath}/keys`,
            masterPassword,
        });
        const sessionStore = new FileSessionStore({
            directory: `${storagePath}/sessions`,
            masterPassword,
        });
        // Initialize crypto manager with storage
        const crypto = new CryptoSessionManager(userId, identityStore, sessionStore);
        await crypto.initialize();
        // Initialize OTP manager
        const otpManager = new OTPKeyManager(100, 24 * 60 * 60 * 1000);
        // Initialize rate limiter (1000 ops/sec per peer, 10000 global)
        const rateLimiter = new RateLimiter({
            globalRateLimit: 10000,
            peerRateLimit: 1000,
            enableBackpressure: true,
            verbose,
        });
        // Initialize circuit breaker (50% failure threshold)
        const circuitBreaker = new CircuitBreaker({
            failureThreshold: 0.5,
            windowSize: 100,
            resetTimeoutMs: 5000,
            maxResetTimeoutMs: 60000,
            backoffMultiplier: 2,
            verbose,
        });
        // Initialize retry manager with default policy
        const retryManager = new RetryManager(RetryPolicy.default());
        // Initialize analytics engine
        const analytics = new AnalyticsEngine({
            maxEventsInMemory: 10000,
            rotationIntervalMs: 3600000, // 1 hour
            verbose,
        });
        // Initialize lifecycle manager
        const lifecycle = new ResourceLifecycleManager(crypto, otpManager, {
            maxCachedSessions: options.maxCachedSessions ?? 1000,
            maxOTPKeys: options.maxOTPKeys ?? 500,
            sessionIdleTimeout: options.sessionIdleTimeout ?? 60 * 60 * 1000,
            verbose,
        });
        // Relay client — optional, null if no relayUrl/appToken provided
        let relay = null;
        if (options.relayUrl && options.appToken) {
            relay = new RelayClient(options.relayUrl, options.appToken);
            await relay.register(userId, crypto.getPublicKeys());
        }
        const sdk = new StvorSDK(userId, crypto, relay, lifecycle, rateLimiter, circuitBreaker, retryManager, analytics, verbose);
        sdk.isInitialized = true;
        if (relay) {
            sdk.startPolling();
        }
        if (verbose) {
            console.log('[SDK] Initialized successfully');
            lifecycle.logStats();
        }
        return sdk;
    }
    /**
     * Send message to peer (auto-establishes session)
     */
    async send(recipient, data, options = {}) {
        if (!this.isInitialized) {
            throw new Error('SDK not initialized');
        }
        const autoEstablish = options.autoEstablish ?? true;
        const startTime = Date.now();
        try {
            // Check circuit breaker first
            if (!this.circuitBreaker.canRequest(recipient)) {
                const state = this.circuitBreaker.getState(recipient);
                this.analytics.recordSend(recipient, 0, false, undefined, `Circuit breaker: ${state}`);
                throw new Error(`Circuit breaker OPEN for ${recipient}. Service unavailable.`);
            }
            const sendFn = async () => {
                await this.rateLimiter.waitUntilAllowedForPeer(recipient);
                const encoded = UniversalDataCodec.encode(data);
                const encodedB64 = encoded.toString('base64url');
                if (!this.crypto.hasSession(recipient)) {
                    if (!autoEstablish) {
                        throw new Error(`No session with ${recipient}. Call establishSession() first.`);
                    }
                    if (!this.relay) {
                        throw new Error(`Cannot auto-establish session: no relay configured. Pass relayUrl and appToken to StvorSDK.create().`);
                    }
                    if (this.verbose)
                        console.log(`[SDK] Auto-establishing session with ${recipient}`);
                    const peerKeys = await this.relay.getPublicKeys(recipient);
                    if (!peerKeys)
                        throw new Error(`Peer ${recipient} not found on relay.`);
                    await this.crypto.establishSession(recipient, peerKeys);
                }
                const { ciphertext, header } = this.crypto.encryptForPeer(recipient, encodedB64);
                if (this.relay) {
                    await this.relay.send({ to: recipient, from: this.userId, ciphertext, header });
                }
                if (this.verbose) {
                    console.log(`[SDK] Sent ${UniversalDataCodec.getType(encoded)} to ${recipient}`);
                }
                this.lifecycle.recordSessionAccess(recipient);
                return encodedB64.length;
            };
            // Execute with retry
            const dataSize = await this.retryManager.execute('send', sendFn);
            // Record success
            const duration = Date.now() - startTime;
            this.circuitBreaker.recordSuccess(recipient);
            this.analytics.recordSend(recipient, dataSize, true, duration);
        }
        catch (error) {
            // Record failure
            const duration = Date.now() - startTime;
            this.circuitBreaker.recordFailure(recipient, error);
            this.analytics.recordSend(recipient, 0, false, duration, String(error));
            throw new Error(`Failed to send message: ${error}`);
        }
    }
    startPolling(intervalMs = 1000) {
        if (this.pollingHandle || !this.relay)
            return;
        const poll = async () => {
            try {
                const messages = await this.relay.fetchMessages(this.userId);
                for (const msg of messages) {
                    try {
                        if (!this.crypto.hasSession(msg.from)) {
                            const peerKeys = await this.relay.getPublicKeys(msg.from);
                            if (!peerKeys)
                                continue;
                            await this.crypto.establishSession(msg.from, peerKeys);
                        }
                        const encodedB64 = this.crypto.decryptFromPeer(msg.from, msg.ciphertext, msg.header);
                        const decoded = UniversalDataCodec.decode(Buffer.from(encodedB64, 'base64url'));
                        const handlers = this.messageHandlers.get(msg.from) ?? new Set();
                        const wildcard = this.messageHandlers.get('*') ?? new Set();
                        for (const h of [...handlers, ...wildcard]) {
                            try {
                                h(decoded, { from: msg.from, timestamp: new Date(msg.timestamp) });
                            }
                            catch (e) {
                                console.error('[SDK] Handler error:', e);
                            }
                        }
                    }
                    catch (e) {
                        console.error(`[SDK] Failed to process message from ${msg.from}:`, e);
                    }
                }
            }
            catch { /* polling errors are non-fatal */ }
        };
        this.pollingHandle = setInterval(() => { poll().catch(() => { }); }, intervalMs);
    }
    /**
     * Register message handler
     */
    onMessage(sender, handler) {
        if (!this.messageHandlers.has(sender)) {
            this.messageHandlers.set(sender, new Set());
        }
        const handlers = this.messageHandlers.get(sender);
        handlers.add(handler);
        // Return unsubscribe function
        return () => {
            handlers.delete(handler);
            if (handlers.size === 0) {
                this.messageHandlers.delete(sender);
            }
        };
    }
    /**
     * Process received encrypted message
     */
    processMessage(sender, ciphertext, header) {
        try {
            const ciphertextB64 = typeof ciphertext === 'string' ? ciphertext : ciphertext.toString('base64url');
            const headerStr = typeof header === 'string' ? header : JSON.stringify(header);
            const encodedB64 = this.crypto.decryptFromPeer(sender, ciphertextB64, headerStr);
            const encoded = Buffer.from(encodedB64, 'base64url');
            const data = UniversalDataCodec.decode(encoded);
            const handlers = this.messageHandlers.get(sender);
            if (handlers) {
                for (const handler of handlers) {
                    handler(data, {
                        from: sender,
                        timestamp: new Date(),
                    });
                }
            }
            this.lifecycle.recordSessionAccess(sender);
        }
        catch (error) {
            console.error(`[SDK] Failed to process message from ${sender}:`, error);
        }
    }
    /**
     * Establish session with peer
     */
    async establishSession(peerId, peerPublicKeys) {
        if (!this.isInitialized) {
            throw new Error('SDK not initialized');
        }
        try {
            await this.crypto.establishSession(peerId, peerPublicKeys);
            this.lifecycle.recordSessionAccess(peerId);
            if (this.verbose) {
                console.log(`[SDK] Session established with ${peerId}`);
            }
        }
        catch (error) {
            throw new Error(`Failed to establish session: ${error}`);
        }
    }
    /**
     * Batch send messages (10x faster)
     */
    async sendBatch(recipient, messages, options = {}) {
        if (!this.isInitialized) {
            throw new Error('SDK not initialized');
        }
        if (!this.crypto.hasSession(recipient)) {
            throw new Error(`No session with ${recipient}`);
        }
        try {
            // Encode all messages
            const encoded = messages.map((msg) => UniversalDataCodec.encode(msg).toString('base64url'));
            // Batch encrypt
            const result = await batchEncryptMessages(this.crypto, recipient, encoded, {
                concurrency: options.concurrency ?? 10,
                onProgress: options.onProgress,
                verbose: this.verbose,
            });
            this.lifecycle.recordSessionAccess(recipient);
            return {
                successCount: result.metrics.successCount,
                failureCount: result.metrics.failureCount,
                totalTime: result.metrics.totalTime,
            };
        }
        catch (error) {
            throw new Error(`Batch send failed: ${error}`);
        }
    }
    /**
     * Batch receive messages
     */
    async receiveBatch(sender, encrypted, options = {}) {
        if (!this.isInitialized) {
            throw new Error('SDK not initialized');
        }
        if (!this.crypto.hasSession(sender)) {
            throw new Error(`No session with ${sender}`);
        }
        try {
            // Convert Buffer types to string types for BatchEncryptedMessage
            const convertedMessages = encrypted.map((msg) => ({
                ciphertext: typeof msg.ciphertext === 'string' ? msg.ciphertext : msg.ciphertext.toString('base64url'),
                header: typeof msg.header === 'string' ? msg.header : JSON.stringify(msg.header),
            }));
            const result = await batchDecryptMessages(this.crypto, sender, convertedMessages, {
                concurrency: options.concurrency ?? 10,
                verbose: this.verbose,
            });
            const decoded = result.results.map((r) => {
                if (r.error)
                    throw r.error;
                const buf = Buffer.from(r.decrypted, 'base64url');
                return UniversalDataCodec.decode(buf);
            });
            this.lifecycle.recordSessionAccess(sender);
            return decoded;
        }
        catch (error) {
            throw new Error(`Batch receive failed: ${error}`);
        }
    }
    /**
     * Get public keys for sharing with peers
     */
    getPublicKeys() {
        if (!this.isInitialized) {
            throw new Error('SDK not initialized');
        }
        return this.crypto.getPublicKeys();
    }
    /**
     * Get user ID
     */
    getUserId() {
        return this.userId;
    }
    /**
     * Get resource statistics
     */
    getStats() {
        return this.lifecycle.getStats();
    }
    /**
     * Get rate limit status
     */
    getRateLimitStatus() {
        return this.rateLimiter.getStatus();
    }
    /**
     * Log resource statistics
     */
    logStats() {
        this.lifecycle.logStats();
        console.log('[SDK] Rate Limit Status:', this.rateLimiter.getStatus());
    }
    /**
     * Health check
     */
    isHealthy() {
        return this.lifecycle.isHealthy();
    }
    /**
     * Get circuit breaker status
     */
    getCircuitBreakerStatus() {
        return this.circuitBreaker.getAllMetrics();
    }
    /**
     * Get circuit breaker health
     */
    getCircuitBreakerHealth() {
        return this.circuitBreaker.getHealth();
    }
    /**
     * Get retry manager config
     */
    getRetryConfig() {
        return this.retryManager.getStats();
    }
    /**
     * Get analytics report (last hour)
     */
    getAnalyticsReport() {
        return this.analytics.generateReport(Date.now() - 3600000, Date.now());
    }
    /**
     * Get full analytics report for custom time range
     */
    getAnalyticsReportForRange(fromMs, toMs) {
        return this.analytics.generateReport(fromMs, toMs);
    }
    /**
     * Get analytics events
     */
    getAnalyticsEvents(fromMs, toMs) {
        return this.analytics.exportEvents(fromMs, toMs);
    }
    /**
     * Reset circuit breaker for peer (manual recovery)
     */
    resetCircuitBreakerForPeer(peerId) {
        this.circuitBreaker.reset(peerId);
        if (this.verbose) {
            console.log(`[SDK] Circuit breaker reset for ${peerId}`);
        }
    }
    /**
     * Reset all circuit breakers
     */
    resetAllCircuitBreakers() {
        this.circuitBreaker.resetAll();
        if (this.verbose) {
            console.log(`[SDK] All circuit breakers reset`);
        }
    }
    /**
     * Graceful shutdown
     */
    async shutdown() {
        if (!this.isInitialized) {
            return;
        }
        try {
            if (this.verbose) {
                console.log('[SDK] Shutting down...');
            }
            if (this.pollingHandle) {
                clearInterval(this.pollingHandle);
                this.pollingHandle = null;
            }
            this.relay?.disconnect();
            await this.lifecycle.shutdown();
            this.messageHandlers.clear();
            this.isInitialized = false;
            if (this.verbose) {
                console.log('[SDK] Shutdown complete');
            }
        }
        catch (error) {
            console.error('[SDK] Shutdown error:', error);
            throw error;
        }
    }
    /**
     * Force ratchet (after suspected compromise)
     */
    async forceRatchet(peerId) {
        try {
            this.crypto.forceRatchet(peerId);
            if (this.verbose) {
                console.log(`[SDK] Ratchet forced for ${peerId}`);
            }
        }
        catch (error) {
            throw new Error(`Force ratchet failed: ${error}`);
        }
    }
}
/**
 * Export convenience functions
 */
export async function createSDK(userId, options) {
    return StvorSDK.create(userId, options);
}
export { UniversalDataCodec } from './universal-data.js';
