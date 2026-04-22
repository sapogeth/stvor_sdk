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
import { StvorData } from './universal-data.js';
export interface SimpleSDKOptions {
    storagePath?: string;
    masterPassword?: string;
    relayUrl?: string;
    appToken?: string;
    verbose?: boolean;
    maxCachedSessions?: number;
    maxOTPKeys?: number;
    sessionIdleTimeout?: number;
}
export interface MessageHandler {
    (data: StvorData, metadata: {
        from: string;
        timestamp: Date;
    }): void;
}
/**
 * Simple SDK - Main API for easy E2EE
 */
export declare class StvorSDK {
    private crypto;
    private relay;
    private lifecycle;
    private rateLimiter;
    private circuitBreaker;
    private retryManager;
    private analytics;
    private messageHandlers;
    private pollingHandle;
    private isInitialized;
    private userId;
    private verbose;
    private constructor();
    /**
     * Create and initialize SDK
     */
    static create(userId: string, options?: SimpleSDKOptions): Promise<StvorSDK>;
    /**
     * Send message to peer (auto-establishes session)
     */
    send(recipient: string, data: StvorData, options?: {
        timeout?: number;
        autoEstablish?: boolean;
    }): Promise<void>;
    startPolling(intervalMs?: number): void;
    /**
     * Register message handler
     */
    onMessage(sender: string, handler: MessageHandler): () => void;
    /**
     * Process received encrypted message
     */
    processMessage(sender: string, ciphertext: Buffer, header: any): void;
    /**
     * Establish session with peer
     */
    establishSession(peerId: string, peerPublicKeys: any): Promise<void>;
    /**
     * Batch send messages (10x faster)
     */
    sendBatch(recipient: string, messages: StvorData[], options?: {
        concurrency?: number;
        onProgress?: (current: number, total: number) => void;
    }): Promise<{
        successCount: number;
        failureCount: number;
        totalTime: number;
    }>;
    /**
     * Batch receive messages
     */
    receiveBatch(sender: string, encrypted: Array<{
        ciphertext: Buffer;
        header: any;
    }>, options?: {
        concurrency?: number;
    }): Promise<StvorData[]>;
    /**
     * Get public keys for sharing with peers
     */
    getPublicKeys(): any;
    /**
     * Get user ID
     */
    getUserId(): string;
    /**
     * Get resource statistics
     */
    getStats(): import("./resource-lifecycle.js").ResourceStats;
    /**
     * Get rate limit status
     */
    getRateLimitStatus(): {
        globalTokens: number;
        globalLimit: number;
        peerStats: Array<{
            peerId: string;
            tokens: number;
            limit: number;
        }>;
    };
    /**
     * Log resource statistics
     */
    logStats(): void;
    /**
     * Health check
     */
    isHealthy(): boolean;
    /**
     * Get circuit breaker status
     */
    getCircuitBreakerStatus(): Record<string, any>;
    /**
     * Get circuit breaker health
     */
    getCircuitBreakerHealth(): {
        healthy: string[];
        degraded: string[];
        failed: string[];
    };
    /**
     * Get retry manager config
     */
    getRetryConfig(): {
        defaultPolicy: any;
        registeredPolicies: number;
        policies: Record<string, any>;
    };
    /**
     * Get analytics report (last hour)
     */
    getAnalyticsReport(): import("./analytics-engine.js").AnalyticsReport;
    /**
     * Get full analytics report for custom time range
     */
    getAnalyticsReportForRange(fromMs: number, toMs: number): import("./analytics-engine.js").AnalyticsReport;
    /**
     * Get analytics events
     */
    getAnalyticsEvents(fromMs?: number, toMs?: number): import("./analytics-engine.js").AnalyticsEvent[];
    /**
     * Reset circuit breaker for peer (manual recovery)
     */
    resetCircuitBreakerForPeer(peerId: string): void;
    /**
     * Reset all circuit breakers
     */
    resetAllCircuitBreakers(): void;
    /**
     * Graceful shutdown
     */
    shutdown(): Promise<void>;
    /**
     * Force ratchet (after suspected compromise)
     */
    forceRatchet(peerId: string): Promise<void>;
}
/**
 * Export convenience functions
 */
export declare function createSDK(userId: string, options?: SimpleSDKOptions): Promise<StvorSDK>;
export { UniversalDataCodec } from './universal-data.js';
export type { StvorData } from './universal-data.js';
