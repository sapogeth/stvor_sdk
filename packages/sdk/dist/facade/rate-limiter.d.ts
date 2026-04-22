/**
 * Rate Limiter for STVOR SDK
 *
 * Protects against DOS attacks:
 * - Token bucket algorithm
 * - Per-peer rate limits
 * - Backpressure handling
 * - Adaptive throttling
 *
 * Default: 1000 ops/sec per peer, 10000 ops/sec global
 */
export interface RateLimitConfig {
    /** Max operations per second (global) */
    globalRateLimit?: number;
    /** Max operations per second per peer */
    peerRateLimit?: number;
    /** Bucket size (refill capacity) */
    bucketSize?: number;
    /** Refill interval in ms */
    refillInterval?: number;
    /** Enable backpressure throttling */
    enableBackpressure?: boolean;
    /** Verbose logging */
    verbose?: boolean;
}
/**
 * Token bucket rate limiter
 */
export declare class RateLimiter {
    private globalBucket;
    private peerBuckets;
    private globalRateLimit;
    private peerRateLimit;
    private bucketSize;
    private refillInterval;
    private enableBackpressure;
    private verbose;
    constructor(config?: RateLimitConfig);
    /**
     * Refill tokens based on elapsed time
     */
    private refill;
    /**
     * Check if operation is allowed (global rate limit)
     */
    canProceed(cost?: number): boolean;
    /**
     * Check if operation is allowed for specific peer
     */
    canProceedForPeer(peerId: string, cost?: number): boolean;
    /**
     * Wait until operation is allowed (backpressure)
     */
    waitUntilAllowed(cost?: number): Promise<void>;
    /**
     * Wait until operation is allowed for peer
     */
    waitUntilAllowedForPeer(peerId: string, cost?: number): Promise<void>;
    /**
     * Get current rate limit status
     */
    getStatus(): {
        globalTokens: number;
        globalLimit: number;
        peerStats: Array<{
            peerId: string;
            tokens: number;
            limit: number;
        }>;
    };
    /**
     * Reset specific peer bucket
     */
    resetPeer(peerId: string): void;
    /**
     * Reset all peer buckets
     */
    resetAll(): void;
    /**
     * Calculate wait time until operation is allowed
     */
    getWaitTime(cost?: number): number;
    /**
     * Calculate wait time for peer
     */
    getWaitTimeForPeer(peerId: string, cost?: number): number;
    /**
     * Disable rate limiting temporarily
     */
    disable(): void;
    /**
     * Enable rate limiting
     */
    enable(): void;
}
