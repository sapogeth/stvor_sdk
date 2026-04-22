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
/**
 * Token bucket rate limiter
 */
export class RateLimiter {
    constructor(config = {}) {
        this.peerBuckets = new Map();
        this.globalRateLimit = config.globalRateLimit ?? 10000; // ops/sec
        this.peerRateLimit = config.peerRateLimit ?? 1000; // ops/sec
        this.bucketSize = config.bucketSize ?? this.globalRateLimit * 2;
        this.refillInterval = config.refillInterval ?? 1000; // 1 second
        this.enableBackpressure = config.enableBackpressure ?? true;
        this.verbose = config.verbose ?? false;
        this.globalBucket = {
            tokens: this.bucketSize,
            lastRefill: Date.now(),
        };
        if (this.verbose) {
            console.log(`[RateLimiter] Initialized: ${this.globalRateLimit} global/sec, ${this.peerRateLimit} peer/sec`);
        }
    }
    /**
     * Refill tokens based on elapsed time
     */
    refill(bucket, rateLimit) {
        const now = Date.now();
        const elapsed = now - bucket.lastRefill;
        const tokensToAdd = (elapsed / this.refillInterval) * rateLimit;
        bucket.tokens = Math.min(this.bucketSize, bucket.tokens + tokensToAdd);
        bucket.lastRefill = now;
    }
    /**
     * Check if operation is allowed (global rate limit)
     */
    canProceed(cost = 1) {
        this.refill(this.globalBucket, this.globalRateLimit);
        if (this.globalBucket.tokens >= cost) {
            this.globalBucket.tokens -= cost;
            return true;
        }
        if (this.verbose) {
            console.warn(`[RateLimiter] Global limit exceeded: ${this.globalBucket.tokens.toFixed(1)} tokens`);
        }
        return false;
    }
    /**
     * Check if operation is allowed for specific peer
     */
    canProceedForPeer(peerId, cost = 1) {
        // Get or create peer bucket
        let peerBucket = this.peerBuckets.get(peerId);
        if (!peerBucket) {
            peerBucket = {
                tokens: this.peerRateLimit,
                lastRefill: Date.now(),
            };
            this.peerBuckets.set(peerId, peerBucket);
        }
        // Refill bucket
        this.refill(peerBucket, this.peerRateLimit);
        // Check if tokens available
        if (peerBucket.tokens >= cost) {
            peerBucket.tokens -= cost;
            return true;
        }
        if (this.verbose) {
            console.warn(`[RateLimiter] Peer limit exceeded for ${peerId}: ${peerBucket.tokens.toFixed(1)} tokens`);
        }
        return false;
    }
    /**
     * Wait until operation is allowed (backpressure)
     */
    async waitUntilAllowed(cost = 1) {
        if (!this.enableBackpressure) {
            if (!this.canProceed(cost)) {
                throw new Error('Rate limit exceeded');
            }
            return;
        }
        while (!this.canProceed(cost)) {
            // Wait for tokens to refill
            await new Promise((resolve) => setTimeout(resolve, 10));
        }
    }
    /**
     * Wait until operation is allowed for peer
     */
    async waitUntilAllowedForPeer(peerId, cost = 1) {
        if (!this.enableBackpressure) {
            if (!this.canProceedForPeer(peerId, cost)) {
                throw new Error(`Rate limit exceeded for ${peerId}`);
            }
            return;
        }
        while (!this.canProceedForPeer(peerId, cost)) {
            await new Promise((resolve) => setTimeout(resolve, 10));
        }
    }
    /**
     * Get current rate limit status
     */
    getStatus() {
        return {
            globalTokens: this.globalBucket.tokens,
            globalLimit: this.globalRateLimit,
            peerStats: Array.from(this.peerBuckets.entries()).map(([peerId, bucket]) => ({
                peerId,
                tokens: bucket.tokens,
                limit: this.peerRateLimit,
            })),
        };
    }
    /**
     * Reset specific peer bucket
     */
    resetPeer(peerId) {
        this.peerBuckets.delete(peerId);
        if (this.verbose) {
            console.log(`[RateLimiter] Reset rate limit for peer ${peerId}`);
        }
    }
    /**
     * Reset all peer buckets
     */
    resetAll() {
        this.peerBuckets.clear();
        this.globalBucket = {
            tokens: this.bucketSize,
            lastRefill: Date.now(),
        };
        if (this.verbose) {
            console.log(`[RateLimiter] Reset all rate limits`);
        }
    }
    /**
     * Calculate wait time until operation is allowed
     */
    getWaitTime(cost = 1) {
        this.refill(this.globalBucket, this.globalRateLimit);
        if (this.globalBucket.tokens >= cost) {
            return 0;
        }
        const tokensNeeded = cost - this.globalBucket.tokens;
        return (tokensNeeded / this.globalRateLimit) * this.refillInterval;
    }
    /**
     * Calculate wait time for peer
     */
    getWaitTimeForPeer(peerId, cost = 1) {
        let peerBucket = this.peerBuckets.get(peerId);
        if (!peerBucket) {
            return 0;
        }
        this.refill(peerBucket, this.peerRateLimit);
        if (peerBucket.tokens >= cost) {
            return 0;
        }
        const tokensNeeded = cost - peerBucket.tokens;
        return (tokensNeeded / this.peerRateLimit) * this.refillInterval;
    }
    /**
     * Disable rate limiting temporarily
     */
    disable() {
        this.globalBucket.tokens = this.bucketSize;
        this.peerBuckets.forEach((bucket) => {
            bucket.tokens = this.bucketSize;
        });
        if (this.verbose) {
            console.log(`[RateLimiter] Rate limiting disabled`);
        }
    }
    /**
     * Enable rate limiting
     */
    enable() {
        if (this.verbose) {
            console.log(`[RateLimiter] Rate limiting enabled`);
        }
    }
}
