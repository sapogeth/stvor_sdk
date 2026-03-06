/**
 * Redis-based Replay Protection Cache for SDK
 * Production-ready replay protection for clustered client deployments
 *
 * Use case: When running multiple instances of the same app (e.g., web app with
 * multiple tabs, mobile app with background sync, or server-side SDK usage)
 */
/**
 * Redis-based replay cache implementation
 * Works with any Redis client (ioris, node-redis, etc.)
 */
export class RedisReplayCache {
    constructor(config) {
        this.client = config.client;
        this.keyPrefix = config.keyPrefix || 'stvor:replay:';
        this.ttlSeconds = config.ttlSeconds || 300;
    }
    /**
     * Build Redis key for nonce
     */
    buildKey(userId, nonce) {
        return `${this.keyPrefix}${userId}:${nonce}`;
    }
    /**
     * Add nonce to cache
     */
    async addNonce(userId, nonce, timestamp) {
        const key = this.buildKey(userId, nonce);
        await this.client.setEx(key, this.ttlSeconds, String(timestamp));
    }
    /**
     * Check if nonce exists in cache
     */
    async hasNonce(userId, nonce) {
        const key = this.buildKey(userId, nonce);
        const result = await this.client.exists(key);
        return result === 1;
    }
    /**
     * Cleanup expired nonces
     * Note: With Redis SETEX, keys auto-expire, so this is a no-op
     */
    async cleanup(userId, maxAge) {
        // Redis handles TTL automatically via SETEX
        // This is kept for interface compatibility but returns 0
        return 0;
    }
    /**
     * Get cache statistics
     */
    async getStats() {
        try {
            const keys = await this.client.keys(`${this.keyPrefix}*`);
            return { size: keys.length };
        }
        catch {
            return { size: 0 };
        }
    }
}
