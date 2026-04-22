/**
 * Redis-based Replay Protection Cache
 * Production-ready replay protection for clustered deployments
 */
import Redis from 'ioredis';
export class RedisReplayCache {
    constructor(config) {
        this.keyPrefix = config.keyPrefix || 'stvor:replay:';
        this.ttlSeconds = config.ttlSeconds || 300;
        this.client = new Redis(config.url, {
            retryStrategy: (times) => {
                if (times > 10) {
                    console.error('[RedisReplay] Max reconnection attempts reached');
                    return null;
                }
                return Math.min(times * 100, 3000);
            },
            maxRetriesPerRequest: 3,
        });
        this.client.on('error', (err) => {
            console.error('[RedisReplay] Redis error:', err);
        });
        this.client.on('connect', () => {
            console.log('[RedisReplay] Connected to Redis');
        });
    }
    /**
     * Connect to Redis (ioredis connects automatically)
     */
    async connect() {
        // ioredis connects on instantiation
    }
    /**
     * Disconnect from Redis
     */
    async disconnect() {
        await this.client.quit();
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
        await this.client.setex(key, this.ttlSeconds, String(timestamp));
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
     * Cleanup expired nonces for a user
     * Note: With Redis SETEX, keys auto-expire, so this is a no-op
     */
    async cleanup(userId, maxAge) {
        // Redis handles TTL automatically, no need to manually cleanup
        return 0;
    }
    /**
     * Get cache statistics
     */
    async getStats() {
        const keys = await this.client.keys(`${this.keyPrefix}*`);
        return { size: keys.length };
    }
    /**
     * Health check
     */
    async isHealthy() {
        try {
            await this.client.ping();
            return true;
        }
        catch {
            return false;
        }
    }
}
/**
 * Create Redis replay cache from environment variables
 */
export function createRedisReplayCacheFromEnv() {
    const redisUrl = process.env.REDIS_URL || process.env.REDIS_REPLAY_URL;
    if (!redisUrl) {
        console.log('[RedisReplay] REDIS_URL not set, using in-memory fallback');
        return null;
    }
    return new RedisReplayCache({
        url: redisUrl,
        keyPrefix: process.env.REDIS_REPLAY_PREFIX || 'stvor:replay:',
        ttlSeconds: parseInt(process.env.REDIS_REPLAY_TTL || '300', 10)
    });
}
