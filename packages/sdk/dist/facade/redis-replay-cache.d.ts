/**
 * Redis-based Replay Protection Cache for SDK
 * Production-ready replay protection for clustered client deployments
 *
 * Use case: When running multiple instances of the same app (e.g., web app with
 * multiple tabs, mobile app with background sync, or server-side SDK usage)
 */
import { IReplayCache } from './replay-manager.js';
/**
 * Redis client interface (compatible with ioredis, node-redis, etc.)
 */
export interface RedisClient {
    setEx(key: string, ttl: number, value: string): Promise<void>;
    exists(key: string): Promise<number>;
    keys(pattern: string): Promise<string[]>;
    ping(): Promise<string>;
    quit(): Promise<void>;
}
/**
 * Configuration for Redis replay cache
 */
export interface RedisReplayCacheConfig {
    /** Redis client instance (ioredis, node-redis, etc.) */
    client: RedisClient;
    /** Prefix for all keys (default: 'stvor:replay:') */
    keyPrefix?: string;
    /** TTL in seconds (default: 300 = 5 minutes) */
    ttlSeconds?: number;
}
/**
 * Redis-based replay cache implementation
 * Works with any Redis client (ioris, node-redis, etc.)
 */
export declare class RedisReplayCache implements IReplayCache {
    private client;
    private keyPrefix;
    private ttlSeconds;
    constructor(config: RedisReplayCacheConfig);
    /**
     * Build Redis key for nonce
     */
    private buildKey;
    /**
     * Add nonce to cache
     */
    addNonce(userId: string, nonce: string, timestamp: number): Promise<void>;
    /**
     * Check if nonce exists in cache
     */
    hasNonce(userId: string, nonce: string): Promise<boolean>;
    /**
     * Cleanup expired nonces
     * Note: With Redis SETEX, keys auto-expire, so this is a no-op
     */
    cleanup(userId: string, maxAge: number): Promise<number>;
    /**
     * Get cache statistics
     */
    getStats(): Promise<{
        size: number;
    }>;
}
/**
 * Example: Create Redis cache using ioredis
 *
 * ```typescript
 * import Redis from 'ioredis';
 * import { initializeReplayProtection, RedisReplayCache } from '@stvor/sdk';
 *
 * const redis = new Redis(process.env.REDIS_URL!);
 * const cache = new RedisReplayCache({ client: redis });
 * initializeReplayProtection(cache);
 * ```
 */
/**
 * Example: Create Redis cache using node-redis
 *
 * ```typescript
 * import { createClient } from 'redis';
 * import { initializeReplayProtection, RedisReplayCache } from '@stvor/sdk';
 *
 * const redis = createClient({ url: process.env.REDIS_URL });
 * await redis.connect();
 * const cache = new RedisReplayCache({ client: redis });
 * initializeReplayProtection(cache);
 * ```
 */
export type { IReplayCache } from './replay-manager.js';
