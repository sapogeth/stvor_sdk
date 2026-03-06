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
export class RedisReplayCache implements IReplayCache {
  private client: RedisClient;
  private keyPrefix: string;
  private ttlSeconds: number;

  constructor(config: RedisReplayCacheConfig) {
    this.client = config.client;
    this.keyPrefix = config.keyPrefix || 'stvor:replay:';
    this.ttlSeconds = config.ttlSeconds || 300;
  }

  /**
   * Build Redis key for nonce
   */
  private buildKey(userId: string, nonce: string): string {
    return `${this.keyPrefix}${userId}:${nonce}`;
  }

  /**
   * Add nonce to cache
   */
  async addNonce(userId: string, nonce: string, timestamp: number): Promise<void> {
    const key = this.buildKey(userId, nonce);
    await this.client.setEx(key, this.ttlSeconds, String(timestamp));
  }

  /**
   * Check if nonce exists in cache
   */
  async hasNonce(userId: string, nonce: string): Promise<boolean> {
    const key = this.buildKey(userId, nonce);
    const result = await this.client.exists(key);
    return result === 1;
  }

  /**
   * Cleanup expired nonces
   * Note: With Redis SETEX, keys auto-expire, so this is a no-op
   */
  async cleanup(userId: string, maxAge: number): Promise<number> {
    // Redis handles TTL automatically via SETEX
    // This is kept for interface compatibility but returns 0
    return 0;
  }

  /**
   * Get cache statistics
   */
  async getStats(): Promise<{ size: number }> {
    try {
      const keys = await this.client.keys(`${this.keyPrefix}*`);
      return { size: keys.length };
    } catch {
      return { size: 0 };
    }
  }
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

// Re-export for convenience
export type { IReplayCache } from './replay-manager.js';
