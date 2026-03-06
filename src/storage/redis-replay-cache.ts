/**
 * Redis-based Replay Protection Cache
 * Production-ready replay protection for clustered deployments
 */

import { createClient, RedisClientType } from 'redis';

export interface RedisReplayCacheConfig {
  url: string;           // Redis connection URL
  keyPrefix?: string;    // Prefix for keys (default: 'stvor:replay:')
  ttlSeconds?: number;   // TTL for nonce entries (default: 300 = 5 min)
}

export class RedisReplayCache {
  private client: RedisClientType;
  private keyPrefix: string;
  private ttlSeconds: number;

  constructor(config: RedisReplayCacheConfig) {
    this.keyPrefix = config.keyPrefix || 'stvor:replay:';
    this.ttlSeconds = config.ttlSeconds || 300;
    
    this.client = createClient({
      url: config.url,
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 10) {
            console.error('[RedisReplay] Max reconnection attempts reached');
            return new Error('Max reconnection attempts reached');
          }
          return Math.min(retries * 100, 3000);
        }
      }
    });

    this.client.on('error', (err) => {
      console.error('[RedisReplay] Redis error:', err);
    });

    this.client.on('connect', () => {
      console.log('[RedisReplay] Connected to Redis');
    });
  }

  /**
   * Connect to Redis
   */
  async connect(): Promise<void> {
    await this.client.connect();
  }

  /**
   * Disconnect from Redis
   */
  async disconnect(): Promise<void> {
    await this.client.quit();
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
   * Cleanup expired nonces for a user
   * Note: With Redis SETEX, keys auto-expire, so this is a no-op
   */
  async cleanup(userId: string, maxAge: number): Promise<number> {
    // Redis handles TTL automatically, no need to manually cleanup
    return 0;
  }

  /**
   * Get cache statistics
   */
  async getStats(): Promise<{ size: number }> {
    const keys = await this.client.keys(`${this.keyPrefix}*`);
    return { size: keys.length };
  }

  /**
   * Health check
   */
  async isHealthy(): Promise<boolean> {
    try {
      await this.client.ping();
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Create Redis replay cache from environment variables
 */
export function createRedisReplayCacheFromEnv(): RedisReplayCache | null {
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
