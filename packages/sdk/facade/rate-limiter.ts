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

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

/**
 * Token bucket rate limiter
 */
export class RateLimiter {
  private globalBucket: TokenBucket;
  private peerBuckets: Map<string, TokenBucket> = new Map();
  private globalRateLimit: number;
  private peerRateLimit: number;
  private bucketSize: number;
  private refillInterval: number;
  private enableBackpressure: boolean;
  private verbose: boolean;

  constructor(config: RateLimitConfig = {}) {
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
      console.log(
        `[RateLimiter] Initialized: ${this.globalRateLimit} global/sec, ${this.peerRateLimit} peer/sec`,
      );
    }
  }

  /**
   * Refill tokens based on elapsed time
   */
  private refill(bucket: TokenBucket, rateLimit: number): void {
    const now = Date.now();
    const elapsed = now - bucket.lastRefill;
    const tokensToAdd = (elapsed / this.refillInterval) * rateLimit;

    bucket.tokens = Math.min(this.bucketSize, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;
  }

  /**
   * Check if operation is allowed (global rate limit)
   */
  canProceed(cost: number = 1): boolean {
    this.refill(this.globalBucket, this.globalRateLimit);

    if (this.globalBucket.tokens >= cost) {
      this.globalBucket.tokens -= cost;
      return true;
    }

    if (this.verbose) {
      console.warn(
        `[RateLimiter] Global limit exceeded: ${this.globalBucket.tokens.toFixed(1)} tokens`,
      );
    }

    return false;
  }

  /**
   * Check if operation is allowed for specific peer
   */
  canProceedForPeer(peerId: string, cost: number = 1): boolean {
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
      console.warn(
        `[RateLimiter] Peer limit exceeded for ${peerId}: ${peerBucket.tokens.toFixed(1)} tokens`,
      );
    }

    return false;
  }

  /**
   * Wait until operation is allowed (backpressure)
   */
  async waitUntilAllowed(cost: number = 1): Promise<void> {
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
  async waitUntilAllowedForPeer(peerId: string, cost: number = 1): Promise<void> {
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
  getStatus(): {
    globalTokens: number;
    globalLimit: number;
    peerStats: Array<{ peerId: string; tokens: number; limit: number }>;
  } {
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
  resetPeer(peerId: string): void {
    this.peerBuckets.delete(peerId);
    if (this.verbose) {
      console.log(`[RateLimiter] Reset rate limit for peer ${peerId}`);
    }
  }

  /**
   * Reset all peer buckets
   */
  resetAll(): void {
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
  getWaitTime(cost: number = 1): number {
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
  getWaitTimeForPeer(peerId: string, cost: number = 1): number {
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
  disable(): void {
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
  enable(): void {
    if (this.verbose) {
      console.log(`[RateLimiter] Rate limiting enabled`);
    }
  }
}
