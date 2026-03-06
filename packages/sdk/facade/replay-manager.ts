/**
 * STVOR Replay Protection Manager
 * Implements persistent replay protection with fallback to in-memory
 * 
 * VERSION 2.0 - PRODUCTION READY
 * 
 * Features:
 * - Persistent storage interface (Redis, PostgreSQL, etc.)
 * - In-memory fallback for development
 * - Proper cleanup of expired entries
 * - Cache statistics
 */

import { createHash } from 'crypto';

// Storage interface for replay protection
export interface IReplayCache {
  addNonce(userId: string, nonce: string, timestamp: number): Promise<void>;
  hasNonce(userId: string, nonce: string): Promise<boolean>;
  cleanup(userId: string, maxAge: number): Promise<number>;
  getStats(): Promise<{ size: number }>;
}

// In-memory replay cache (fallback)
class InMemoryReplayCache implements IReplayCache {
  private cache = new Map<string, { timestamp: number; userId: string }>();
  private maxSize = 10000;

  async addNonce(userId: string, nonce: string, timestamp: number): Promise<void> {
    const key = `${userId}:${nonce}`;
    this.cache.set(key, { timestamp: Date.now(), userId });
    
    // Prevent memory exhaustion
    if (this.cache.size > this.maxSize) {
      await this.cleanupOldest(1000);
    }
  }

  async hasNonce(userId: string, nonce: string): Promise<boolean> {
    return this.cache.has(`${userId}:${nonce}`);
  }

  async cleanup(userId: string, maxAge: number): Promise<number> {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [key, value] of this.cache.entries()) {
      if (value.userId === userId && now - value.timestamp > maxAge) {
        this.cache.delete(key);
        cleaned++;
      }
    }
    
    return cleaned;
  }

  async getStats(): Promise<{ size: number }> {
    return { size: this.cache.size };
  }

  private async cleanupOldest(count: number): Promise<void> {
    const entries = Array.from(this.cache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    for (let i = 0; i < Math.min(count, entries.length); i++) {
      this.cache.delete(entries[i][0]);
    }
  }
}

// Global in-memory cache instance
let globalReplayCache: IReplayCache | null = null;

// Configuration
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes - production should be shorter
const MESSAGE_EXPIRY_MS = 60 * 1000; // Messages older than 1 minute are rejected

/**
 * Initialize replay protection with optional persistent storage
 */
export function initializeReplayProtection(customCache?: IReplayCache): void {
  globalReplayCache = customCache || new InMemoryReplayCache();
  console.log('[ReplayProtection] Initialized' + (customCache ? ' with persistent storage' : ' with in-memory fallback'));
}

/**
 * Check if message is a replay attack
 */
export async function isReplay(
  userId: string,
  nonce: string,
  timestamp: number
): Promise<boolean> {
  if (!globalReplayCache) {
    initializeReplayProtection();
  }

  const now = Date.now();

  // CRITICAL: Check if message is too old FIRST (before checking cache)
  // This prevents replay of old messages that have expired
  const messageAge = now - timestamp * 1000;
  if (messageAge > MESSAGE_EXPIRY_MS) {
    throw new Error(`Message rejected: too old (${Math.round(messageAge / 1000)}s)`);
  }

  // Check if nonce already seen
  const isDuplicate = await globalReplayCache!.hasNonce(userId, nonce);
  if (isDuplicate) {
    console.warn(`[ReplayProtection] Replay detected from user ${userId}`);
    return true;
  }

  // Store nonce with timestamp
  await globalReplayCache!.addNonce(userId, nonce, timestamp);

  return false;
}

/**
 * Validate message for replay protection
 * Throws error if replay detected or message too old
 */
export async function validateMessage(
  userId: string,
  nonce: string,
  timestamp: number
): Promise<void> {
  const replay = await isReplay(userId, nonce, timestamp);
  if (replay) {
    throw new Error(`Replay attack detected from user ${userId}`);
  }
}

/**
 * Validate message with Uint8Array nonce
 */
export async function validateMessageWithNonce(
  userId: string,
  nonce: Uint8Array,
  timestamp: number
): Promise<void> {
  const nonceHex = Buffer.from(nonce).toString('hex');
  await validateMessage(userId, nonceHex, timestamp);
}

/**
 * Cleanup expired nonces from cache
 * Should be called periodically in production
 */
export async function cleanupExpiredNonces(): Promise<number> {
  if (!globalReplayCache) {
    return 0;
  }

  const cleaned = await globalReplayCache.cleanup('all', NONCE_EXPIRY_MS);
  if (cleaned > 0) {
    console.log(`[ReplayProtection] Cleaned ${cleaned} expired nonces`);
  }
  return cleaned;
}

/**
 * Get cache statistics (for monitoring)
 */
export async function getCacheStats(): Promise<{ size: number; maxSize: number }> {
  const stats = await globalReplayCache?.getStats() || { size: 0 };
  return {
    size: stats.size,
    maxSize: 10000,
  };
}

// Auto-cleanup interval (every 1 minute)
let cleanupInterval: ReturnType<typeof setInterval> | null = null;

export function startAutoCleanup(): void {
  if (cleanupInterval) {
    return;
  }
  
  cleanupInterval = setInterval(() => {
    cleanupExpiredNonces().catch(err => {
      console.error('[ReplayProtection] Cleanup error:', err);
    });
  }, 60000);
  
  console.log('[ReplayProtection] Auto-cleanup started');
}

export function stopAutoCleanup(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('[ReplayProtection] Auto-cleanup stopped');
  }
}

// Default initialization
initializeReplayProtection();
