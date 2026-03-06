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
export interface IReplayCache {
    addNonce(userId: string, nonce: string, timestamp: number): Promise<void>;
    hasNonce(userId: string, nonce: string): Promise<boolean>;
    cleanup(userId: string, maxAge: number): Promise<number>;
    getStats(): Promise<{
        size: number;
    }>;
}
/**
 * Initialize replay protection with optional persistent storage
 */
export declare function initializeReplayProtection(customCache?: IReplayCache): void;
/**
 * Check if message is a replay attack
 */
export declare function isReplay(userId: string, nonce: string, timestamp: number): Promise<boolean>;
/**
 * Validate message for replay protection
 * Throws error if replay detected or message too old
 */
export declare function validateMessage(userId: string, nonce: string, timestamp: number): Promise<void>;
/**
 * Validate message with Uint8Array nonce
 */
export declare function validateMessageWithNonce(userId: string, nonce: Uint8Array, timestamp: number): Promise<void>;
/**
 * Cleanup expired nonces from cache
 * Should be called periodically in production
 */
export declare function cleanupExpiredNonces(): Promise<number>;
/**
 * Get cache statistics (for monitoring)
 */
export declare function getCacheStats(): Promise<{
    size: number;
    maxSize: number;
}>;
export declare function startAutoCleanup(): void;
export declare function stopAutoCleanup(): void;
