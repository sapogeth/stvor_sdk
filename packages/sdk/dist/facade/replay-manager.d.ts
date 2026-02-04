/**
 * STVOR Replay Protection Manager
 * Integrates nonce-based replay protection with in-memory fallback
 *
 * ⚠️  CRITICAL LIMITATIONS (v2.1):
 *
 * 1. IN-MEMORY ONLY - DEMO-LEVEL PROTECTION
 *    - Process restart → cache cleared → replay window reopens
 *    - Clustered deployment → each instance has separate cache
 *    - Mobile background → iOS/Android may kill process
 *
 * 2. ATTACK WINDOW: 5 minutes after restart/cache clear
 *
 * 3. PRODUCTION REQUIREMENTS:
 *    - Redis or distributed cache (Memcached, DynamoDB)
 *    - Persistent storage survives restarts
 *    - Shared state across instances
 *
 * 4. ACCEPTABLE FOR:
 *    ✓ Single-instance development
 *    ✓ Proof-of-concept deployments
 *    ✓ Low-security use cases
 *
 * 5. NOT ACCEPTABLE FOR:
 *    ✗ Multi-instance production
 *    ✗ High-security environments
 *    ✗ Mobile apps (background kills)
 *
 * STATUS: Transitional implementation - Redis integration planned for v2.2
 */
/**
 * Check if message is a replay attack
 * @param userId - Sender's user ID
 * @param nonce - Message nonce (base64 or hex)
 * @param timestamp - Message timestamp (Unix seconds)
 * @returns true if replay detected
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
 * Get cache statistics (for monitoring)
 */
export declare function getCacheStats(): {
    size: number;
    maxSize: number;
};
/**
 * Clear all cached nonces (for testing)
 */
export declare function clearNonceCache(): void;
