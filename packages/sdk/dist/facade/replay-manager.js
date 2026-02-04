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
import sodium from 'libsodium-wrappers';
// In-memory nonce cache (fallback when Redis unavailable)
// ⚠️  LOST ON RESTART - see limitations above
const nonceCache = new Map();
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CACHE_SIZE = 10000; // Prevent memory exhaustion
/**
 * Check if message is a replay attack
 * @param userId - Sender's user ID
 * @param nonce - Message nonce (base64 or hex)
 * @param timestamp - Message timestamp (Unix seconds)
 * @returns true if replay detected
 */
export async function isReplay(userId, nonce, timestamp) {
    const key = `${userId}:${nonce}`;
    const now = Date.now();
    // Check if nonce already seen
    const cached = nonceCache.get(key);
    if (cached) {
        // Replay detected
        return true;
    }
    // Check if message is too old
    const messageAge = now - timestamp * 1000;
    if (messageAge > NONCE_EXPIRY_MS) {
        throw new Error('Message rejected: too old');
    }
    // Store nonce with timestamp
    nonceCache.set(key, { timestamp: now });
    // Cleanup old entries if cache is too large
    if (nonceCache.size > MAX_CACHE_SIZE) {
        await cleanupExpiredNonces();
    }
    return false;
}
/**
 * Validate message for replay protection
 * Throws error if replay detected or message too old
 */
export async function validateMessage(userId, nonce, timestamp) {
    const replay = await isReplay(userId, nonce, timestamp);
    if (replay) {
        throw new Error(`Replay attack detected from user ${userId}`);
    }
}
/**
 * Validate message with Uint8Array nonce
 */
export async function validateMessageWithNonce(userId, nonce, timestamp) {
    const nonceHex = sodium.to_hex(nonce);
    await validateMessage(userId, nonceHex, timestamp);
}
/**
 * Cleanup expired nonces from cache
 */
async function cleanupExpiredNonces() {
    const now = Date.now();
    let cleaned = 0;
    for (const [key, value] of nonceCache.entries()) {
        if (now - value.timestamp > NONCE_EXPIRY_MS) {
            nonceCache.delete(key);
            cleaned++;
        }
    }
    if (cleaned > 0) {
        console.log(`[ReplayProtection] Cleaned ${cleaned} expired nonces`);
    }
}
/**
 * Get cache statistics (for monitoring)
 */
export function getCacheStats() {
    return {
        size: nonceCache.size,
        maxSize: MAX_CACHE_SIZE,
    };
}
/**
 * Clear all cached nonces (for testing)
 */
export function clearNonceCache() {
    nonceCache.clear();
}
// Periodic cleanup (every 5 minutes)
if (typeof setInterval !== 'undefined') {
    setInterval(cleanupExpiredNonces, 5 * 60 * 1000);
}
