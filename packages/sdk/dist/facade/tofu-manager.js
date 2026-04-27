/**
 * STVOR TOFU (Trust On First Use) Manager
 *
 * Fingerprint = SHA-256(identity_public_key), hex-encoded.
 * Binding: identity key only — SPK rotation does not change fingerprint.
 * On key change: throws hard error (possible MITM).
 */
import { createHash } from 'crypto';
// In-memory TOFU store (fallback)
class InMemoryTofuStore {
    constructor() {
        this.store = new Map();
    }
    async saveFingerprint(userId, record) {
        this.store.set(userId, record);
    }
    async loadFingerprint(userId) {
        return this.store.get(userId) || null;
    }
    async deleteFingerprint(userId) {
        this.store.delete(userId);
    }
    async listFingerprints() {
        return Array.from(this.store.keys());
    }
}
// Global store instance
let tofuStore = null;
const FINGERPRINT_VERSION = 1; // Increment on breaking changes
/**
 * Initialize TOFU manager with optional persistent storage
 */
export function initializeTofu(customStore) {
    tofuStore = customStore || new InMemoryTofuStore();
    console.log('[TOFU] Initialized' + (customStore ? ' with persistent storage' : ' with in-memory fallback'));
}
/**
 * Generate SHA-256 fingerprint from identity public key.
 * Binding: identity key only.
 */
export function generateFingerprint(identityPublicKey) {
    return createHash('sha256').update(identityPublicKey).digest('hex');
}
/**
 * Store fingerprint for user
 */
export async function storeFingerprint(userId, fingerprint) {
    if (!tofuStore) {
        initializeTofu();
    }
    const record = {
        fingerprint,
        firstSeen: new Date(),
        lastSeen: new Date(),
        version: FINGERPRINT_VERSION,
        trusted: true,
    };
    await tofuStore.saveFingerprint(userId, record);
    console.log(`[TOFU] Stored fingerprint for user: ${userId}`);
}
/**
 * Verify fingerprint against stored value
 *
 * BEHAVIOR:
 * - First use: stores fingerprint, returns true
 * - Match: returns true
 * - Mismatch: throws error (HARD FAILURE)
 */
export async function verifyFingerprint(userId, identityPublicKey) {
    if (!tofuStore) {
        initializeTofu();
    }
    const fingerprint = generateFingerprint(identityPublicKey);
    const stored = await tofuStore.loadFingerprint(userId);
    if (!stored) {
        // First use - store and trust
        await storeFingerprint(userId, fingerprint);
        console.log(`[TOFU] First contact: ${userId} (fingerprint: ${fingerprint.slice(0, 16)}...)`);
        return true;
    }
    if (stored.fingerprint !== fingerprint) {
        // Fingerprint mismatch - potential MITM!
        console.error(`[TOFU] FINGERPRINT MISMATCH for ${userId}!`);
        console.error(`[TOFU] Expected: ${stored.fingerprint.slice(0, 16)}...`);
        console.error(`[TOFU] Received: ${fingerprint.slice(0, 16)}...`);
        throw new Error(`FINGERPRINT MISMATCH for user ${userId} - possible MITM attack!`);
    }
    // Update last seen
    stored.lastSeen = new Date();
    await tofuStore.saveFingerprint(userId, stored);
    return true;
}
/**
 * Check if user fingerprint is trusted
 */
export async function isFingerprintTrusted(userId) {
    if (!tofuStore) {
        initializeTofu();
    }
    const stored = await tofuStore.loadFingerprint(userId);
    return stored?.trusted || false;
}
/**
 * Get fingerprint for user
 */
export async function getFingerprint(userId) {
    if (!tofuStore) {
        initializeTofu();
    }
    const stored = await tofuStore.loadFingerprint(userId);
    return stored?.fingerprint || null;
}
/**
 * Revoke trust for a user (after key rotation or suspected compromise)
 */
export async function revokeTrust(userId) {
    if (!tofuStore) {
        initializeTofu();
    }
    await tofuStore.deleteFingerprint(userId);
    console.log(`[TOFU] Revoked trust for user: ${userId}`);
}
/**
 * Re-trust a user after verifying their new fingerprint out-of-band
 */
export async function trustNewFingerprint(userId, identityPublicKey) {
    const fingerprint = generateFingerprint(identityPublicKey);
    await storeFingerprint(userId, fingerprint);
    console.log(`[TOFU] Re-trusted user: ${userId}`);
}
/**
 * List all trusted fingerprints
 */
export async function listTrustedFingerprints() {
    if (!tofuStore) {
        initializeTofu();
    }
    return tofuStore.listFingerprints();
}
/**
 * Get detailed fingerprint info for debugging
 */
export async function getFingerprintInfo(userId) {
    if (!tofuStore) {
        initializeTofu();
    }
    return tofuStore.loadFingerprint(userId);
}
// Default initialization
initializeTofu();
