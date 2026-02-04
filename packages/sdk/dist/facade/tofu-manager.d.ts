/**
 * STVOR TOFU (Trust On First Use) Manager
 * Integrates fingerprint verification with in-memory fallback
 *
 * SEMANTICS:
 * - Fingerprint = BLAKE2b(identity_public_key)
 * - Binding: identity key ONLY (not bundle, not SPK)
 * - Key rotation: requires manual re-trust via trustNewFingerprint()
 * - Multi-device: NOT supported (each device = new identity)
 * - Reinstall: fingerprint lost (in-memory only)
 *
 * LIMITATIONS:
 * - First-use MITM vulnerability (standard TOFU)
 * - No persistence (keys lost on restart)
 * - No out-of-band verification UX
 *
 * TODO:
 * - Add persistent storage (IndexedDB/localStorage)
 * - Add manual verification UI (compare fingerprints)
 * - Add key rotation notification system
 */
interface FingerprintRecord {
    fingerprint: string;
    firstSeen: Date;
    version: number;
}
/**
 * Generate BLAKE2b-256 fingerprint from identity public key
 *
 * BINDING: Identity key ONLY
 * - SPK rotation does NOT change fingerprint
 * - OPK exhaustion does NOT change fingerprint
 * - Only identity key rotation changes fingerprint
 */
export declare function generateFingerprint(identityPublicKey: Uint8Array): string;
/**
 * Store fingerprint for user (in-memory fallback)
 */
export declare function storeFingerprint(userId: string, fingerprint: string): Promise<void>;
/**
 * Verify fingerprint against stored value
 *
 * BEHAVIOR:
 * - First use: stores fingerprint, returns true
 * - Match: returns true
 * - Mismatch: throws error (HARD FAILURE)
 *
 * KEY ROTATION:
 * - Automatic rotation NOT supported
 * - Requires manual trustNewFingerprint() call
 * - Otherwise connection fails on mismatch
 *
 * @throws Error on fingerprint mismatch (possible MITM or key rotation)
 */
export declare function verifyFingerprint(userId: string, identityPublicKey: Uint8Array): Promise<boolean>;
/**
 * Manually trust a new fingerprint (key rotation)
 *
 * USE CASES:
 * - User reinstalled app and lost keys
 * - Legitimate key rotation after compromise
 * - Migration from old device
 *
 * SECURITY: Should be called ONLY after out-of-band verification
 */
export declare function trustNewFingerprint(userId: string, identityPublicKey: Uint8Array): Promise<void>;
/**
 * Get stored fingerprint record for user
 */
export declare function getStoredFingerprint(userId: string): FingerprintRecord | undefined;
/**
 * Format fingerprint for display (groups of 4 hex chars)
 * Example: "a3f2 d8c1 5e90 7b4a ..."
 */
export declare function formatFingerprint(fingerprint: string): string;
/**
 * Clear all stored fingerprints (TESTING ONLY)
 */
export declare function clearFingerprints(): void;
export {};
