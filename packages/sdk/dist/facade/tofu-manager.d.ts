/**
 * STVOR TOFU (Trust On First Use) Manager
 * Implements persistent TOFU with fallback to in-memory
 *
 * VERSION 2.0 - PRODUCTION READY
 *
 * Features:
 * - Persistent storage interface
 * - In-memory fallback for development
 * - Fingerprint verification
 * - Key rotation support
 *
 * SEMANTICS:
 * - Fingerprint = BLAKE2b(identity_public_key)
 * - Binding: identity key ONLY (not bundle, not SPK)
 * - Key rotation: requires manual re-trust via trustNewFingerprint()
 * - Multi-device: NOT supported (each device = new identity)
 */
interface FingerprintRecord {
    fingerprint: string;
    firstSeen: Date;
    lastSeen: Date;
    version: number;
    trusted: boolean;
}
export interface ITofuStore {
    saveFingerprint(userId: string, record: FingerprintRecord): Promise<void>;
    loadFingerprint(userId: string): Promise<FingerprintRecord | null>;
    deleteFingerprint(userId: string): Promise<void>;
    listFingerprints(): Promise<string[]>;
}
/**
 * Initialize TOFU manager with optional persistent storage
 */
export declare function initializeTofu(customStore?: ITofuStore): void;
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
 * Store fingerprint for user
 */
export declare function storeFingerprint(userId: string, fingerprint: string): Promise<void>;
/**
 * Verify fingerprint against stored value
 *
 * BEHAVIOR:
 * - First use: stores fingerprint, returns true
 * - Match: returns true
 * - Mismatch: throws error (HARD FAILURE)
 */
export declare function verifyFingerprint(userId: string, identityPublicKey: Uint8Array): Promise<boolean>;
/**
 * Check if user fingerprint is trusted
 */
export declare function isFingerprintTrusted(userId: string): Promise<boolean>;
/**
 * Get fingerprint for user
 */
export declare function getFingerprint(userId: string): Promise<string | null>;
/**
 * Revoke trust for a user (after key rotation or suspected compromise)
 */
export declare function revokeTrust(userId: string): Promise<void>;
/**
 * Re-trust a user after verifying their new fingerprint out-of-band
 */
export declare function trustNewFingerprint(userId: string, identityPublicKey: Uint8Array): Promise<void>;
/**
 * List all trusted fingerprints
 */
export declare function listTrustedFingerprints(): Promise<string[]>;
/**
 * Get detailed fingerprint info for debugging
 */
export declare function getFingerprintInfo(userId: string): Promise<FingerprintRecord | null>;
export {};
