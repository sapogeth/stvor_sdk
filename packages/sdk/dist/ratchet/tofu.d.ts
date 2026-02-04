/**
 * Generate a SHA-256 fingerprint for a given public key.
 * @param publicKey - The public key to fingerprint.
 * @returns The fingerprint as a hex string.
 */
export declare function generateFingerprint(publicKey: Uint8Array): string;
/**
 * Store the fingerprint in the database.
 * @param userId - The user ID associated with the fingerprint.
 * @param fingerprint - The fingerprint to store.
 */
export declare function storeFingerprint(userId: string, fingerprint: string): Promise<void>;
/**
 * Verify the fingerprint against the stored value.
 * @param userId - The user ID associated with the fingerprint.
 * @param fingerprint - The fingerprint to verify.
 * @returns True if the fingerprint matches, false otherwise.
 */
export declare function verifyFingerprint(userId: string, fingerprint: string): Promise<boolean>;
/**
 * Honest TOFU Limitations
 *
 * 1. First-session MITM risk: The first connection assumes trust.
 * 2. Fingerprint mismatches result in hard failure.
 * 3. No automatic recovery from key substitution attacks.
 */
export declare function handleFingerprintMismatch(userId: string): void;
