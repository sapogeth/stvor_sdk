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

import sodium from 'libsodium-wrappers';

interface FingerprintRecord {
  fingerprint: string;
  firstSeen: Date;
  version: number; // For future key rotation support
}

// In-memory fingerprint cache (fallback when PostgreSQL unavailable)
const fingerprintCache = new Map<string, FingerprintRecord>();

const FINGERPRINT_VERSION = 1; // Increment on breaking changes

/**
 * Generate BLAKE2b-256 fingerprint from identity public key
 * 
 * BINDING: Identity key ONLY
 * - SPK rotation does NOT change fingerprint
 * - OPK exhaustion does NOT change fingerprint
 * - Only identity key rotation changes fingerprint
 */
export function generateFingerprint(identityPublicKey: Uint8Array): string {
  const hash = sodium.crypto_generichash(32, identityPublicKey);
  return sodium.to_hex(hash);
}

/**
 * Store fingerprint for user (in-memory fallback)
 */
export async function storeFingerprint(userId: string, fingerprint: string): Promise<void> {
  const record: FingerprintRecord = {
    fingerprint,
    firstSeen: new Date(),
    version: FINGERPRINT_VERSION,
  };
  
  fingerprintCache.set(userId, record);
  
  // TODO: Add PostgreSQL persistence when available
  // try {
  //   await pool.query(
  //     'INSERT INTO fingerprints (user_id, fingerprint, first_seen, version) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO UPDATE SET fingerprint = $2',
  //     [userId, fingerprint, record.firstSeen, record.version]
  //   );
  // } catch (error) {
  //   // Fallback to in-memory storage
  //   fingerprintCache.set(userId, record);
  // }
}

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
export async function verifyFingerprint(
  userId: string,
  identityPublicKey: Uint8Array
): Promise<boolean> {
  const fingerprint = generateFingerprint(identityPublicKey);

  // Check in-memory cache first
  const storedRecord = fingerprintCache.get(userId);

  if (!storedRecord) {
    // First use - store fingerprint
    await storeFingerprint(userId, fingerprint);
    console.log(`[TOFU] ✓ First contact: ${userId} (${fingerprint.slice(0, 16)}...)`);
    return true;
  }

  // Verify fingerprint matches
  if (storedRecord.fingerprint !== fingerprint) {
    throw new Error(
      `[TOFU] ✗ SECURITY ALERT: Identity key mismatch for ${userId}\n` +
      `  Expected: ${storedRecord.fingerprint.slice(0, 16)}...\n` +
      `  Received: ${fingerprint.slice(0, 16)}...\n` +
      `  First seen: ${storedRecord.firstSeen.toISOString()}\n\n` +
      `POSSIBLE CAUSES:\n` +
      `  1. MITM attack (key substitution)\n` +
      `  2. User reinstalled app (legitimate key rotation)\n` +
      `  3. Multi-device not supported (different keys)\n\n` +
      `ACTION: Verify out-of-band or call trustNewFingerprint()`
    );
  }

  return true;
}

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
export async function trustNewFingerprint(
  userId: string,
  identityPublicKey: Uint8Array
): Promise<void> {
  const fingerprint = generateFingerprint(identityPublicKey);
  const oldRecord = fingerprintCache.get(userId);
  
  await storeFingerprint(userId, fingerprint);
  
  console.log(
    `[TOFU] ⚠️  Manually trusted new identity for ${userId}\n` +
    `  Old: ${oldRecord?.fingerprint.slice(0, 16) || 'none'}...\n` +
    `  New: ${fingerprint.slice(0, 16)}...`
  );
}

/**
 * Get stored fingerprint record for user
 */
export function getStoredFingerprint(userId: string): FingerprintRecord | undefined {
  return fingerprintCache.get(userId);
}

/**
 * Format fingerprint for display (groups of 4 hex chars)
 * Example: "a3f2 d8c1 5e90 7b4a ..."
 */
export function formatFingerprint(fingerprint: string): string {
  return fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint;
}

/**
 * Clear all stored fingerprints (TESTING ONLY)
 */
export function clearFingerprints(): void {
  fingerprintCache.clear();
}
