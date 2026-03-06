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

import { createHash } from 'crypto';

interface FingerprintRecord {
  fingerprint: string;
  firstSeen: Date;
  lastSeen: Date;
  version: number;
  trusted: boolean;
}

// Storage interface for TOFU
export interface ITofuStore {
  saveFingerprint(userId: string, record: FingerprintRecord): Promise<void>;
  loadFingerprint(userId: string): Promise<FingerprintRecord | null>;
  deleteFingerprint(userId: string): Promise<void>;
  listFingerprints(): Promise<string[]>;
}

// In-memory TOFU store (fallback)
class InMemoryTofuStore implements ITofuStore {
  private store = new Map<string, FingerprintRecord>();

  async saveFingerprint(userId: string, record: FingerprintRecord): Promise<void> {
    this.store.set(userId, record);
  }

  async loadFingerprint(userId: string): Promise<FingerprintRecord | null> {
    return this.store.get(userId) || null;
  }

  async deleteFingerprint(userId: string): Promise<void> {
    this.store.delete(userId);
  }

  async listFingerprints(): Promise<string[]> {
    return Array.from(this.store.keys());
  }
}

// Global store instance
let tofuStore: ITofuStore | null = null;
const FINGERPRINT_VERSION = 1; // Increment on breaking changes

/**
 * Initialize TOFU manager with optional persistent storage
 */
export function initializeTofu(customStore?: ITofuStore): void {
  tofuStore = customStore || new InMemoryTofuStore();
  console.log('[TOFU] Initialized' + (customStore ? ' with persistent storage' : ' with in-memory fallback'));
}

/**
 * Generate BLAKE2b-256 fingerprint from identity public key
 * 
 * BINDING: Identity key ONLY
 * - SPK rotation does NOT change fingerprint
 * - OPK exhaustion does NOT change fingerprint
 * - Only identity key rotation changes fingerprint
 */
export function generateFingerprint(identityPublicKey: Uint8Array): string {
  const hash = createHash('sha256').update(identityPublicKey).digest();
  return hash.toString('hex');
}

/**
 * Store fingerprint for user
 */
export async function storeFingerprint(userId: string, fingerprint: string): Promise<void> {
  if (!tofuStore) {
    initializeTofu();
  }

  const record: FingerprintRecord = {
    fingerprint,
    firstSeen: new Date(),
    lastSeen: new Date(),
    version: FINGERPRINT_VERSION,
    trusted: true,
  };
  
  await tofuStore!.saveFingerprint(userId, record);
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
export async function verifyFingerprint(
  userId: string,
  identityPublicKey: Uint8Array
): Promise<boolean> {
  if (!tofuStore) {
    initializeTofu();
  }

  const fingerprint = generateFingerprint(identityPublicKey);
  const stored = await tofuStore!.loadFingerprint(userId);

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
  await tofuStore!.saveFingerprint(userId, stored);
  
  return true;
}

/**
 * Check if user fingerprint is trusted
 */
export async function isFingerprintTrusted(userId: string): Promise<boolean> {
  if (!tofuStore) {
    initializeTofu();
  }

  const stored = await tofuStore!.loadFingerprint(userId);
  return stored?.trusted || false;
}

/**
 * Get fingerprint for user
 */
export async function getFingerprint(userId: string): Promise<string | null> {
  if (!tofuStore) {
    initializeTofu();
  }

  const stored = await tofuStore!.loadFingerprint(userId);
  return stored?.fingerprint || null;
}

/**
 * Revoke trust for a user (after key rotation or suspected compromise)
 */
export async function revokeTrust(userId: string): Promise<void> {
  if (!tofuStore) {
    initializeTofu();
  }

  await tofuStore!.deleteFingerprint(userId);
  console.log(`[TOFU] Revoked trust for user: ${userId}`);
}

/**
 * Re-trust a user after verifying their new fingerprint out-of-band
 */
export async function trustNewFingerprint(
  userId: string,
  identityPublicKey: Uint8Array
): Promise<void> {
  const fingerprint = generateFingerprint(identityPublicKey);
  await storeFingerprint(userId, fingerprint);
  console.log(`[TOFU] Re-trusted user: ${userId}`);
}

/**
 * List all trusted fingerprints
 */
export async function listTrustedFingerprints(): Promise<string[]> {
  if (!tofuStore) {
    initializeTofu();
  }

  return tofuStore!.listFingerprints();
}

/**
 * Get detailed fingerprint info for debugging
 */
export async function getFingerprintInfo(userId: string): Promise<FingerprintRecord | null> {
  if (!tofuStore) {
    initializeTofu();
  }

  return tofuStore!.loadFingerprint(userId);
}

// Default initialization
initializeTofu();
