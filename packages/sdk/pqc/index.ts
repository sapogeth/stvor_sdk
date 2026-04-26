/**
 * Stvor PQC — Post-Quantum Cryptography layer
 *
 * Implements ML-KEM-768 (NIST FIPS 203) from scratch.
 * Zero external dependencies — pure Node.js crypto + math.
 *
 * When pqc: true in Stvor.connect(), key exchange uses:
 *   Classical:    X3DH (ECDH P-256)           — breaks with quantum computers
 *   Post-quantum: ML-KEM-768 (Kyber)           — quantum-resistant
 *   Combined:     HKDF(classical_ss ‖ pqc_ss) — hybrid, secure if either holds
 *
 * The hybrid approach means:
 *   - If ECDH is broken by quantum → PQC protects you
 *   - If PQC has an unknown flaw   → ECDH still protects you
 */

import nodeCrypto from 'node:crypto';
import {
  mlkemKeyGen,
  mlkemEncaps,
  mlkemDecaps,
  EK_SIZE,
  DK_SIZE,
  CT_SIZE,
  SS_SIZE,
  MLKEMKeyPair,
  MLKEMEncapsResult,
} from './mlkem.js';

export { EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE };
export type { MLKEMKeyPair, MLKEMEncapsResult };

// ── Key generation ────────────────────────────────────────────────────────────

/**
 * Generate a ML-KEM-768 key pair.
 * @returns { ek: Uint8Array(1184), dk: Uint8Array(2400) }
 */
export function pqcKeyGen(): MLKEMKeyPair {
  return mlkemKeyGen();
}

// ── Encapsulation ─────────────────────────────────────────────────────────────

/**
 * Encapsulate a shared secret using recipient's public key.
 * @param ek  Recipient's encapsulation key (1184 bytes)
 * @returns   { ciphertext: Uint8Array(1088), sharedSecret: Uint8Array(32) }
 */
export function pqcEncaps(ek: Uint8Array): MLKEMEncapsResult {
  return mlkemEncaps(ek);
}

// ── Decapsulation ─────────────────────────────────────────────────────────────

/**
 * Decapsulate to recover shared secret.
 * @param ct  Ciphertext (1088 bytes)
 * @param dk  Decapsulation key (2400 bytes)
 * @returns   sharedSecret: Uint8Array(32)
 */
export function pqcDecaps(ct: Uint8Array, dk: Uint8Array): Uint8Array {
  return mlkemDecaps(ct, dk);
}

// ── Hybrid key derivation ─────────────────────────────────────────────────────

/**
 * Derive final session key from classical + PQC shared secrets.
 * Uses HKDF-SHA256: secure if either classical OR PQC is secure.
 *
 * @param classicalSS  32-byte shared secret from X3DH/ECDH
 * @param pqcSS        32-byte shared secret from ML-KEM
 * @param context      Domain separation string
 * @returns            32-byte combined session key
 */
export function hybridKDF(
  classicalSS: Uint8Array,
  pqcSS: Uint8Array,
  context = 'stvor-hybrid-v1',
): Uint8Array {
  const ikm  = Buffer.concat([classicalSS, pqcSS]);
  const salt = Buffer.from(context, 'utf-8');
  return new Uint8Array(nodeCrypto.hkdfSync('sha256', ikm, salt, context, 32));
}

// ── Serialization helpers ─────────────────────────────────────────────────────

export function pqcEkToBase64(ek: Uint8Array): string {
  return Buffer.from(ek).toString('base64url');
}

export function pqcEkFromBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export function pqcCtToBase64(ct: Uint8Array): string {
  return Buffer.from(ct).toString('base64url');
}

export function pqcCtFromBase64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}
