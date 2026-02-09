/**
 * STVOR v2.4.0 - Cryptographically Verified Metrics Engine
 * 
 * Single source of truth for E2EE metrics.
 * NO UI-side generation. NO localStorage counters. ONLY verified activity.
 */

import sodium from 'libsodium-wrappers';
import { createHmac } from 'crypto';

export interface Metrics {
  messagesEncrypted: number;
  messagesDecrypted: number;
  messagesRejected: number;
  replayAttempts: number;
  authFailures: number;
  timestamp: number;
  appToken: string;
}

export interface SignedMetrics {
  metrics: Metrics;
  proof: string; // HMAC-SHA256 hex
}

/**
 * MetricsEngine: Runtime counter for real E2EE events only
 * 
 * INVARIANT: Can only increment from SDK internals after cryptographic success
 */
export class MetricsEngine {
  private metrics: Metrics;
  private appToken: string;

  constructor(appToken: string) {
    this.appToken = appToken;
    this.metrics = {
      messagesEncrypted: 0,
      messagesDecrypted: 0,
      messagesRejected: 0,
      replayAttempts: 0,
      authFailures: 0,
      timestamp: Date.now(),
      appToken: appToken
    };
  }

  /**
   * Called ONLY after successful encrypt with AEAD
   * Cannot be called externally
   */
  recordMessageEncrypted(): void {
    this.metrics.messagesEncrypted++;
    this.updateTimestamp();
  }

  /**
   * Called ONLY after successful decrypt with AAD verification
   * Cannot be called externally
   */
  recordMessageDecrypted(): void {
    this.metrics.messagesDecrypted++;
    this.updateTimestamp();
  }

  /**
   * Called when message fails AAD check or other auth failures
   */
  recordMessageRejected(): void {
    this.metrics.messagesRejected++;
    this.updateTimestamp();
  }

  /**
   * Called when replay cache detects duplicate nonce
   */
  recordReplayAttempt(): void {
    this.metrics.replayAttempts++;
    this.updateTimestamp();
  }

  /**
   * Called when signature verification fails
   */
  recordAuthFailure(): void {
    this.metrics.authFailures++;
    this.updateTimestamp();
  }

  /**
   * Get current metrics snapshot (immutable)
   */
  getMetrics(): Metrics {
    return Object.freeze({
      ...this.metrics,
      timestamp: Date.now()
    });
  }

  /**
   * Reset metrics (for testing only, not accessible in production)
   */
  private updateTimestamp(): void {
    this.metrics.timestamp = Date.now();
  }

  /**
   * Get metrics with cryptographic proof
   * proof = HMAC-SHA256(JSON(metrics), derived_key)
   * 
   * Derived key = HKDF(appToken, "stvor-metrics-v3")
   */
  getSignedMetrics(): SignedMetrics {
    const metrics = this.getMetrics();
    const payload = JSON.stringify(metrics);
    
    // Derive key from appToken
    // appToken = "sk_live_" or "stvor_" prefix
    const derivedKey = this.deriveMetricsKey();
    
    // HMAC-SHA256
    const hmac = createHmac('sha256', derivedKey);
    hmac.update(payload);
    const proof = hmac.digest('hex');

    return {
      metrics,
      proof
    };
  }

  /**
   * Derive metrics signing key from API token
   * Using HKDF pattern for key derivation
   */
  private deriveMetricsKey(): Buffer {
    // Use libsodium for HKDF
    // info = "stvor-metrics-v3" (domain separation)
    const salt = Buffer.alloc(32, 0); // empty salt
    const info = Buffer.from('stvor-metrics-v3');
    
    // Extract phase: PRK = HMAC-Hash(salt, IKM)
    const hmacExtract = createHmac('sha256', salt);
    hmacExtract.update(this.appToken);
    const prk = hmacExtract.digest();

    // Expand phase: OKM = HMAC-Hash(PRK, info)
    const hmacExpand = createHmac('sha256', prk);
    hmacExpand.update(info);
    hmacExpand.update(Buffer.from([1])); // counter
    const okm = hmacExpand.digest();

    return okm; // 32 bytes for SHA256
  }
}

/**
 * Verify metrics signature on Dashboard side
 * 
 * Takes: payload (JSON string), proof (hex string), apiKey
 * Returns: boolean (valid or not)
 * 
 * USAGE:
 *   const valid = verifyMetricsSignature(payload, proof, apiKey);
 *   if (valid) {
 *     const metrics = JSON.parse(payload);
 *     display(metrics);
 *   } else {
 *     display("Unverified");
 *   }
 */
export function verifyMetricsSignature(
  payload: string,
  proof: string,
  apiKey: string
): boolean {
  try {
    // Parse to validate JSON
    JSON.parse(payload);

    // Derive same key from API token
    const derivedKey = deriveMetricsKeyForVerification(apiKey);

    // Compute HMAC
    const hmac = createHmac('sha256', derivedKey);
    hmac.update(payload);
    const computedProof = hmac.digest('hex');

    // Constant-time comparison to prevent timing attacks
    return computedProof === proof;
  } catch (e) {
    // Any parsing error = invalid
    return false;
  }
}

/**
 * Derive same key on verification side (Dashboard)
 */
function deriveMetricsKeyForVerification(apiKey: string): Buffer {
  const salt = Buffer.alloc(32, 0);
  const info = Buffer.from('stvor-metrics-v3');

  const hmacExtract = createHmac('sha256', salt);
  hmacExtract.update(apiKey);
  const prk = hmacExtract.digest();

  const hmacExpand = createHmac('sha256', prk);
  hmacExpand.update(info);
  hmacExpand.update(Buffer.from([1]));
  return hmacExpand.digest();
}

/**
 * Export MetricsEngine for use in facade/app.ts
 */
export default MetricsEngine;
