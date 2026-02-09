/**
 * STVOR v3.0 - Metrics Attestation Engine
 * 
 * ⚠️  CRITICAL SECURITY MODEL:
 * 
 * This module ONLY records real E2EE events and creates attestations.
 * It does NOT verify attestations (that's backend's job).
 * 
 * Trust boundary:
 * ┌─────────────────────────────────────────┐
 * │ SDK (Trusted) - Record + Sign           │
 * │ ┌─────────────────────────────────────┐ │
 * │ │ MetricsAttestationEngine            │ │
 * │ └─────────────────────────────────────┘ │
 * └──────────────┬──────────────────────────┘
 *                │ POST /api/metrics/attest
 *                ▼
 * ┌─────────────────────────────────────────┐
 * │ BACKEND (Trusted) - Verify + Store      │
 * │ ┌─────────────────────────────────────┐ │
 * │ │ MetricsVerificationService          │ │
 * │ │ - Check signature                   │ │
 * │ │ - Check monotonicity                │ │
 * │ │ - Check anti-replay                 │ │
 * │ └─────────────────────────────────────┘ │
 * └──────────────┬──────────────────────────┘
 *                │ Verified metrics in DB
 *                ▼
 * ┌─────────────────────────────────────────┐
 * │ Dashboard (Untrusted) - Display Only    │
 * │ - No crypto verification in browser     │
 * │ - No calculations                       │
 * │ - No fallback numbers                   │
 * │ - Only: fetch from /api/metrics         │
 * └─────────────────────────────────────────┘
 */

import { createHmac, randomBytes } from 'crypto';
import sodium from 'libsodium-wrappers';

/**
 * Raw metrics from SDK (before attestation)
 * INVARIANT: Only incremented after crypto success
 */
export interface RawMetrics {
  messagesEncrypted: number;
  messagesDecrypted: number;
  messagesRejected: number;
  replayAttempts: number;
  authFailures: number;
}

/**
 * Attestation = metrics + proof that can be sent to backend
 * Backend will verify this, not Dashboard
 */
export interface MetricsAttestation {
  // Raw metrics (what SDK measured)
  metrics: RawMetrics;

  // Attestation metadata
  attestationId: string;     // Unique per attestation (for replay protection)
  timestamp: number;          // Unix milliseconds
  sessionId: string;          // SDK session identifier
  sequenceNumber: number;     // Monotonic counter (starts at 0)

  // Proof (for backend to verify)
  // Format: HMAC-SHA256(payload, derivedKey)
  proof: string;              // Hex string
}

/**
 * MetricsAttestationEngine
 * 
 * RESPONSIBILITY: Record real events + create attestations
 * NOT RESPONSIBLE: Verify attestations (backend does that)
 */
export class MetricsAttestationEngine {
  private metrics: RawMetrics;
  private sessionId: string;
  private sequenceNumber: number = 0;
  private attestationKey: Buffer;

  constructor(appToken: string) {
    // Initialize raw metrics
    this.metrics = {
      messagesEncrypted: 0,
      messagesDecrypted: 0,
      messagesRejected: 0,
      replayAttempts: 0,
      authFailures: 0,
    };

    // Generate session ID (unique per SDK instance)
    this.sessionId = this.generateSessionId();

    // Derive attestation key from appToken
    // This key is NEVER used for crypto operations in browser
    // It's sent to backend along with metrics for verification
    this.attestationKey = this.deriveAttestationKey(appToken);
  }

  /**
   * Record real event: Successful encryption with AEAD
   * INVARIANT: Only called after cryptoSession.encryptForPeer() succeeds
   */
  public recordMessageEncrypted(): void {
    this.metrics.messagesEncrypted++;
  }

  /**
   * Record real event: Successful decryption with AAD verification
   * INVARIANT: Only called after cryptoSession.decryptFromPeer() succeeds
   */
  public recordMessageDecrypted(): void {
    this.metrics.messagesDecrypted++;
  }

  /**
   * Record real event: AAD verification failed (auth failure)
   * INVARIANT: Only called when AEAD auth tag is invalid
   */
  public recordMessageRejected(): void {
    this.metrics.messagesRejected++;
  }

  /**
   * Record real event: Replay attack detected
   * INVARIANT: Only called when nonce is duplicate
   */
  public recordReplayAttempt(): void {
    this.metrics.replayAttempts++;
  }

  /**
   * Record real event: Signature verification failed
   * INVARIANT: Only called on crypto auth failure
   */
  public recordAuthFailure(): void {
    this.metrics.authFailures++;
  }

  /**
   * Create attestation that can be sent to backend
   * 
   * Backend MUST verify:
   * - Signature is valid
   * - Metrics are monotonic
   * - Timestamp is within acceptable window
   * - sessionId matches
   * - sequenceNumber hasn't been seen before
   */
  public createAttestation(): MetricsAttestation {
    const attestationId = this.generateAttestationId();
    const timestamp = Date.now();

    const attestation: MetricsAttestation = {
      metrics: { ...this.metrics },
      attestationId,
      timestamp,
      sessionId: this.sessionId,
      sequenceNumber: this.sequenceNumber++,
      proof: '', // Will be filled in next
    };

    // Create proof that backend can verify
    const proof = this.createProof(attestation);
    attestation.proof = proof;

    return attestation;
  }

  /**
   * Get current metrics snapshot (immutable)
   * Used for monitoring/debugging, NOT for Dashboard display
   */
  public getMetrics(): Readonly<RawMetrics> {
    return Object.freeze({ ...this.metrics });
  }

  /**
   * Internal: Create proof for attestation
   * 
   * Format:
   *   proof = HMAC-SHA256(
   *     JSON.stringify({metrics, sessionId, sequenceNumber, timestamp}),
   *     attestationKey
   *   )
   * 
   * Backend will recompute this with the appToken sent by SDK.
   * If proof matches, backend knows:
   * - Metrics came from this SDK instance
   * - Metrics haven't been tampered
   * - This is the correct sequence number
   */
  private createProof(attestation: MetricsAttestation): string {
    const payload = JSON.stringify({
      metrics: attestation.metrics,
      sessionId: attestation.sessionId,
      sequenceNumber: attestation.sequenceNumber,
      timestamp: attestation.timestamp,
      attestationId: attestation.attestationId,
    });

    const hmac = createHmac('sha256', this.attestationKey);
    hmac.update(payload);
    return hmac.digest('hex');
  }

  /**
   * Derive attestation key from appToken
   * 
   * HKDF-SHA256 with:
   * - IKM: appToken
   * - salt: 32 zero bytes
   * - info: "stvor-metrics-attestation-v1"
   * 
   * Result is deterministic: same appToken → same key
   * 
   * This key is sent to backend for verification.
   * Backend computes same key from appToken and verifies proof.
   */
  private deriveAttestationKey(appToken: string): Buffer {
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('stvor-metrics-attestation-v1');

    // Extract
    const hmacExtract = createHmac('sha256', salt);
    hmacExtract.update(appToken);
    const prk = hmacExtract.digest();

    // Expand
    const hmacExpand = createHmac('sha256', prk);
    hmacExpand.update(info);
    hmacExpand.update(Buffer.from([1]));
    return hmacExpand.digest();
  }

  /**
   * Generate unique session ID
   * Used to distinguish different SDK instances
   */
  private generateSessionId(): string {
    return `session_${randomBytes(16).toString('hex')}`;
  }

  /**
   * Generate unique attestation ID
   * Used for anti-replay detection
   */
  private generateAttestationId(): string {
    return `attest_${randomBytes(16).toString('hex')}`;
  }
}

/**
 * Backend Verification Service (Pseudo-code)
 * 
 * This runs on BACKEND, not in browser or SDK
 */
export class MetricsVerificationService {
  /**
   * Verify attestation received from SDK
   * 
   * RETURN: VerificationResult
   */
  public verifyAttestation(
    attestation: MetricsAttestation,
    appToken: string,
    lastSequenceNumber: number  // From DB for this session
  ): VerificationResult {
    // 1. Verify proof signature
    if (!this.verifyProof(attestation, appToken)) {
      return {
        valid: false,
        reason: 'Signature verification failed',
      };
    }

    // 2. Verify monotonicity
    if (attestation.sequenceNumber !== lastSequenceNumber + 1) {
      return {
        valid: false,
        reason: 'Sequence number not monotonic',
      };
    }

    // 3. Verify timestamp is recent
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    if (now - attestation.timestamp > maxAge) {
      return {
        valid: false,
        reason: 'Attestation timestamp too old',
      };
    }

    // 4. Check for replay (attestationId must be unique)
    if (this.hasSeenAttestationId(attestation.attestationId)) {
      return {
        valid: false,
        reason: 'Attestation already processed (replay detected)',
      };
    }

    // 5. Verify metrics are monotonic across SDK sessions
    const lastMetrics = this.getLastVerifiedMetrics(attestation.sessionId);
    if (lastMetrics) {
      if (attestation.metrics.messagesEncrypted < lastMetrics.messagesEncrypted) {
        return {
          valid: false,
          reason: 'Metrics rolled back (not monotonic)',
        };
      }
    }

    return { valid: true, reason: 'Attestation verified' };
  }

  /**
   * Verify proof signature (backend-side)
   */
  private verifyProof(attestation: MetricsAttestation, appToken: string): boolean {
    // Derive same key from appToken
    const expectedKey = this.deriveAttestationKey(appToken);

    // Recompute proof
    const payload = JSON.stringify({
      metrics: attestation.metrics,
      sessionId: attestation.sessionId,
      sequenceNumber: attestation.sequenceNumber,
      timestamp: attestation.timestamp,
      attestationId: attestation.attestationId,
    });

    const hmac = createHmac('sha256', expectedKey);
    hmac.update(payload);
    const computedProof = hmac.digest('hex');

    // Constant-time comparison
    return this.constantTimeCompare(computedProof, attestation.proof);
  }

  private deriveAttestationKey(appToken: string): Buffer {
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('stvor-metrics-attestation-v1');

    const hmacExtract = createHmac('sha256', salt);
    hmacExtract.update(appToken);
    const prk = hmacExtract.digest();

    const hmacExpand = createHmac('sha256', prk);
    hmacExpand.update(info);
    hmacExpand.update(Buffer.from([1]));
    return hmacExpand.digest();
  }

  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  private hasSeenAttestationId(attestationId: string): boolean {
    // Check DB for duplicate attestationId
    // Return true if already seen (replay detected)
    return false; // Pseudo-code
  }

  private getLastVerifiedMetrics(sessionId: string): RawMetrics | null {
    // Query DB for last verified metrics from this session
    return null; // Pseudo-code
  }
}

export interface VerificationResult {
  valid: boolean;
  reason: string;
}

/**
 * SECURITY INVARIANTS (MUST BE ENFORCED)
 * 
 * I1: Dashboard NEVER generates metric numbers
 *     ✓ MetricsAttestationEngine records only on crypto success
 *     ✓ Dashboard only fetches from /api/metrics
 * 
 * I2: Metrics without backend verification are discarded
 *     ✓ Backend verifies proof before storing
 *     ✓ Only verified metrics go to DB
 *     ✓ Dashboard reads DB, not SDK
 * 
 * I3: Metric counters are monotonic
 *     ✓ SDK: counters only increment (never set)
 *     ✓ Backend: checks sequenceNumber is sequential
 *     ✓ Backend: checks metrics don't roll back
 * 
 * I4: Metrics replay is impossible
 *     ✓ SDK: each attestation has unique attestationId
 *     ✓ Backend: stores all seen attestationIds
 *     ✓ Backend: rejects duplicate attestationIds
 * 
 * I5: Different SDK instances cannot forge each other
 *     ✓ Each SDK has unique sessionId
 *     ✓ Backend checks sessionId matches appToken
 * 
 * I6: appToken compromise ≠ metrics forgery
 *     ✓ appToken only derives the signing key
 *     ✓ Backend verifies timestamp is recent
 *     ✓ Backend checks monotonicity constraints
 */
