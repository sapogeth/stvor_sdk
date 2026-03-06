/**
 * STVOR v2.4.0 - Metrics Attestation Engine
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
    metrics: RawMetrics;
    attestationId: string;
    timestamp: number;
    sessionId: string;
    sequenceNumber: number;
    proof: string;
}
/**
 * MetricsAttestationEngine
 *
 * RESPONSIBILITY: Record real events + create attestations
 * NOT RESPONSIBLE: Verify attestations (backend does that)
 */
export declare class MetricsAttestationEngine {
    private metrics;
    private sessionId;
    private sequenceNumber;
    private attestationKey;
    constructor(appToken: string);
    /**
     * Record real event: Successful encryption with AEAD
     * INVARIANT: Only called after cryptoSession.encryptForPeer() succeeds
     */
    recordMessageEncrypted(): void;
    /**
     * Record real event: Successful decryption with AAD verification
     * INVARIANT: Only called after cryptoSession.decryptFromPeer() succeeds
     */
    recordMessageDecrypted(): void;
    /**
     * Record real event: AAD verification failed (auth failure)
     * INVARIANT: Only called when AEAD auth tag is invalid
     */
    recordMessageRejected(): void;
    /**
     * Record real event: Replay attack detected
     * INVARIANT: Only called when nonce is duplicate
     */
    recordReplayAttempt(): void;
    /**
     * Record real event: Signature verification failed
     * INVARIANT: Only called on crypto auth failure
     */
    recordAuthFailure(): void;
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
    createAttestation(): MetricsAttestation;
    /**
     * Get current metrics snapshot (immutable)
     * Used for monitoring/debugging, NOT for Dashboard display
     */
    getMetrics(): Readonly<RawMetrics>;
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
    private createProof;
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
    private deriveAttestationKey;
    /**
     * Generate unique session ID
     * Used to distinguish different SDK instances
     */
    private generateSessionId;
    /**
     * Generate unique attestation ID
     * Used for anti-replay detection
     */
    private generateAttestationId;
}
/**
 * Backend Verification Service (Pseudo-code)
 *
 * This runs on BACKEND, not in browser or SDK
 */
export declare class MetricsVerificationService {
    /**
     * Verify attestation received from SDK
     *
     * RETURN: VerificationResult
     */
    verifyAttestation(attestation: MetricsAttestation, appToken: string, lastSequenceNumber: number): VerificationResult;
    /**
     * Verify proof signature (backend-side)
     */
    private verifyProof;
    private deriveAttestationKey;
    private constantTimeCompare;
    private hasSeenAttestationId;
    private getLastVerifiedMetrics;
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
