/**
 * STVOR v2.4.0 - Cryptographically Verified Metrics Engine
 *
 * Single source of truth for E2EE metrics.
 * NO UI-side generation. NO localStorage counters. ONLY verified activity.
 */
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
    proof: string;
}
/**
 * MetricsEngine: Runtime counter for real E2EE events only
 *
 * INVARIANT: Can only increment from SDK internals after cryptographic success
 */
export declare class MetricsEngine {
    private metrics;
    private appToken;
    private analyticsUrl;
    constructor(appToken: string, analyticsUrl?: string);
    /**
     * Called ONLY after successful encrypt with AEAD
     */
    recordMessageEncrypted(): void;
    /**
     * Called ONLY after successful decrypt with AAD verification
     * Cannot be called externally
     */
    recordMessageDecrypted(): void;
    /**
     * Called when message fails AAD check or other auth failures
     */
    recordMessageRejected(): void;
    /**
     * Called when replay cache detects duplicate nonce
     */
    recordReplayAttempt(): void;
    /**
     * Called when signature verification fails
     */
    recordAuthFailure(): void;
    /**
     * Get current metrics snapshot (immutable)
     */
    getMetrics(): Metrics;
    /**
     * Reset metrics (for testing only, not accessible in production)
     */
    private updateTimestamp;
    /**
     * Get metrics with cryptographic proof
     * proof = HMAC-SHA256(JSON(metrics), derived_key)
     *
     * Derived key = HKDF(appToken, "stvor-metrics-v3")
     */
    getSignedMetrics(): SignedMetrics;
    /**
     * Derive metrics signing key from API token
     * Using HKDF pattern for key derivation
     */
    private deriveMetricsKey;
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
export declare function verifyMetricsSignature(payload: string, proof: string, apiKey: string): boolean;
/**
 * Export MetricsEngine for use in facade/app.ts
 */
export default MetricsEngine;
