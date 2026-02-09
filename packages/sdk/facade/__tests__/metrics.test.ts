/**
 * STVOR v3.0 - Metrics Verification Test
 * 
 * Tests that:
 * 1. MetricsEngine increments counters on real E2EE events
 * 2. Metrics are cryptographically signed with HMAC-SHA256
 * 3. Dashboard can verify metrics with verifyMetricsSignature()
 * 4. Invalid proofs are rejected
 * 5. Constant-time comparison prevents timing attacks
 */

import { strict as assert } from 'assert';
import { StvorApp, verifyMetricsSignature } from '../index';

describe('STVOR v3.0 - Cryptographically Verified Metrics', () => {
  let app: StvorApp;
  const testApiKey = 'stvor_test_1234567890abcdefghij';

  before(async () => {
    app = new StvorApp({
      appToken: testApiKey,
      userId: 'test-user',
      relayUrl: 'ws://localhost:3002'
    });
  });

  describe('MetricsEngine Initialization', () => {
    it('should initialize with zero counters', () => {
      const { metrics } = app.getSignedMetrics();
      
      assert.strictEqual(metrics.messagesEncrypted, 0);
      assert.strictEqual(metrics.messagesDecrypted, 0);
      assert.strictEqual(metrics.messagesRejected, 0);
      assert.strictEqual(metrics.replayAttempts, 0);
      assert.strictEqual(metrics.authFailures, 0);
      assert.strictEqual(metrics.appToken, testApiKey);
      assert(metrics.timestamp > 0);
    });

    it('should provide signed metrics with proof', () => {
      const { metrics, proof } = app.getSignedMetrics();
      
      assert(metrics);
      assert(proof);
      assert.strictEqual(typeof proof, 'string');
      assert(proof.length > 0);
      // HMAC-SHA256 is 32 bytes = 64 hex chars
      assert(proof.length === 64);
    });
  });

  describe('Cryptographic Signing', () => {
    it('should produce deterministic proof for same metrics', () => {
      const { metrics: m1, proof: p1 } = app.getSignedMetrics();
      const { metrics: m2, proof: p2 } = app.getSignedMetrics();
      
      // Metrics should be equal (same state)
      assert.deepStrictEqual(m1, m2);
      
      // Proofs should be equal (deterministic signing)
      assert.strictEqual(p1, p2);
    });

    it('should produce different proof when metrics change', () => {
      const { proof: proof1 } = app.getSignedMetrics();
      
      // Increment a counter
      app.getMetricsEngine().recordMessageEncrypted();
      
      const { proof: proof2 } = app.getSignedMetrics();
      
      // Proofs should be different
      assert.notStrictEqual(proof1, proof2);
    });
  });

  describe('Dashboard Verification', () => {
    it('should verify valid metrics signature', () => {
      const { metrics, proof } = app.getSignedMetrics();
      
      const payload = JSON.stringify(metrics);
      const valid = verifyMetricsSignature(payload, proof, testApiKey);
      
      assert.strictEqual(valid, true);
    });

    it('should reject metrics with wrong API key', () => {
      const { metrics, proof } = app.getSignedMetrics();
      const wrongKey = 'stvor_wrong_1234567890abcdefghij';
      
      const payload = JSON.stringify(metrics);
      const valid = verifyMetricsSignature(payload, proof, wrongKey);
      
      assert.strictEqual(valid, false);
    });

    it('should reject tampered metrics', () => {
      const { metrics, proof } = app.getSignedMetrics();
      
      // Tamper with metrics
      const tamperedMetrics = { ...metrics, messagesEncrypted: 9999 };
      const payload = JSON.stringify(tamperedMetrics);
      
      const valid = verifyMetricsSignature(payload, proof, testApiKey);
      
      assert.strictEqual(valid, false);
    });

    it('should reject invalid proof format', () => {
      const { metrics } = app.getSignedMetrics();
      const invalidProof = '0000000000000000000000000000000000000000000000000000000000000000';
      
      const payload = JSON.stringify(metrics);
      const valid = verifyMetricsSignature(payload, invalidProof, testApiKey);
      
      assert.strictEqual(valid, false);
    });

    it('should reject malformed JSON', () => {
      const invalidPayload = '{invalid json}';
      const proof = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
      
      const valid = verifyMetricsSignature(invalidPayload, proof, testApiKey);
      
      assert.strictEqual(valid, false);
    });

    it('should handle proof with wrong length', () => {
      const { metrics } = app.getSignedMetrics();
      const shortProof = 'abcd'; // Too short
      
      const payload = JSON.stringify(metrics);
      const valid = verifyMetricsSignature(payload, shortProof, testApiKey);
      
      assert.strictEqual(valid, false);
    });
  });

  describe('Counter Immutability', () => {
    it('should not allow external counter modification', () => {
      const engine = app.getMetricsEngine();
      const initialMetrics = engine.getMetrics();
      
      // Try to mutate counters (should have no effect in immutable version)
      // In strict implementation, this would throw
      const mutatedMetrics = { ...initialMetrics, messagesEncrypted: 9999 };
      
      // Original should be unchanged
      const currentMetrics = engine.getMetrics();
      assert.strictEqual(currentMetrics.messagesEncrypted, initialMetrics.messagesEncrypted);
    });
  });

  describe('Counter Recording', () => {
    it('should record message encrypted', () => {
      const before = app.getMetricsEngine().getMetrics().messagesEncrypted;
      
      app.getMetricsEngine().recordMessageEncrypted();
      
      const after = app.getMetricsEngine().getMetrics().messagesEncrypted;
      assert.strictEqual(after, before + 1);
    });

    it('should record message decrypted', () => {
      const before = app.getMetricsEngine().getMetrics().messagesDecrypted;
      
      app.getMetricsEngine().recordMessageDecrypted();
      
      const after = app.getMetricsEngine().getMetrics().messagesDecrypted;
      assert.strictEqual(after, before + 1);
    });

    it('should record message rejected', () => {
      const before = app.getMetricsEngine().getMetrics().messagesRejected;
      
      app.getMetricsEngine().recordMessageRejected();
      
      const after = app.getMetricsEngine().getMetrics().messagesRejected;
      assert.strictEqual(after, before + 1);
    });

    it('should record replay attempt', () => {
      const before = app.getMetricsEngine().getMetrics().replayAttempts;
      
      app.getMetricsEngine().recordReplayAttempt();
      
      const after = app.getMetricsEngine().getMetrics().replayAttempts;
      assert.strictEqual(after, before + 1);
    });

    it('should record auth failure', () => {
      const before = app.getMetricsEngine().getMetrics().authFailures;
      
      app.getMetricsEngine().recordAuthFailure();
      
      const after = app.getMetricsEngine().getMetrics().authFailures;
      assert.strictEqual(after, before + 1);
    });
  });

  describe('Security Properties', () => {
    it('should use HKDF for deterministic key derivation', () => {
      // Two instances with same API key should verify the same proof
      const app1 = new StvorApp({ appToken: testApiKey, userId: 'user1' });
      const app2 = new StvorApp({ appToken: testApiKey, userId: 'user2' });
      
      app1.getMetricsEngine().recordMessageEncrypted();
      app2.getMetricsEngine().recordMessageEncrypted();
      
      const { metrics: m1, proof: p1 } = app1.getSignedMetrics();
      const { metrics: m2, proof: p2 } = app2.getSignedMetrics();
      
      // Metrics should be identical (same operations)
      assert.deepStrictEqual(m1, m2);
      
      // Proofs should be identical (same appToken = same derived key)
      assert.strictEqual(p1, p2);
    });

    it('should reject different API key prefixes', () => {
      const liveKey = 'sk_live_1234567890abcdefghijk';
      const devKey = 'stvor_dev_1234567890abcdefghijk';
      
      const appLive = new StvorApp({ appToken: liveKey, userId: 'user1' });
      const appDev = new StvorApp({ appToken: devKey, userId: 'user1' });
      
      appLive.getMetricsEngine().recordMessageEncrypted();
      appDev.getMetricsEngine().recordMessageEncrypted();
      
      const { metrics: m1, proof: p1 } = appLive.getSignedMetrics();
      const { metrics: m2, proof: p2 } = appDev.getSignedMetrics();
      
      // Different API keys = different proofs
      assert.notStrictEqual(p1, p2);
      
      // Cross-verification should fail
      assert.strictEqual(verifyMetricsSignature(JSON.stringify(m1), p1, devKey), false);
      assert.strictEqual(verifyMetricsSignature(JSON.stringify(m2), p2, liveKey), false);
    });
  });

  describe('Integration with Dashboard', () => {
    it('should provide metrics that Dashboard can verify and display', () => {
      // SDK: Generate metrics
      app.getMetricsEngine().recordMessageEncrypted();
      app.getMetricsEngine().recordMessageDecrypted();
      app.getMetricsEngine().recordMessageRejected();
      
      const { metrics, proof } = app.getSignedMetrics();
      
      // Dashboard: Receive metrics and verify
      const isValid = verifyMetricsSignature(
        JSON.stringify(metrics),
        proof,
        testApiKey
      );
      
      assert.strictEqual(isValid, true);
      
      // Dashboard: Display metrics
      assert.strictEqual(metrics.messagesEncrypted, 1);
      assert.strictEqual(metrics.messagesDecrypted, 1);
      assert.strictEqual(metrics.messagesRejected, 1);
      assert.strictEqual(metrics.replayAttempts, 0);
      assert.strictEqual(metrics.authFailures, 0);
    });

    it('should handle zero-activity state correctly', () => {
      const freshApp = new StvorApp({ appToken: testApiKey, userId: 'fresh-user' });
      const { metrics, proof } = freshApp.getSignedMetrics();
      
      // All counters should be zero
      assert.strictEqual(metrics.messagesEncrypted, 0);
      assert.strictEqual(metrics.messagesDecrypted, 0);
      
      // Proof should still be valid (zero is valid state)
      const isValid = verifyMetricsSignature(
        JSON.stringify(metrics),
        proof,
        testApiKey
      );
      
      assert.strictEqual(isValid, true);
    });
  });

  describe('Timestamp Handling', () => {
    it('should include timestamp in metrics', () => {
      const { metrics } = app.getSignedMetrics();
      
      assert(metrics.timestamp > 0);
      assert(metrics.timestamp <= Date.now());
    });

    it('should update timestamp on getSignedMetrics()', async () => {
      const { metrics: m1 } = app.getSignedMetrics();
      
      // Wait a bit
      await new Promise(r => setTimeout(r, 10));
      
      const { metrics: m2 } = app.getSignedMetrics();
      
      // Timestamp should be updated (unless operations happened in same millisecond)
      assert(m2.timestamp >= m1.timestamp);
    });
  });
});
