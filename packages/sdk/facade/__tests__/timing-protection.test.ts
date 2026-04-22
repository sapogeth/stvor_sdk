/**
 * Tests for Timing Attack Protection
 */

import { test } from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import {
  constantTimeCompare,
  constantTimeSignatureVerify,
  constantTimeHmacCompare,
  benchmarkOperation,
  analyzeTimingDistribution,
  verifyCryptoIsConstantTime,
} from '../timing-protection.ts';

test('Timing Attack Protection', async (t) => {
  await t.test('should reject different buffers', () => {
    const buf1 = Buffer.from('hello');
    const buf2 = Buffer.from('world');
    
    const result = constantTimeCompare(buf1, buf2);
    assert.strictEqual(result, false, 'Different buffers return false');
  });

  await t.test('should accept identical buffers', () => {
    const buf = Buffer.from('same');
    const result = constantTimeCompare(buf, buf);
    assert.strictEqual(result, true, 'Identical buffers return true');
  });

  await t.test('should handle different lengths safely', () => {
    const buf1 = Buffer.from('short');
    const buf2 = Buffer.from('much-longer-buffer');
    
    const result = constantTimeCompare(buf1, buf2);
    assert.strictEqual(result, false, 'Different lengths return false');
  });

  await t.test('should verify signatures with constant time', () => {
    const sig1 = crypto.randomBytes(64);
    const sig2 = crypto.randomBytes(64);
    
    const result1 = constantTimeSignatureVerify(sig1, sig1);
    const result2 = constantTimeSignatureVerify(sig1, sig2);
    
    assert.strictEqual(result1, true, 'Same signature verifies');
    assert.strictEqual(result2, false, 'Different signatures fail');
  });

  await t.test('should handle HMAC comparison', () => {
    const hmac1 = crypto.randomBytes(32);
    const hmac2 = crypto.randomBytes(32);
    
    const result1 = constantTimeHmacCompare(hmac1, hmac1);
    const result2 = constantTimeHmacCompare(hmac1, hmac2);
    
    assert.strictEqual(result1, true, 'Same HMAC verifies');
    assert.strictEqual(result2, false, 'Different HMACs fail');
  });

  await t.test('should benchmark operations', async () => {
    let callCount = 0;
    const result = await benchmarkOperation(() => {
      callCount++;
      return Promise.resolve(true);
    }, 100);

    assert.strictEqual(callCount, 100, 'Benchmarked 100 iterations');
    assert.ok(result.mean > 0, 'Mean timing is positive');
    assert.ok(result.stdDev >= 0, 'StdDev is non-negative');
    assert.ok(result.min <= result.mean, 'Min ≤ mean');
    assert.ok(result.max >= result.mean, 'Max ≥ mean');
    assert.strictEqual(result.timings.length, 100, 'Collected 100 timings');
  });

  await t.test('should analyze timing distribution', () => {
    // Uniform distribution (constant time)
    const uniform = Array(100).fill(0).map(() => 1000 + Math.random() * 10);
    const uniformAnalysis = analyzeTimingDistribution(uniform);
    
    assert.ok(uniformAnalysis.uniformity > 0.9, 'Uniform data has high uniformity');
    assert.ok(uniformAnalysis.uniformity <= 1, 'Uniformity ≤ 1');
    assert.ok(uniformAnalysis.recommendation.includes('✅'), 'Good timing detected');

    // Non-uniform distribution (timing attack vulnerable)
    const nonUniform = [
      ...Array(50).fill(0).map(() => 1000),
      ...Array(50).fill(0).map(() => 5000),
    ];
    const nonUniformAnalysis = analyzeTimingDistribution(nonUniform);
    
    assert.ok(nonUniformAnalysis.uniformity < 0.9, 'Non-uniform data has lower uniformity');
  });

  await t.test('should verify crypto is constant time', async () => {
    const verification = await verifyCryptoIsConstantTime();
    
    assert.ok(Array.isArray(verification.results), 'Results is array');
    assert.ok(verification.results.length > 0, 'Has results');
    
    // All operations should use constant-time comparisons
    for (const result of verification.results) {
      assert.ok(result.operation, `Operation name: ${result.operation}`);
      assert.ok(typeof result.isTimingSafe === 'boolean', `isTimingSafe is boolean`);
      assert.ok(result.mean > 0, `Mean timing > 0: ${result.mean}µs`);
      assert.ok(result.stdDev >= 0, `StdDev >= 0: ${result.stdDev}µs`);
    }
  });

  await t.test('should handle empty timing array', () => {
    const analysis = analyzeTimingDistribution([]);
    assert.strictEqual(analysis.uniformity, 0, 'Empty array has 0 uniformity');
    assert.ok(analysis.recommendation.includes('Insufficient'), 'Insufficient data message');
  });

  await t.test('should handle single timing value', () => {
    const analysis = analyzeTimingDistribution([100]);
    assert.strictEqual(analysis.uniformity, 0, 'Single value has 0 uniformity');
  });

  await t.test('should detect outliers in timing', () => {
    // Add some extreme outliers
    const timings = [
      ...Array(90).fill(0).map(() => 1000 + Math.random() * 10),
      ...Array(10).fill(0).map(() => 10000 + Math.random() * 100), // Extreme outliers
    ];
    
    const analysis = analyzeTimingDistribution(timings);
    assert.ok(analysis.outliers > 0, 'Outliers detected');
  });
});
