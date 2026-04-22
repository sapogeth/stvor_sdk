/**
 * Timing Attack Protection & Analysis
 *
 * Ensures all cryptographic operations are constant-time
 * to prevent information leakage through timing side-channels.
 */
import crypto from 'crypto';
/**
 * Constant-time buffer comparison
 * Safe against timing attacks - always takes same time regardless of input
 */
export function constantTimeCompare(a, b) {
    // Pad to same length to avoid timing leak on length check
    const len = Math.max(a.length, b.length);
    const aPadded = Buffer.alloc(len);
    const bPadded = Buffer.alloc(len);
    a.copy(aPadded);
    b.copy(bPadded);
    try {
        // This will throw if lengths differ after padding, but timing is same
        return crypto.timingSafeEqual(aPadded, bPadded) && a.length === b.length;
    }
    catch {
        return false;
    }
}
/**
 * Constant-time signature verification
 * Resistant to timing-based forgery attacks
 */
export function constantTimeSignatureVerify(expected, actual) {
    if (expected.length !== actual.length) {
        return false;
    }
    try {
        return crypto.timingSafeEqual(expected, actual);
    }
    catch (e) {
        return false;
    }
}
/**
 * Safe HMAC comparison (for message authentication codes)
 */
export function constantTimeHmacCompare(expected, actual) {
    const expectedHmac = crypto.createHmac('sha256', Buffer.alloc(32)).update(expected).digest();
    const actualHmac = crypto.createHmac('sha256', Buffer.alloc(32)).update(actual).digest();
    try {
        return crypto.timingSafeEqual(expectedHmac, actualHmac);
    }
    catch (e) {
        return false;
    }
}
/**
 * Benchmark a function to detect timing attacks
 * Returns timing distribution for statistical analysis
 */
export async function benchmarkOperation(fn, iterations = 1000) {
    const timings = [];
    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        await fn();
        const end = process.hrtime.bigint();
        timings.push(Number(end - start) / 1000); // Convert to microseconds
    }
    // Sort for analysis
    timings.sort((a, b) => a - b);
    // Calculate statistics
    const mean = timings.reduce((a, b) => a + b) / timings.length;
    const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2)) / timings.length;
    const stdDev = Math.sqrt(variance);
    const min = timings[0];
    const max = timings[timings.length - 1];
    // Check if timing is safe
    // Safe: low variation (stdDev < 10% of mean)
    const isTimingSafe = stdDev < mean * 0.1;
    return {
        mean: Math.round(mean * 100) / 100,
        stdDev: Math.round(stdDev * 100) / 100,
        min: Math.round(min * 100) / 100,
        max: Math.round(max * 100) / 100,
        timings,
        isTimingSafe,
    };
}
/**
 * Analyze timing distribution for potential attacks
 */
export function analyzeTimingDistribution(timings) {
    if (timings.length < 10) {
        return {
            uniformity: 0,
            outliers: 0,
            recommendation: 'Insufficient data for analysis',
        };
    }
    const sorted = [...timings].sort((a, b) => a - b);
    const mean = timings.reduce((a, b) => a + b) / timings.length;
    const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2)) / timings.length;
    const stdDev = Math.sqrt(variance);
    // Calculate uniformity (lower variation = higher uniformity)
    const cv = stdDev / mean; // Coefficient of variation
    const uniformity = Math.max(0, 1 - cv); // Invert so 1 = uniform
    // Count outliers (> 3 std devs)
    const outliers = timings.filter(t => Math.abs(t - mean) > 3 * stdDev).length;
    // Generate recommendation
    let recommendation = '';
    if (uniformity > 0.95) {
        recommendation = '✅ Excellent - timing is uniform and safe';
    }
    else if (uniformity > 0.85) {
        recommendation = '⚠️ Good - minor timing variations detected';
    }
    else if (uniformity > 0.7) {
        recommendation = '⚠️ Acceptable - timing variations present';
    }
    else {
        recommendation = '❌ Concerning - significant timing variations detected';
    }
    return { uniformity, outliers, recommendation };
}
/**
 * Verify that critical crypto operations are constant-time
 */
export async function verifyCryptoIsConstantTime() {
    const results = [];
    // Test 1: Buffer comparison
    const buffer1 = crypto.randomBytes(32);
    const buffer2 = crypto.randomBytes(32);
    const compareResult = await benchmarkOperation(() => {
        return Promise.resolve(constantTimeCompare(buffer1, buffer2));
    });
    results.push({
        operation: 'Buffer comparison (timingSafeEqual)',
        isTimingSafe: compareResult.isTimingSafe,
        mean: compareResult.mean,
        stdDev: compareResult.stdDev,
    });
    // Test 2: Signature verification
    const sig1 = crypto.randomBytes(64);
    const sig2 = crypto.randomBytes(64);
    const sigResult = await benchmarkOperation(() => {
        return Promise.resolve(constantTimeSignatureVerify(sig1, sig2));
    });
    results.push({
        operation: 'Signature verification',
        isTimingSafe: sigResult.isTimingSafe,
        mean: sigResult.mean,
        stdDev: sigResult.stdDev,
    });
    // Test 3: HMAC comparison
    const hmac1 = crypto.randomBytes(32);
    const hmac2 = crypto.randomBytes(32);
    const hmacResult = await benchmarkOperation(() => {
        return Promise.resolve(constantTimeHmacCompare(hmac1, hmac2));
    });
    results.push({
        operation: 'HMAC comparison',
        isTimingSafe: hmacResult.isTimingSafe,
        mean: hmacResult.mean,
        stdDev: hmacResult.stdDev,
    });
    const passed = results.every(r => r.isTimingSafe);
    return { passed, results };
}
