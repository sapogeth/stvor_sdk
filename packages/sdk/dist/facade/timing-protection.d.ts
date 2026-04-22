/**
 * Timing Attack Protection & Analysis
 *
 * Ensures all cryptographic operations are constant-time
 * to prevent information leakage through timing side-channels.
 */
/**
 * Constant-time buffer comparison
 * Safe against timing attacks - always takes same time regardless of input
 */
export declare function constantTimeCompare(a: Buffer, b: Buffer): boolean;
/**
 * Constant-time signature verification
 * Resistant to timing-based forgery attacks
 */
export declare function constantTimeSignatureVerify(expected: Buffer, actual: Buffer): boolean;
/**
 * Safe HMAC comparison (for message authentication codes)
 */
export declare function constantTimeHmacCompare(expected: Buffer, actual: Buffer): boolean;
/**
 * Benchmark a function to detect timing attacks
 * Returns timing distribution for statistical analysis
 */
export declare function benchmarkOperation(fn: () => Promise<boolean>, iterations?: number): Promise<{
    mean: number;
    stdDev: number;
    min: number;
    max: number;
    timings: number[];
    isTimingSafe: boolean;
}>;
/**
 * Analyze timing distribution for potential attacks
 */
export declare function analyzeTimingDistribution(timings: number[]): {
    uniformity: number;
    outliers: number;
    recommendation: string;
};
/**
 * Verify that critical crypto operations are constant-time
 */
export declare function verifyCryptoIsConstantTime(): Promise<{
    passed: boolean;
    results: Array<{
        operation: string;
        isTimingSafe: boolean;
        mean: number;
        stdDev: number;
    }>;
}>;
