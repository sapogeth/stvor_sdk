/**
 * Retry Policies for STVOR SDK
 *
 * Provides flexible retry strategies:
 * - Fixed delay
 * - Exponential backoff
 * - Linear backoff
 * - Custom policies
 * - Jitter support
 * - Max attempts and timeout
 */
export type BackoffStrategy = 'fixed' | 'exponential' | 'linear' | 'custom';
export interface RetryPolicyConfig {
    /** Max retry attempts */
    maxAttempts?: number;
    /** Max total time to retry (ms) */
    maxDurationMs?: number;
    /** Backoff strategy */
    strategy?: BackoffStrategy;
    /** Initial delay (ms) */
    initialDelayMs?: number;
    /** Max delay (ms) */
    maxDelayMs?: number;
    /** Multiplier for exponential backoff */
    multiplier?: number;
    /** Add random jitter (0-1) */
    jitterFactor?: number;
    /** Retry on specific errors only */
    retryableErrors?: (string | number)[];
    /** Don't retry on these errors */
    nonRetryableErrors?: (string | number)[];
    /** Custom backoff calculator */
    customBackoff?: (attempt: number, error?: Error) => number;
    /** Verbose logging */
    verbose?: boolean;
}
export interface RetryAttempt {
    attemptNumber: number;
    error?: Error;
    nextDelayMs?: number;
    elapsedMs: number;
}
/**
 * Retry policy executor
 */
export declare class RetryPolicy {
    private maxAttempts;
    private maxDurationMs;
    private strategy;
    private initialDelayMs;
    private maxDelayMs;
    private multiplier;
    private jitterFactor;
    private retryableErrors?;
    private nonRetryableErrors?;
    private customBackoff?;
    private verbose;
    constructor(config?: RetryPolicyConfig);
    /**
     * Check if error is retryable
     */
    private isRetryable;
    /**
     * Calculate backoff delay
     */
    private calculateDelay;
    /**
     * Execute function with retries
     */
    execute<T>(fn: () => Promise<T>, onAttempt?: (attempt: RetryAttempt) => void): Promise<T>;
    /**
     * Create predefined retry policy - Default (exponential backoff)
     */
    static default(): RetryPolicy;
    /**
     * Create predefined retry policy - Aggressive (fast retries)
     */
    static aggressive(): RetryPolicy;
    /**
     * Create predefined retry policy - Conservative (slow retries)
     */
    static conservative(): RetryPolicy;
    /**
     * Create predefined retry policy - Once (single retry)
     */
    static once(): RetryPolicy;
    /**
     * Create predefined retry policy - Never (no retries)
     */
    static never(): RetryPolicy;
    /**
     * Get policy configuration
     */
    getConfig(): {
        maxAttempts: number;
        maxDurationMs: number;
        strategy: BackoffStrategy;
        initialDelayMs: number;
        maxDelayMs: number;
    };
}
/**
 * Retry manager for multiple operations
 */
export declare class RetryManager {
    private policies;
    private defaultPolicy;
    constructor(defaultPolicy?: RetryPolicy);
    /**
     * Register policy for operation type
     */
    registerPolicy(operationName: string, policy: RetryPolicy): void;
    /**
     * Get policy for operation
     */
    getPolicy(operationName: string): RetryPolicy;
    /**
     * Execute operation with retry
     */
    execute<T>(operationName: string, fn: () => Promise<T>, customPolicy?: RetryPolicy): Promise<T>;
    /**
     * Get stats
     */
    getStats(): {
        defaultPolicy: any;
        registeredPolicies: number;
        policies: Record<string, any>;
    };
}
