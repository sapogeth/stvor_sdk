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
/**
 * Retry policy executor
 */
export class RetryPolicy {
    constructor(config = {}) {
        this.maxAttempts = config.maxAttempts ?? 3;
        this.maxDurationMs = config.maxDurationMs ?? 30000; // 30 sec
        this.strategy = config.strategy ?? 'exponential';
        this.initialDelayMs = config.initialDelayMs ?? 100; // ms
        this.maxDelayMs = config.maxDelayMs ?? 10000; // 10 sec
        this.multiplier = config.multiplier ?? 2;
        this.jitterFactor = config.jitterFactor ?? 0.1; // 10% jitter
        this.retryableErrors = config.retryableErrors;
        this.nonRetryableErrors = config.nonRetryableErrors;
        this.customBackoff = config.customBackoff;
        this.verbose = config.verbose ?? false;
        if (this.verbose) {
            console.log(`[RetryPolicy] ${this.strategy} (${this.maxAttempts} attempts, ${this.maxDurationMs}ms max)`);
        }
    }
    /**
     * Check if error is retryable
     */
    isRetryable(error) {
        if (!error)
            return true;
        // Check non-retryable errors first (highest priority)
        if (this.nonRetryableErrors) {
            for (const code of this.nonRetryableErrors) {
                if (error.message.includes(String(code)) || error.code === code) {
                    return false;
                }
            }
        }
        // Check retryable errors (if specified)
        if (this.retryableErrors) {
            for (const code of this.retryableErrors) {
                if (error.message.includes(String(code)) || error.code === code) {
                    return true;
                }
            }
            // If specific retryable errors defined but this doesn't match, don't retry
            return false;
        }
        // Default: retry all errors
        return true;
    }
    /**
     * Calculate backoff delay
     */
    calculateDelay(attempt, error) {
        // Use custom backoff if provided
        if (this.customBackoff) {
            return Math.min(this.maxDelayMs, this.customBackoff(attempt, error));
        }
        let delay = 0;
        switch (this.strategy) {
            case 'fixed':
                delay = this.initialDelayMs;
                break;
            case 'linear':
                delay = this.initialDelayMs * attempt;
                break;
            case 'exponential':
                delay = this.initialDelayMs * Math.pow(this.multiplier, attempt - 1);
                break;
            case 'custom':
                delay = this.initialDelayMs;
                break;
        }
        // Cap at max delay
        delay = Math.min(this.maxDelayMs, delay);
        // Add jitter
        if (this.jitterFactor > 0) {
            const jitter = delay * this.jitterFactor * Math.random();
            delay += jitter;
        }
        return Math.round(delay);
    }
    /**
     * Execute function with retries
     */
    async execute(fn, onAttempt) {
        const startTime = Date.now();
        for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
            try {
                const result = await fn();
                return result;
            }
            catch (error) {
                const elapsedMs = Date.now() - startTime;
                const isRetryable = this.isRetryable(error);
                if (this.verbose) {
                    console.log(`[RetryPolicy] Attempt ${attempt} failed: ${error.message} ` +
                        `(retryable: ${isRetryable})`);
                }
                // Check if should retry
                if (attempt >= this.maxAttempts || !isRetryable || elapsedMs >= this.maxDurationMs) {
                    if (this.verbose) {
                        const reason = attempt >= this.maxAttempts
                            ? 'max attempts'
                            : !isRetryable
                                ? 'non-retryable'
                                : 'timeout';
                        console.log(`[RetryPolicy] Giving up (${reason})`);
                    }
                    throw error;
                }
                // Calculate delay
                const delayMs = this.calculateDelay(attempt, error);
                // Check if timeout would be exceeded
                if (elapsedMs + delayMs > this.maxDurationMs) {
                    if (this.verbose) {
                        console.log(`[RetryPolicy] Would exceed max duration, giving up`);
                    }
                    throw error;
                }
                // Call callback
                if (onAttempt) {
                    onAttempt({
                        attemptNumber: attempt,
                        error: error,
                        nextDelayMs: delayMs,
                        elapsedMs,
                    });
                }
                if (this.verbose) {
                    console.log(`[RetryPolicy] Retrying in ${delayMs}ms (attempt ${attempt + 1}/${this.maxAttempts})`);
                }
                // Wait before retry
                await new Promise((resolve) => setTimeout(resolve, delayMs));
            }
        }
        throw new Error('Retry policy exhausted');
    }
    /**
     * Create predefined retry policy - Default (exponential backoff)
     */
    static default() {
        return new RetryPolicy({
            maxAttempts: 3,
            maxDurationMs: 30000,
            strategy: 'exponential',
            initialDelayMs: 100,
            maxDelayMs: 5000,
            jitterFactor: 0.1,
        });
    }
    /**
     * Create predefined retry policy - Aggressive (fast retries)
     */
    static aggressive() {
        return new RetryPolicy({
            maxAttempts: 5,
            maxDurationMs: 10000,
            strategy: 'linear',
            initialDelayMs: 100,
            maxDelayMs: 1000,
            jitterFactor: 0.05,
        });
    }
    /**
     * Create predefined retry policy - Conservative (slow retries)
     */
    static conservative() {
        return new RetryPolicy({
            maxAttempts: 2,
            maxDurationMs: 60000,
            strategy: 'exponential',
            initialDelayMs: 500,
            maxDelayMs: 30000,
            jitterFactor: 0.2,
        });
    }
    /**
     * Create predefined retry policy - Once (single retry)
     */
    static once() {
        return new RetryPolicy({
            maxAttempts: 2,
            maxDurationMs: 5000,
            strategy: 'fixed',
            initialDelayMs: 100,
        });
    }
    /**
     * Create predefined retry policy - Never (no retries)
     */
    static never() {
        return new RetryPolicy({
            maxAttempts: 1,
        });
    }
    /**
     * Get policy configuration
     */
    getConfig() {
        return {
            maxAttempts: this.maxAttempts,
            maxDurationMs: this.maxDurationMs,
            strategy: this.strategy,
            initialDelayMs: this.initialDelayMs,
            maxDelayMs: this.maxDelayMs,
        };
    }
}
/**
 * Retry manager for multiple operations
 */
export class RetryManager {
    constructor(defaultPolicy = RetryPolicy.default()) {
        this.policies = new Map();
        this.defaultPolicy = defaultPolicy;
    }
    /**
     * Register policy for operation type
     */
    registerPolicy(operationName, policy) {
        this.policies.set(operationName, policy);
    }
    /**
     * Get policy for operation
     */
    getPolicy(operationName) {
        return this.policies.get(operationName) ?? this.defaultPolicy;
    }
    /**
     * Execute operation with retry
     */
    async execute(operationName, fn, customPolicy) {
        const policy = customPolicy ?? this.getPolicy(operationName);
        return policy.execute(fn);
    }
    /**
     * Get stats
     */
    getStats() {
        const policies = {};
        for (const [name, policy] of Array.from(this.policies.entries())) {
            policies[name] = policy.getConfig();
        }
        return {
            defaultPolicy: this.defaultPolicy.getConfig(),
            registeredPolicies: this.policies.size,
            policies,
        };
    }
}
