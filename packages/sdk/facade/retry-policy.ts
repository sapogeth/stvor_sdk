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
export class RetryPolicy {
  private maxAttempts: number;
  private maxDurationMs: number;
  private strategy: BackoffStrategy;
  private initialDelayMs: number;
  private maxDelayMs: number;
  private multiplier: number;
  private jitterFactor: number;
  private retryableErrors?: (string | number)[];
  private nonRetryableErrors?: (string | number)[];
  private customBackoff?: (attempt: number, error?: Error) => number;
  private verbose: boolean;

  constructor(config: RetryPolicyConfig = {}) {
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
      console.log(
        `[RetryPolicy] ${this.strategy} (${this.maxAttempts} attempts, ${this.maxDurationMs}ms max)`,
      );
    }
  }

  /**
   * Check if error is retryable
   */
  private isRetryable(error?: Error): boolean {
    if (!error) return true;

    // Check non-retryable errors first (highest priority)
    if (this.nonRetryableErrors) {
      for (const code of this.nonRetryableErrors) {
        if (error.message.includes(String(code)) || (error as any).code === code) {
          return false;
        }
      }
    }

    // Check retryable errors (if specified)
    if (this.retryableErrors) {
      for (const code of this.retryableErrors) {
        if (error.message.includes(String(code)) || (error as any).code === code) {
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
  private calculateDelay(attempt: number, error?: Error): number {
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
  async execute<T>(
    fn: () => Promise<T>,
    onAttempt?: (attempt: RetryAttempt) => void,
  ): Promise<T> {
    const startTime = Date.now();

    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        const result = await fn();
        return result;
      } catch (error) {
        const elapsedMs = Date.now() - startTime;
        const isRetryable = this.isRetryable(error as Error);

        if (this.verbose) {
          console.log(
            `[RetryPolicy] Attempt ${attempt} failed: ${(error as Error).message} ` +
              `(retryable: ${isRetryable})`,
          );
        }

        // Check if should retry
        if (attempt >= this.maxAttempts || !isRetryable || elapsedMs >= this.maxDurationMs) {
          if (this.verbose) {
            const reason =
              attempt >= this.maxAttempts
                ? 'max attempts'
                : !isRetryable
                  ? 'non-retryable'
                  : 'timeout';
            console.log(`[RetryPolicy] Giving up (${reason})`);
          }
          throw error;
        }

        // Calculate delay
        const delayMs = this.calculateDelay(attempt, error as Error);

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
            error: error as Error,
            nextDelayMs: delayMs,
            elapsedMs,
          });
        }

        if (this.verbose) {
          console.log(
            `[RetryPolicy] Retrying in ${delayMs}ms (attempt ${attempt + 1}/${this.maxAttempts})`,
          );
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
  static default(): RetryPolicy {
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
  static aggressive(): RetryPolicy {
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
  static conservative(): RetryPolicy {
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
  static once(): RetryPolicy {
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
  static never(): RetryPolicy {
    return new RetryPolicy({
      maxAttempts: 1,
    });
  }

  /**
   * Get policy configuration
   */
  getConfig(): {
    maxAttempts: number;
    maxDurationMs: number;
    strategy: BackoffStrategy;
    initialDelayMs: number;
    maxDelayMs: number;
  } {
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
  private policies: Map<string, RetryPolicy> = new Map();
  private defaultPolicy: RetryPolicy;

  constructor(defaultPolicy: RetryPolicy = RetryPolicy.default()) {
    this.defaultPolicy = defaultPolicy;
  }

  /**
   * Register policy for operation type
   */
  registerPolicy(operationName: string, policy: RetryPolicy): void {
    this.policies.set(operationName, policy);
  }

  /**
   * Get policy for operation
   */
  getPolicy(operationName: string): RetryPolicy {
    return this.policies.get(operationName) ?? this.defaultPolicy;
  }

  /**
   * Execute operation with retry
   */
  async execute<T>(
    operationName: string,
    fn: () => Promise<T>,
    customPolicy?: RetryPolicy,
  ): Promise<T> {
    const policy = customPolicy ?? this.getPolicy(operationName);
    return policy.execute(fn);
  }

  /**
   * Get stats
   */
  getStats(): {
    defaultPolicy: any;
    registeredPolicies: number;
    policies: Record<string, any>;
  } {
    const policies: Record<string, any> = {};
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
