/**
 * Circuit Breaker Pattern for STVOR SDK
 *
 * Prevents cascading failures:
 * - Detects service failures
 * - Stops sending requests to failing peers
 * - Auto-recovery with exponential backoff
 * - Per-peer state management
 *
 * States: CLOSED (normal) → OPEN (failing) → HALF_OPEN (testing) → CLOSED
 */
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';
export interface CircuitBreakerConfig {
    /** Failure threshold (0-1, e.g., 0.5 = 50% failures) */
    failureThreshold?: number;
    /** Number of requests before evaluating threshold */
    windowSize?: number;
    /** Time to wait before attempting recovery (ms) */
    resetTimeoutMs?: number;
    /** Max reset timeout (exponential backoff cap) */
    maxResetTimeoutMs?: number;
    /** Backoff multiplier for exponential backoff */
    backoffMultiplier?: number;
    /** Half-open mode: requests allowed during recovery */
    halfOpenRequests?: number;
    /** Verbose logging */
    verbose?: boolean;
}
/**
 * Circuit breaker for peer failure handling
 */
export declare class CircuitBreaker {
    private peerStates;
    private failureThreshold;
    private windowSize;
    private resetTimeoutMs;
    private maxResetTimeoutMs;
    private backoffMultiplier;
    private halfOpenRequests;
    private verbose;
    constructor(config?: CircuitBreakerConfig);
    /**
     * Initialize peer state
     */
    private ensurePeerState;
    /**
     * Check if request can proceed for peer
     */
    canRequest(peerId: string): boolean;
    /**
     * Record successful request
     */
    recordSuccess(peerId: string): void;
    /**
     * Record failed request
     */
    recordFailure(peerId: string, error?: Error): void;
    /**
     * Evaluate failure threshold
     */
    private evaluateThreshold;
    /**
     * Transition state
     */
    private transitionState;
    /**
     * Get peer state
     */
    getState(peerId: string): CircuitState;
    /**
     * Get peer metrics
     */
    getMetrics(peerId: string): {
        state: CircuitState;
        failureRate: number;
        totalFailures: number;
        totalSuccesses: number;
        stateChanges: number;
        nextRetryIn?: number;
    };
    /**
     * Get all peer states
     */
    getAllMetrics(): Record<string, any>;
    /**
     * Manual reset for peer
     */
    reset(peerId: string): void;
    /**
     * Reset all peers
     */
    resetAll(): void;
    /**
     * Get health status
     */
    getHealth(): {
        healthy: string[];
        degraded: string[];
        failed: string[];
    };
}
