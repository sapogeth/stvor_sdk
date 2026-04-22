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
/**
 * Circuit breaker for peer failure handling
 */
export class CircuitBreaker {
    constructor(config = {}) {
        this.peerStates = new Map();
        this.failureThreshold = config.failureThreshold ?? 0.5; // 50%
        this.windowSize = config.windowSize ?? 100; // requests
        this.resetTimeoutMs = config.resetTimeoutMs ?? 5000; // 5 sec
        this.maxResetTimeoutMs = config.maxResetTimeoutMs ?? 60000; // 1 min
        this.backoffMultiplier = config.backoffMultiplier ?? 2;
        this.halfOpenRequests = config.halfOpenRequests ?? 3;
        this.verbose = config.verbose ?? false;
        if (this.verbose) {
            console.log(`[CircuitBreaker] Initialized: ${Math.round(this.failureThreshold * 100)}% threshold`);
        }
    }
    /**
     * Initialize peer state
     */
    ensurePeerState(peerId) {
        if (!this.peerStates.has(peerId)) {
            this.peerStates.set(peerId, {
                state: 'CLOSED',
                failureCount: 0,
                successCount: 0,
                totalRequests: 0,
                lastFailureTime: 0,
                nextRetryTime: 0,
                resetAttempts: 0,
                metrics: {
                    totalFailures: 0,
                    totalSuccesses: 0,
                    stateChanges: 0,
                },
            });
        }
        return this.peerStates.get(peerId);
    }
    /**
     * Check if request can proceed for peer
     */
    canRequest(peerId) {
        const state = this.ensurePeerState(peerId);
        // Transition to HALF_OPEN if timeout passed
        if (state.state === 'OPEN' && Date.now() >= state.nextRetryTime) {
            this.transitionState(peerId, 'HALF_OPEN');
        }
        // Allow request in CLOSED or HALF_OPEN states
        if (state.state === 'CLOSED') {
            return true;
        }
        if (state.state === 'HALF_OPEN') {
            // Limit requests in half-open
            return state.totalRequests % this.windowSize < this.halfOpenRequests;
        }
        // OPEN state - deny
        return false;
    }
    /**
     * Record successful request
     */
    recordSuccess(peerId) {
        const state = this.ensurePeerState(peerId);
        state.totalRequests++;
        state.successCount++;
        state.metrics.totalSuccesses++;
        if (state.state === 'HALF_OPEN') {
            // Transition back to CLOSED after successes
            if (state.successCount >= this.halfOpenRequests) {
                this.transitionState(peerId, 'CLOSED');
                if (this.verbose) {
                    console.log(`[CircuitBreaker] ${peerId} recovered (HALF_OPEN → CLOSED)`);
                }
            }
        }
        else if (state.state === 'CLOSED') {
            // Reset failure count on success
            if (state.failureCount > 0) {
                state.failureCount = Math.max(0, state.failureCount - 1);
            }
        }
        // Evaluate window
        if (state.totalRequests % this.windowSize === 0) {
            this.evaluateThreshold(peerId);
        }
    }
    /**
     * Record failed request
     */
    recordFailure(peerId, error) {
        const state = this.ensurePeerState(peerId);
        state.totalRequests++;
        state.failureCount++;
        state.lastFailureTime = Date.now();
        state.metrics.totalFailures++;
        if (this.verbose) {
            console.log(`[CircuitBreaker] ${peerId} failure (${state.failureCount}/${this.windowSize}) - ${error?.message || 'unknown'}`);
        }
        // Immediate transition if failure rate too high
        if (state.state !== 'OPEN') {
            const failureRate = state.failureCount / this.windowSize;
            if (failureRate > this.failureThreshold) {
                this.transitionState(peerId, 'OPEN');
                return;
            }
        }
        // Evaluate window
        if (state.totalRequests % this.windowSize === 0) {
            this.evaluateThreshold(peerId);
        }
    }
    /**
     * Evaluate failure threshold
     */
    evaluateThreshold(peerId) {
        const state = this.ensurePeerState(peerId);
        const failureRate = state.failureCount / this.windowSize;
        if (failureRate > this.failureThreshold) {
            if (state.state === 'CLOSED') {
                this.transitionState(peerId, 'OPEN');
            }
        }
        else if (state.state === 'OPEN') {
            // No automatic recovery from window evaluation
            // Recovery only from timeout → HALF_OPEN
        }
        // Reset window
        state.failureCount = 0;
        state.successCount = 0;
        state.totalRequests = 0;
    }
    /**
     * Transition state
     */
    transitionState(peerId, newState) {
        const state = this.ensurePeerState(peerId);
        const oldState = state.state;
        state.state = newState;
        state.metrics.stateChanges++;
        if (newState === 'OPEN') {
            // Schedule recovery
            state.resetAttempts++;
            const backoffMs = Math.min(this.maxResetTimeoutMs, this.resetTimeoutMs * Math.pow(this.backoffMultiplier, state.resetAttempts - 1));
            state.nextRetryTime = Date.now() + backoffMs;
            if (this.verbose) {
                console.log(`[CircuitBreaker] ${peerId} OPEN (${oldState} → OPEN), retry in ${Math.round(backoffMs / 1000)}s`);
            }
        }
        else if (newState === 'HALF_OPEN') {
            if (this.verbose) {
                console.log(`[CircuitBreaker] ${peerId} HALF_OPEN (testing recovery)`);
            }
        }
        else if (newState === 'CLOSED') {
            state.resetAttempts = 0;
            state.failureCount = 0;
            state.successCount = 0;
            if (this.verbose) {
                console.log(`[CircuitBreaker] ${peerId} CLOSED (normal operation)`);
            }
        }
    }
    /**
     * Get peer state
     */
    getState(peerId) {
        const state = this.ensurePeerState(peerId);
        return state.state;
    }
    /**
     * Get peer metrics
     */
    getMetrics(peerId) {
        const state = this.ensurePeerState(peerId);
        const failureRate = this.windowSize > 0 ? (state.failureCount / this.windowSize) * 100 : 0;
        return {
            state: state.state,
            failureRate: Math.round(failureRate),
            totalFailures: state.metrics.totalFailures,
            totalSuccesses: state.metrics.totalSuccesses,
            stateChanges: state.metrics.stateChanges,
            nextRetryIn: state.state === 'OPEN' ? Math.max(0, state.nextRetryTime - Date.now()) : undefined,
        };
    }
    /**
     * Get all peer states
     */
    getAllMetrics() {
        const result = {};
        for (const [peerId, state] of Array.from(this.peerStates.entries())) {
            result[peerId] = this.getMetrics(peerId);
        }
        return result;
    }
    /**
     * Manual reset for peer
     */
    reset(peerId) {
        const state = this.ensurePeerState(peerId);
        const oldState = state.state;
        state.state = 'CLOSED';
        state.failureCount = 0;
        state.successCount = 0;
        state.totalRequests = 0;
        state.resetAttempts = 0;
        state.nextRetryTime = 0;
        if (this.verbose) {
            console.log(`[CircuitBreaker] ${peerId} manually reset (${oldState} → CLOSED)`);
        }
    }
    /**
     * Reset all peers
     */
    resetAll() {
        for (const peerId of Array.from(this.peerStates.keys())) {
            this.reset(peerId);
        }
        if (this.verbose) {
            console.log(`[CircuitBreaker] Reset all ${this.peerStates.size} peers`);
        }
    }
    /**
     * Get health status
     */
    getHealth() {
        const health = {
            healthy: [],
            degraded: [],
            failed: [],
        };
        for (const [peerId, state] of Array.from(this.peerStates.entries())) {
            if (state.state === 'CLOSED') {
                health.healthy.push(peerId);
            }
            else if (state.state === 'HALF_OPEN') {
                health.degraded.push(peerId);
            }
            else {
                health.failed.push(peerId);
            }
        }
        return health;
    }
}
