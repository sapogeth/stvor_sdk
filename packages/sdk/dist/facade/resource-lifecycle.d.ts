/**
 * Resource Lifecycle Management for STVOR SDK
 *
 * Handles:
 * - Memory cleanup (old sessions, OTP keys)
 * - Graceful shutdown
 * - Resource pooling
 * - Health monitoring
 */
import { CryptoSessionManager } from './crypto-session.js';
import { OTPKeyManager } from './otp-key-manager.js';
export interface LifecycleOptions {
    /** Session idle timeout in ms (default: 1 hour) */
    sessionIdleTimeout?: number;
    /** OTP cleanup interval in ms (default: 10 minutes) */
    otpCleanupInterval?: number;
    /** Max cached sessions (default: 1000) */
    maxCachedSessions?: number;
    /** Max OTP keys (default: 500) */
    maxOTPKeys?: number;
    /** Enable debug logging */
    verbose?: boolean;
}
export interface ResourceStats {
    totalSessions: number;
    activeSessions: number;
    totalOTPKeys: number;
    unusedOTPKeys: number;
    memoryUsage: NodeJS.MemoryUsage;
    uptime: number;
}
/**
 * Lifecycle manager for STVOR SDK resources
 */
export declare class ResourceLifecycleManager {
    private crypto;
    private otpManager?;
    private options;
    private cleanupInterval;
    private sessionAccessTime;
    private isShuttingDown;
    private verbose;
    constructor(crypto: CryptoSessionManager, otpManager?: OTPKeyManager, options?: LifecycleOptions);
    /**
     * Start automatic cleanup cycle
     */
    private startCleanupCycle;
    /**
     * Track session access time
     */
    recordSessionAccess(peerId: string): void;
    /**
     * Perform cleanup operations
     */
    cleanup(): void;
    /**
     * Get current resource statistics
     */
    getStats(): ResourceStats;
    /**
     * Log resource statistics
     */
    logStats(): void;
    /**
     * Graceful shutdown
     */
    shutdown(): Promise<void>;
    /**
     * Register shutdown handlers
     */
    registerShutdownHandlers(): void;
    /**
     * Health check
     */
    isHealthy(): boolean;
    /**
     * Wait for graceful shutdown signal
     */
    waitForShutdown(): Promise<void>;
}
