/**
 * Resource Lifecycle Management for STVOR SDK
 *
 * Handles:
 * - Memory cleanup (old sessions, OTP keys)
 * - Graceful shutdown
 * - Resource pooling
 * - Health monitoring
 */
/**
 * Lifecycle manager for STVOR SDK resources
 */
export class ResourceLifecycleManager {
    constructor(crypto, otpManager, options = {}) {
        this.cleanupInterval = null;
        this.sessionAccessTime = new Map();
        this.isShuttingDown = false;
        this.crypto = crypto;
        this.otpManager = otpManager;
        this.verbose = options.verbose ?? false;
        this.options = {
            sessionIdleTimeout: options.sessionIdleTimeout ?? 60 * 60 * 1000, // 1 hour
            otpCleanupInterval: options.otpCleanupInterval ?? 10 * 60 * 1000, // 10 minutes
            maxCachedSessions: options.maxCachedSessions ?? 1000,
            maxOTPKeys: options.maxOTPKeys ?? 500,
            verbose: options.verbose ?? false,
        };
        this.startCleanupCycle();
    }
    /**
     * Start automatic cleanup cycle
     */
    startCleanupCycle() {
        if (this.cleanupInterval)
            clearInterval(this.cleanupInterval);
        this.cleanupInterval = setInterval(() => {
            if (!this.isShuttingDown) {
                this.cleanup();
            }
        }, this.options.otpCleanupInterval);
        // Also unref to prevent keeping process alive
        this.cleanupInterval.unref();
        if (this.verbose) {
            console.log('[Lifecycle] Cleanup cycle started');
        }
    }
    /**
     * Track session access time
     */
    recordSessionAccess(peerId) {
        this.sessionAccessTime.set(peerId, Date.now());
    }
    /**
     * Perform cleanup operations
     */
    cleanup() {
        const startTime = Date.now();
        let cleanedSessions = 0;
        let cleanedOTPs = 0;
        try {
            // Cleanup old sessions
            const now = Date.now();
            const toDelete = [];
            for (const [peerId, lastAccess] of this.sessionAccessTime) {
                if (now - lastAccess > this.options.sessionIdleTimeout) {
                    toDelete.push(peerId);
                }
            }
            for (const peerId of toDelete) {
                try {
                    // In real implementation, would call deleteSession
                    this.sessionAccessTime.delete(peerId);
                    cleanedSessions++;
                }
                catch (e) {
                    if (this.verbose) {
                        console.error(`[Lifecycle] Failed to cleanup session ${peerId}:`, e);
                    }
                }
            }
            // Cleanup OTP keys
            if (this.otpManager) {
                try {
                    // Would call actual cleanup
                    const beforeOTPs = this.otpManager.getStatus().totalKeys;
                    this.otpManager.cleanup();
                    const afterOTPs = this.otpManager.getStatus().totalKeys;
                    cleanedOTPs = beforeOTPs - afterOTPs;
                }
                catch (e) {
                    if (this.verbose) {
                        console.error('[Lifecycle] OTP cleanup failed:', e);
                    }
                }
            }
            const duration = Date.now() - startTime;
            if (this.verbose && (cleanedSessions > 0 || cleanedOTPs > 0)) {
                console.log(`[Lifecycle] Cleanup: ${cleanedSessions} sessions, ${cleanedOTPs} OTPs (${duration}ms)`);
            }
        }
        catch (error) {
            if (this.verbose) {
                console.error('[Lifecycle] Cleanup cycle failed:', error);
            }
        }
    }
    /**
     * Get current resource statistics
     */
    getStats() {
        const activeCount = this.sessionAccessTime.size;
        const now = Date.now();
        let activeSessions = 0;
        for (const lastAccess of this.sessionAccessTime.values()) {
            if (now - lastAccess < this.options.sessionIdleTimeout) {
                activeSessions++;
            }
        }
        const otpStatus = this.otpManager?.getStatus() ?? {
            totalKeys: 0,
            unusedKeys: 0,
        };
        return {
            totalSessions: activeCount,
            activeSessions,
            totalOTPKeys: otpStatus.totalKeys,
            unusedOTPKeys: otpStatus.unusedKeys,
            memoryUsage: process.memoryUsage(),
            uptime: process.uptime(),
        };
    }
    /**
     * Log resource statistics
     */
    logStats() {
        const stats = this.getStats();
        const mem = stats.memoryUsage;
        console.log('[Lifecycle] Resource Stats:');
        console.log(`  Sessions: ${stats.activeSessions}/${stats.totalSessions} active`);
        console.log(`  OTP Keys: ${stats.unusedOTPKeys}/${stats.totalOTPKeys} unused`);
        console.log(`  Memory: ${(mem.heapUsed / 1024 / 1024).toFixed(2)}MB heap`);
        console.log(`  Uptime: ${(stats.uptime / 60).toFixed(1)} minutes`);
    }
    /**
     * Graceful shutdown
     */
    async shutdown() {
        if (this.isShuttingDown) {
            return;
        }
        this.isShuttingDown = true;
        if (this.verbose) {
            console.log('[Lifecycle] Starting graceful shutdown...');
        }
        try {
            // Stop accepting new operations
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
                this.cleanupInterval = null;
            }
            // Final cleanup
            this.cleanup();
            // Flush any pending state
            if (this.otpManager) {
                const state = this.otpManager.exportState();
                if (this.verbose) {
                    console.log(`[Lifecycle] OTP state exported (${state.length} bytes)`);
                }
            }
            // Log final stats
            if (this.verbose) {
                this.logStats();
            }
            console.log('[Lifecycle] Graceful shutdown complete');
        }
        catch (error) {
            console.error('[Lifecycle] Shutdown error:', error);
            throw error;
        }
    }
    /**
     * Register shutdown handlers
     */
    registerShutdownHandlers() {
        const shutdown = async () => {
            await this.shutdown();
            process.exit(0);
        };
        process.on('SIGTERM', shutdown);
        process.on('SIGINT', shutdown);
        if (this.verbose) {
            console.log('[Lifecycle] Shutdown handlers registered');
        }
    }
    /**
     * Health check
     */
    isHealthy() {
        try {
            const stats = this.getStats();
            // Check memory usage (alert if > 500MB)
            const heapUsedMB = stats.memoryUsage.heapUsed / 1024 / 1024;
            if (heapUsedMB > 500) {
                if (this.verbose) {
                    console.warn(`[Lifecycle] High memory usage: ${heapUsedMB.toFixed(2)}MB`);
                }
                return false;
            }
            // Check session count
            if (stats.totalSessions > this.options.maxCachedSessions) {
                if (this.verbose) {
                    console.warn(`[Lifecycle] Too many sessions: ${stats.totalSessions}/${this.options.maxCachedSessions}`);
                }
                return false;
            }
            // Check OTP count
            if (stats.totalOTPKeys > this.options.maxOTPKeys) {
                if (this.verbose) {
                    console.warn(`[Lifecycle] Too many OTP keys: ${stats.totalOTPKeys}/${this.options.maxOTPKeys}`);
                }
                return false;
            }
            return true;
        }
        catch (error) {
            if (this.verbose) {
                console.error('[Lifecycle] Health check failed:', error);
            }
            return false;
        }
    }
    /**
     * Wait for graceful shutdown signal
     */
    waitForShutdown() {
        return new Promise((resolve) => {
            const onShutdown = async () => {
                await this.shutdown();
                resolve();
            };
            process.on('SIGTERM', onShutdown);
            process.on('SIGINT', onShutdown);
        });
    }
}
