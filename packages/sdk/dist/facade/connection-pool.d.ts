/**
 * Connection Pool for STVOR SDK
 *
 * Optimizes:
 * - Session reuse (avoid re-establishing)
 * - Connection lifecycle management
 * - Parallel connections (configurable)
 * - Automatic cleanup
 *
 * Improves performance 2-5x by reusing established sessions
 */
export interface PooledConnection {
    id: string;
    peerId: string;
    createdAt: number;
    lastUsed: number;
    usageCount: number;
    active: boolean;
}
export interface ConnectionPoolConfig {
    /** Max connections per peer */
    maxPerPeer?: number;
    /** Max total connections */
    maxTotal?: number;
    /** Connection idle timeout (ms) */
    idleTimeoutMs?: number;
    /** Connection TTL (ms) */
    ttlMs?: number;
    /** Enable automatic cleanup */
    enableAutoCleanup?: boolean;
    /** Cleanup interval (ms) */
    cleanupIntervalMs?: number;
    /** Verbose logging */
    verbose?: boolean;
}
/**
 * Connection pool manager
 */
export declare class ConnectionPool {
    private connections;
    private connectionStates;
    private peerConnections;
    private maxPerPeer;
    private maxTotal;
    private idleTimeoutMs;
    private ttlMs;
    private enableAutoCleanup;
    private cleanupIntervalMs;
    private verbose;
    private cleanupTimer;
    constructor(config?: ConnectionPoolConfig);
    /**
     * Acquire connection for peer
     */
    acquire(peerId: string): string;
    /**
     * Release connection
     */
    release(connId: string): void;
    /**
     * Store session data on connection
     */
    setSessionData(connId: string, data: Record<string, any>): void;
    /**
     * Get session data from connection
     */
    getSessionData(connId: string): Record<string, any>;
    /**
     * Check if connection is established
     */
    isEstablished(connId: string): boolean;
    /**
     * Close connection
     */
    close(connId: string): void;
    /**
     * Close all connections for peer
     */
    closePeer(peerId: string): void;
    /**
     * Get pool statistics
     */
    getStats(): {
        total: number;
        active: number;
        idle: number;
        byPeer: Record<string, {
            total: number;
            active: number;
        }>;
    };
    /**
     * Get connection details
     */
    getConnection(connId: string): PooledConnection | null;
    /**
     * Cleanup idle and expired connections
     */
    cleanup(): number;
    /**
     * Clear all connections
     */
    clear(): void;
    /**
     * Start automatic cleanup
     */
    private startAutoCleanup;
    /**
     * Stop automatic cleanup
     */
    stopAutoCleanup(): void;
    /**
     * Generate connection ID
     */
    private generateId;
    /**
     * Get connection efficiency metrics
     */
    getEfficiency(): {
        avgUsagePerConnection: number;
        connectionReuseFactor: number;
        poolUtilization: number;
    };
}
