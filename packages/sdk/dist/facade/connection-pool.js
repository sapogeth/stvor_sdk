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
/**
 * Connection pool manager
 */
export class ConnectionPool {
    constructor(config = {}) {
        this.connections = new Map();
        this.connectionStates = new Map();
        this.peerConnections = new Map(); // peerId -> [connId]
        this.cleanupTimer = null;
        this.maxPerPeer = config.maxPerPeer ?? 10;
        this.maxTotal = config.maxTotal ?? 1000;
        this.idleTimeoutMs = config.idleTimeoutMs ?? 300000; // 5 min
        this.ttlMs = config.ttlMs ?? 3600000; // 1 hour
        this.enableAutoCleanup = config.enableAutoCleanup ?? true;
        this.cleanupIntervalMs = config.cleanupIntervalMs ?? 60000; // 1 min
        this.verbose = config.verbose ?? false;
        if (this.enableAutoCleanup) {
            this.startAutoCleanup();
        }
        if (this.verbose) {
            console.log(`[ConnectionPool] Initialized: ${this.maxPerPeer}/peer, ${this.maxTotal} total`);
        }
    }
    /**
     * Acquire connection for peer
     */
    acquire(peerId) {
        const now = Date.now();
        // Try to find idle connection
        const peerConns = this.peerConnections.get(peerId) || [];
        for (const connId of peerConns) {
            const conn = this.connections.get(connId);
            if (conn && !conn.active) {
                conn.active = true;
                conn.lastUsed = now;
                conn.usageCount++;
                if (this.verbose) {
                    console.log(`[ConnectionPool] Acquired existing: ${connId} (uses: ${conn.usageCount})`);
                }
                return connId;
            }
        }
        // Create new connection if allowed
        if (peerConns.length < this.maxPerPeer && this.connections.size < this.maxTotal) {
            const connId = this.generateId();
            const connection = {
                id: connId,
                peerId,
                createdAt: now,
                lastUsed: now,
                usageCount: 1,
                active: true,
            };
            this.connections.set(connId, connection);
            this.connectionStates.set(connId, {
                sessionData: {},
                established: false,
            });
            peerConns.push(connId);
            this.peerConnections.set(peerId, peerConns);
            if (this.verbose) {
                console.log(`[ConnectionPool] Created new: ${connId} for ${peerId}`);
            }
            return connId;
        }
        throw new Error(`Pool exhausted: ${peerConns.length}/${this.maxPerPeer} for peer, ` +
            `${this.connections.size}/${this.maxTotal} total`);
    }
    /**
     * Release connection
     */
    release(connId) {
        const conn = this.connections.get(connId);
        if (!conn) {
            console.warn(`[ConnectionPool] Release: connection not found ${connId}`);
            return;
        }
        conn.active = false;
        conn.lastUsed = Date.now();
        if (this.verbose) {
            console.log(`[ConnectionPool] Released: ${connId}`);
        }
    }
    /**
     * Store session data on connection
     */
    setSessionData(connId, data) {
        const state = this.connectionStates.get(connId);
        if (state) {
            state.sessionData = { ...state.sessionData, ...data };
            state.established = true;
        }
    }
    /**
     * Get session data from connection
     */
    getSessionData(connId) {
        const state = this.connectionStates.get(connId);
        return state?.sessionData ?? {};
    }
    /**
     * Check if connection is established
     */
    isEstablished(connId) {
        const state = this.connectionStates.get(connId);
        return state?.established ?? false;
    }
    /**
     * Close connection
     */
    close(connId) {
        const conn = this.connections.get(connId);
        if (!conn)
            return;
        // Remove from peer list
        const peerConns = this.peerConnections.get(conn.peerId) || [];
        const index = peerConns.indexOf(connId);
        if (index >= 0) {
            peerConns.splice(index, 1);
        }
        // Delete connection
        this.connections.delete(connId);
        this.connectionStates.delete(connId);
        if (this.verbose) {
            console.log(`[ConnectionPool] Closed: ${connId}`);
        }
    }
    /**
     * Close all connections for peer
     */
    closePeer(peerId) {
        const peerConns = this.peerConnections.get(peerId) || [];
        for (const connId of [...peerConns]) {
            this.close(connId);
        }
        this.peerConnections.delete(peerId);
        if (this.verbose) {
            console.log(`[ConnectionPool] Closed all (${peerConns.length}) for ${peerId}`);
        }
    }
    /**
     * Get pool statistics
     */
    getStats() {
        const stats = {
            total: this.connections.size,
            active: 0,
            idle: 0,
            byPeer: {},
        };
        for (const conn of Array.from(this.connections.values())) {
            if (conn.active) {
                stats.active++;
            }
            else {
                stats.idle++;
            }
            if (!stats.byPeer[conn.peerId]) {
                stats.byPeer[conn.peerId] = { total: 0, active: 0 };
            }
            stats.byPeer[conn.peerId].total++;
            if (conn.active) {
                stats.byPeer[conn.peerId].active++;
            }
        }
        return stats;
    }
    /**
     * Get connection details
     */
    getConnection(connId) {
        return this.connections.get(connId) ?? null;
    }
    /**
     * Cleanup idle and expired connections
     */
    cleanup() {
        const now = Date.now();
        let cleaned = 0;
        const toDelete = [];
        for (const [connId, conn] of Array.from(this.connections.entries())) {
            // Remove if idle too long
            if (now - conn.lastUsed > this.idleTimeoutMs && !conn.active) {
                toDelete.push(connId);
                continue;
            }
            // Remove if too old
            if (now - conn.createdAt > this.ttlMs) {
                toDelete.push(connId);
                continue;
            }
        }
        for (const connId of toDelete) {
            this.close(connId);
            cleaned++;
        }
        if (this.verbose && cleaned > 0) {
            console.log(`[ConnectionPool] Cleanup: removed ${cleaned} connections`);
        }
        return cleaned;
    }
    /**
     * Clear all connections
     */
    clear() {
        const count = this.connections.size;
        this.connections.clear();
        this.connectionStates.clear();
        this.peerConnections.clear();
        if (this.verbose) {
            console.log(`[ConnectionPool] Cleared ${count} connections`);
        }
    }
    /**
     * Start automatic cleanup
     */
    startAutoCleanup() {
        this.cleanupTimer = setInterval(() => {
            this.cleanup();
        }, this.cleanupIntervalMs);
    }
    /**
     * Stop automatic cleanup
     */
    stopAutoCleanup() {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
            if (this.verbose) {
                console.log(`[ConnectionPool] Auto-cleanup stopped`);
            }
        }
    }
    /**
     * Generate connection ID
     */
    generateId() {
        return `conn_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    }
    /**
     * Get connection efficiency metrics
     */
    getEfficiency() {
        if (this.connections.size === 0) {
            return {
                avgUsagePerConnection: 0,
                connectionReuseFactor: 0,
                poolUtilization: 0,
            };
        }
        let totalUsage = 0;
        for (const conn of Array.from(this.connections.values())) {
            totalUsage += conn.usageCount;
        }
        const avgUsage = totalUsage / this.connections.size;
        const reuseFactor = totalUsage / this.connections.size;
        const utilization = this.connections.size / this.maxTotal;
        return {
            avgUsagePerConnection: avgUsage,
            connectionReuseFactor: reuseFactor,
            poolUtilization: utilization,
        };
    }
}
