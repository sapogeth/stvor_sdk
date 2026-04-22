/**
 * Analytics Engine for STVOR SDK
 *
 * Collects and analyzes:
 * - Message flow patterns
 * - Performance metrics
 * - Error trends
 * - User behavior
 * - System health
 */
/**
 * Analytics engine
 */
export class AnalyticsEngine {
    constructor(config = {}) {
        this.events = [];
        this.rotationTimer = null;
        this.maxEventsInMemory = config.maxEventsInMemory ?? 10000;
        this.rotationIntervalMs = config.rotationIntervalMs ?? 3600000; // 1 hour
        this.verbose = config.verbose ?? false;
        if (this.verbose) {
            console.log(`[AnalyticsEngine] Initialized (${this.maxEventsInMemory} events, ${this.rotationIntervalMs}ms rotation)`);
        }
    }
    /**
     * Record event
     */
    recordEvent(event) {
        const fullEvent = {
            ...event,
            timestamp: Date.now(),
        };
        this.events.push(fullEvent);
        // Rotate if too many events
        if (this.events.length > this.maxEventsInMemory) {
            this.rotate();
        }
    }
    /**
     * Record message send
     */
    recordSend(peerId, dataSize, success, duration, error) {
        this.recordEvent({
            eventType: 'message_send',
            peerId,
            dataSize,
            duration,
            success,
            error,
        });
    }
    /**
     * Record message receive
     */
    recordReceive(peerId, dataSize, success, duration, error) {
        this.recordEvent({
            eventType: 'message_receive',
            peerId,
            dataSize,
            duration,
            success,
            error,
        });
    }
    /**
     * Record session establishment
     */
    recordSessionEstablish(peerId, success, duration, error) {
        this.recordEvent({
            eventType: 'session_establish',
            peerId,
            duration,
            success,
            error,
        });
    }
    /**
     * Record error
     */
    recordError(error, metadata) {
        this.recordEvent({
            eventType: 'error',
            success: false,
            error,
            metadata,
        });
    }
    /**
     * Generate analytics report
     */
    generateReport(fromTime, toTime) {
        const now = Date.now();
        const startTime = fromTime ?? now - 3600000; // Default: last hour
        const endTime = toTime ?? now;
        // Filter events in time range
        const filteredEvents = this.events.filter((e) => e.timestamp >= startTime && e.timestamp <= endTime);
        if (filteredEvents.length === 0) {
            return this.emptyReport(startTime, endTime);
        }
        // Calculate summary stats
        const successCount = filteredEvents.filter((e) => e.success).length;
        const failureCount = filteredEvents.length - successCount;
        const successRate = (successCount / filteredEvents.length) * 100;
        // Calculate performance stats
        const durations = filteredEvents
            .filter((e) => e.duration)
            .map((e) => e.duration)
            .sort((a, b) => a - b);
        const avgDuration = durations.length > 0
            ? durations.reduce((a, b) => a + b, 0) / durations.length
            : 0;
        const p95Index = Math.floor(durations.length * 0.95);
        const p99Index = Math.floor(durations.length * 0.99);
        // Calculate throughput
        const totalBytes = filteredEvents.reduce((sum, e) => sum + (e.dataSize ?? 0), 0);
        const durationSec = (endTime - startTime) / 1000;
        const eventsPerSecond = filteredEvents.length / durationSec;
        const bytesPerSecond = totalBytes / durationSec;
        // Group by event type
        const byEventType = {};
        for (const event of filteredEvents) {
            if (!byEventType[event.eventType]) {
                byEventType[event.eventType] = {
                    count: 0,
                    success: 0,
                    failure: 0,
                    totalBytes: 0,
                    errors: new Set(),
                };
            }
            byEventType[event.eventType].count++;
            if (event.success) {
                byEventType[event.eventType].success++;
            }
            else {
                byEventType[event.eventType].failure++;
            }
            byEventType[event.eventType].totalBytes += event.dataSize ?? 0;
            if (event.error) {
                byEventType[event.eventType].errors.add(event.error);
            }
        }
        // Convert Sets to arrays
        const cleanedByEventType = {};
        for (const [key, value] of Object.entries(byEventType)) {
            cleanedByEventType[key] = {
                ...value,
                errors: Array.from(value.errors),
            };
        }
        // Top peers
        const peerStats = new Map();
        for (const event of filteredEvents) {
            if (!event.peerId)
                continue;
            if (!peerStats.has(event.peerId)) {
                peerStats.set(event.peerId, { count: 0, success: 0, failure: 0, totalBytes: 0 });
            }
            const stats = peerStats.get(event.peerId);
            stats.count++;
            if (event.success) {
                stats.success++;
            }
            else {
                stats.failure++;
            }
            stats.totalBytes += event.dataSize ?? 0;
        }
        const topPeers = Array.from(peerStats.entries())
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, 10)
            .map(([peerId, stats]) => ({
            peerId,
            eventCount: stats.count,
            successRate: (stats.success / stats.count) * 100,
            totalBytes: stats.totalBytes,
        }));
        // Error analysis
        const errorMap = new Map();
        for (const event of filteredEvents) {
            if (event.error) {
                errorMap.set(event.error, (errorMap.get(event.error) ?? 0) + 1);
            }
        }
        const topErrors = Array.from(errorMap.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([error, count]) => ({
            error,
            count,
            percentage: (count / failureCount) * 100,
        }));
        return {
            period: {
                startTime,
                endTime,
                durationMs: endTime - startTime,
            },
            summary: {
                totalEvents: filteredEvents.length,
                successCount,
                failureCount,
                successRate: Math.round(successRate * 100) / 100,
            },
            byEventType: cleanedByEventType,
            performance: {
                avgDurationMs: Math.round(avgDuration * 100) / 100,
                minDurationMs: durations.length > 0 ? durations[0] : 0,
                maxDurationMs: durations.length > 0 ? durations[durations.length - 1] : 0,
                p95DurationMs: durations.length > 0 ? durations[p95Index] : 0,
                p99DurationMs: durations.length > 0 ? durations[p99Index] : 0,
            },
            throughput: {
                eventsPerSecond: Math.round(eventsPerSecond * 100) / 100,
                bytesPerSecond: Math.round(bytesPerSecond * 100) / 100,
                totalBytes,
            },
            topPeers,
            errors: {
                totalErrors: failureCount,
                topErrors,
            },
        };
    }
    /**
     * Empty report for no data
     */
    emptyReport(startTime, endTime) {
        return {
            period: {
                startTime,
                endTime,
                durationMs: endTime - startTime,
            },
            summary: {
                totalEvents: 0,
                successCount: 0,
                failureCount: 0,
                successRate: 0,
            },
            byEventType: {},
            performance: {
                avgDurationMs: 0,
                minDurationMs: 0,
                maxDurationMs: 0,
                p95DurationMs: 0,
                p99DurationMs: 0,
            },
            throughput: {
                eventsPerSecond: 0,
                bytesPerSecond: 0,
                totalBytes: 0,
            },
            topPeers: [],
            errors: {
                totalErrors: 0,
                topErrors: [],
            },
        };
    }
    /**
     * Rotate events (keep only recent)
     */
    rotate() {
        // Keep only most recent half
        const keepCount = Math.floor(this.maxEventsInMemory / 2);
        this.events = this.events.slice(-keepCount);
        if (this.verbose) {
            console.log(`[AnalyticsEngine] Rotated events (${this.events.length} kept)`);
        }
    }
    /**
     * Get event count
     */
    getEventCount() {
        return this.events.length;
    }
    /**
     * Clear all events
     */
    clear() {
        this.events = [];
        if (this.verbose) {
            console.log(`[AnalyticsEngine] Cleared all events`);
        }
    }
    /**
     * Export events as JSON
     */
    exportEvents(fromTime, toTime) {
        const now = Date.now();
        const startTime = fromTime ?? now - 3600000;
        const endTime = toTime ?? now;
        return this.events.filter((e) => e.timestamp >= startTime && e.timestamp <= endTime);
    }
}
