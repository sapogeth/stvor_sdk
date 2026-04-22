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
export interface AnalyticsEvent {
    timestamp: number;
    eventType: string;
    peerId?: string;
    dataSize?: number;
    duration?: number;
    success: boolean;
    error?: string;
    metadata?: Record<string, any>;
}
export interface AnalyticsReport {
    period: {
        startTime: number;
        endTime: number;
        durationMs: number;
    };
    summary: {
        totalEvents: number;
        successCount: number;
        failureCount: number;
        successRate: number;
    };
    byEventType: Record<string, any>;
    performance: {
        avgDurationMs: number;
        minDurationMs: number;
        maxDurationMs: number;
        p95DurationMs: number;
        p99DurationMs: number;
    };
    throughput: {
        eventsPerSecond: number;
        bytesPerSecond: number;
        totalBytes: number;
    };
    topPeers: Array<{
        peerId: string;
        eventCount: number;
        successRate: number;
        totalBytes: number;
    }>;
    errors: {
        totalErrors: number;
        topErrors: Array<{
            error: string;
            count: number;
            percentage: number;
        }>;
    };
}
/**
 * Analytics engine
 */
export declare class AnalyticsEngine {
    private events;
    private maxEventsInMemory;
    private rotationIntervalMs;
    private rotationTimer;
    private verbose;
    constructor(config?: {
        maxEventsInMemory?: number;
        rotationIntervalMs?: number;
        verbose?: boolean;
    });
    /**
     * Record event
     */
    recordEvent(event: Omit<AnalyticsEvent, 'timestamp'>): void;
    /**
     * Record message send
     */
    recordSend(peerId: string, dataSize: number, success: boolean, duration?: number, error?: string): void;
    /**
     * Record message receive
     */
    recordReceive(peerId: string, dataSize: number, success: boolean, duration?: number, error?: string): void;
    /**
     * Record session establishment
     */
    recordSessionEstablish(peerId: string, success: boolean, duration?: number, error?: string): void;
    /**
     * Record error
     */
    recordError(error: string, metadata?: Record<string, any>): void;
    /**
     * Generate analytics report
     */
    generateReport(fromTime?: number, toTime?: number): AnalyticsReport;
    /**
     * Empty report for no data
     */
    private emptyReport;
    /**
     * Rotate events (keep only recent)
     */
    private rotate;
    /**
     * Get event count
     */
    getEventCount(): number;
    /**
     * Clear all events
     */
    clear(): void;
    /**
     * Export events as JSON
     */
    exportEvents(fromTime?: number, toTime?: number): AnalyticsEvent[];
}
