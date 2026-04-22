/**
 * Structured Logger for STVOR SDK
 *
 * Provides:
 * - JSON-formatted logging
 * - Metrics collection
 * - Performance tracking
 * - Error aggregation
 * - Integration with monitoring systems
 */
export interface LogLevel {
    level: 'debug' | 'info' | 'warn' | 'error';
    numeric: number;
}
export declare const LOG_LEVELS: {
    readonly debug: {
        readonly level: "debug";
        readonly numeric: 0;
    };
    readonly info: {
        readonly level: "info";
        readonly numeric: 1;
    };
    readonly warn: {
        readonly level: "warn";
        readonly numeric: 2;
    };
    readonly error: {
        readonly level: "error";
        readonly numeric: 3;
    };
};
export interface LogEntry {
    timestamp: string;
    level: string;
    component: string;
    message: string;
    data?: Record<string, any>;
    duration?: number;
    error?: string;
    traceId?: string;
}
export interface LoggerConfig {
    /** Minimum log level to output */
    minLevel?: 'debug' | 'info' | 'warn' | 'error';
    /** Component name */
    component?: string;
    /** Enable console output */
    consoleOutput?: boolean;
    /** Log to file path */
    filePath?: string;
    /** Enable metrics aggregation */
    enableMetrics?: boolean;
    /** Metrics flush interval (ms) */
    metricsInterval?: number;
}
export interface LoggerMetrics {
    totalLogs: number;
    logsByLevel: Record<string, number>;
    errorCount: number;
    warningCount: number;
    avgDuration: number;
    lastError?: string;
}
/**
 * Structured JSON logger
 */
export declare class StructuredLogger {
    private minLevel;
    private component;
    private consoleOutput;
    private filePath?;
    private enableMetrics;
    private metricsInterval;
    private metrics;
    private totalDuration;
    private durations;
    constructor(config?: LoggerConfig);
    /**
     * Create log entry
     */
    private createEntry;
    /**
     * Output log entry
     */
    private output;
    /**
     * Debug level log
     */
    debug(message: string, data?: Record<string, any>, duration?: number): void;
    /**
     * Info level log
     */
    info(message: string, data?: Record<string, any>, duration?: number): void;
    /**
     * Warning level log
     */
    warn(message: string, data?: Record<string, any>, duration?: number): void;
    /**
     * Error level log
     */
    error(message: string, data?: Record<string, any>, error?: Error): void;
    /**
     * Log with timing
     */
    timed<T>(message: string, fn: () => Promise<T> | T, data?: Record<string, any>): Promise<T>;
    timed<T>(message: string, fn: () => Promise<T> | T): Promise<T>;
    /**
     * Get current metrics
     */
    getMetrics(): LoggerMetrics;
    /**
     * Reset metrics
     */
    resetMetrics(): void;
    /**
     * Get color code for level
     */
    private getColorForLevel;
    /**
     * Generate trace ID
     */
    private generateTraceId;
    /**
     * Export metrics as JSON
     */
    exportMetrics(): string;
    /**
     * Create child logger with different component
     */
    child(component: string): StructuredLogger;
    /**
     * Format performance stats
     */
    getPerformanceStats(): {
        totalLogs: number;
        avgDuration: number;
        minDuration: number;
        maxDuration: number;
        p95Duration: number;
    };
}
/**
 * Initialize global logger
 */
export declare function initializeLogger(config?: LoggerConfig): StructuredLogger;
/**
 * Get global logger
 */
export declare function getLogger(component?: string): StructuredLogger;
