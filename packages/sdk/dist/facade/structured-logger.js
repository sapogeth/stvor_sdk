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
export const LOG_LEVELS = {
    debug: { level: 'debug', numeric: 0 },
    info: { level: 'info', numeric: 1 },
    warn: { level: 'warn', numeric: 2 },
    error: { level: 'error', numeric: 3 },
};
/**
 * Structured JSON logger
 */
export class StructuredLogger {
    constructor(config = {}) {
        this.metrics = {
            totalLogs: 0,
            logsByLevel: {
                debug: 0,
                info: 0,
                warn: 0,
                error: 0,
            },
            errorCount: 0,
            warningCount: 0,
            avgDuration: 0,
        };
        this.totalDuration = 0;
        this.durations = [];
        this.minLevel = LOG_LEVELS[config.minLevel ?? 'info'].numeric;
        this.component = config.component ?? 'SDK';
        this.consoleOutput = config.consoleOutput ?? true;
        this.filePath = config.filePath;
        this.enableMetrics = config.enableMetrics ?? true;
        this.metricsInterval = config.metricsInterval ?? 60000; // 1 minute
    }
    /**
     * Create log entry
     */
    createEntry(level, message, data, duration) {
        return {
            timestamp: new Date().toISOString(),
            level,
            component: this.component,
            message,
            data,
            duration,
            traceId: this.generateTraceId(),
        };
    }
    /**
     * Output log entry
     */
    output(entry) {
        const levelNumeric = LOG_LEVELS[entry.level].numeric;
        if (levelNumeric < this.minLevel) {
            return;
        }
        // Console output
        if (this.consoleOutput) {
            const json = JSON.stringify(entry);
            const color = this.getColorForLevel(entry.level);
            console.log(`${color}${json}\x1b[0m`);
        }
        // Update metrics
        if (this.enableMetrics) {
            this.metrics.totalLogs++;
            this.metrics.logsByLevel[entry.level]++;
            if (entry.level === 'error') {
                this.metrics.errorCount++;
                this.metrics.lastError = entry.message;
            }
            if (entry.level === 'warn') {
                this.metrics.warningCount++;
            }
            if (entry.duration) {
                this.totalDuration += entry.duration;
                this.durations.push(entry.duration);
                this.metrics.avgDuration = this.totalDuration / this.durations.length;
            }
        }
    }
    /**
     * Debug level log
     */
    debug(message, data, duration) {
        this.output(this.createEntry('debug', message, data, duration));
    }
    /**
     * Info level log
     */
    info(message, data, duration) {
        this.output(this.createEntry('info', message, data, duration));
    }
    /**
     * Warning level log
     */
    warn(message, data, duration) {
        this.output(this.createEntry('warn', message, data, duration));
    }
    /**
     * Error level log
     */
    error(message, data, error) {
        const entry = this.createEntry('error', message, data);
        if (error) {
            entry.error = error.message;
        }
        this.output(entry);
    }
    async timed(message, fn, data) {
        const startTime = performance.now();
        try {
            const result = await fn();
            const duration = performance.now() - startTime;
            this.info(`${message} (${duration.toFixed(2)}ms)`, data, duration);
            return result;
        }
        catch (error) {
            const duration = performance.now() - startTime;
            this.error(message, { ...data, duration }, error);
            throw error;
        }
    }
    /**
     * Get current metrics
     */
    getMetrics() {
        return { ...this.metrics };
    }
    /**
     * Reset metrics
     */
    resetMetrics() {
        this.metrics = {
            totalLogs: 0,
            logsByLevel: {
                debug: 0,
                info: 0,
                warn: 0,
                error: 0,
            },
            errorCount: 0,
            warningCount: 0,
            avgDuration: 0,
        };
        this.totalDuration = 0;
        this.durations = [];
    }
    /**
     * Get color code for level
     */
    getColorForLevel(level) {
        switch (level) {
            case 'debug':
                return '\x1b[36m'; // Cyan
            case 'info':
                return '\x1b[32m'; // Green
            case 'warn':
                return '\x1b[33m'; // Yellow
            case 'error':
                return '\x1b[31m'; // Red
            default:
                return '\x1b[0m'; // Reset
        }
    }
    /**
     * Generate trace ID
     */
    generateTraceId() {
        return `trace_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    }
    /**
     * Export metrics as JSON
     */
    exportMetrics() {
        return JSON.stringify(this.getMetrics(), null, 2);
    }
    /**
     * Create child logger with different component
     */
    child(component) {
        return new StructuredLogger({
            minLevel: this.minLevel,
            component,
            consoleOutput: this.consoleOutput,
            filePath: this.filePath,
            enableMetrics: this.enableMetrics,
        });
    }
    /**
     * Format performance stats
     */
    getPerformanceStats() {
        const sorted = [...this.durations].sort((a, b) => a - b);
        const p95Index = Math.floor(sorted.length * 0.95);
        return {
            totalLogs: this.metrics.totalLogs,
            avgDuration: this.metrics.avgDuration,
            minDuration: sorted.length > 0 ? sorted[0] : 0,
            maxDuration: sorted.length > 0 ? sorted[sorted.length - 1] : 0,
            p95Duration: sorted.length > 0 ? sorted[p95Index] : 0,
        };
    }
}
/**
 * Global logger instance
 */
let globalLogger = null;
/**
 * Initialize global logger
 */
export function initializeLogger(config = {}) {
    globalLogger = new StructuredLogger(config);
    return globalLogger;
}
/**
 * Get global logger
 */
export function getLogger(component) {
    if (!globalLogger) {
        globalLogger = new StructuredLogger({ component });
    }
    return component ? globalLogger.child(component) : globalLogger;
}
