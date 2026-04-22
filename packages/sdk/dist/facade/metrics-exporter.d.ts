/**
 * Metrics Exporter for STVOR SDK
 *
 * Exports metrics to:
 * - Prometheus (text format)
 * - CloudWatch (JSON)
 * - StatsD
 * - Custom destinations
 */
export interface MetricValue {
    name: string;
    value: number;
    timestamp: number;
    labels?: Record<string, string>;
    help?: string;
}
export interface ExportFormat {
    format: 'prometheus' | 'json' | 'statsd' | 'custom';
    timestamp: number;
    metrics: MetricValue[];
}
export interface ExporterConfig {
    /** Export format */
    format?: 'prometheus' | 'json' | 'statsd';
    /** Service name for labeling */
    serviceName?: string;
    /** Namespace/prefix for metrics */
    namespace?: string;
    /** Enable compression */
    compressed?: boolean;
    /** Verbose logging */
    verbose?: boolean;
    /** Custom exporter function */
    customExporter?: (data: ExportFormat) => Promise<void>;
}
/**
 * Metrics collector and exporter
 */
export declare class MetricsExporter {
    private metrics;
    private format;
    private serviceName;
    private namespace;
    private compressed;
    private verbose;
    private customExporter?;
    private lastExport;
    private exportInterval;
    constructor(config?: ExporterConfig);
    /**
     * Record metric
     */
    recordMetric(name: string, value: number, labels?: Record<string, string>, help?: string): void;
    /**
     * Increment counter
     */
    incrementCounter(name: string, delta?: number, labels?: Record<string, string>): void;
    /**
     * Record gauge (e.g., current memory usage)
     */
    recordGauge(name: string, value: number, labels?: Record<string, string>): void;
    /**
     * Record histogram (e.g., response time)
     */
    recordHistogram(name: string, value: number, buckets?: number[], labels?: Record<string, string>): void;
    /**
     * Export metrics in Prometheus format
     */
    private exportPrometheus;
    /**
     * Export metrics as JSON
     */
    private exportJSON;
    /**
     * Export metrics as StatsD format
     */
    private exportStatsD;
    /**
     * Export metrics
     */
    export(): Promise<string>;
    /**
     * Start periodic export
     */
    startPeriodicExport(intervalMs?: number): void;
    /**
     * Stop periodic export
     */
    stopPeriodicExport(): void;
    /**
     * Get metrics summary
     */
    getSummary(): {
        totalMetrics: number;
        lastExportTime?: number;
        exportFormat: string;
        metrics: Record<string, number>;
    };
    /**
     * Clear all metrics
     */
    clear(): void;
    /**
     * Create Prometheus exporter (for use with Prometheus scrape endpoint)
     */
    static createPrometheus(serviceName?: string): MetricsExporter;
    /**
     * Create CloudWatch exporter
     */
    static createCloudWatch(customExporter: (data: ExportFormat) => Promise<void>): MetricsExporter;
    /**
     * Create StatsD exporter
     */
    static createStatsD(namespace?: string): MetricsExporter;
}
/**
 * Metrics collector (aggregates metrics from multiple sources)
 */
export declare class MetricsCollector {
    private exporters;
    /**
     * Register exporter
     */
    registerExporter(name: string, exporter: MetricsExporter): void;
    /**
     * Get exporter
     */
    getExporter(name: string): MetricsExporter | null;
    /**
     * Record metric across all exporters
     */
    recordMetric(name: string, value: number, labels?: Record<string, string>, help?: string): void;
    /**
     * Export all
     */
    exportAll(): Promise<Record<string, string>>;
    /**
     * Get all summaries
     */
    getAllSummaries(): Record<string, any>;
}
