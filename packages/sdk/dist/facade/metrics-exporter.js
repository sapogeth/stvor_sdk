/**
 * Metrics Exporter for STVOR SDK
 *
 * Exports metrics to:
 * - Prometheus (text format)
 * - CloudWatch (JSON)
 * - StatsD
 * - Custom destinations
 */
/**
 * Metrics collector and exporter
 */
export class MetricsExporter {
    constructor(config = {}) {
        this.metrics = new Map();
        this.lastExport = 0;
        this.exportInterval = null;
        this.format = config.format ?? 'prometheus';
        this.serviceName = config.serviceName ?? 'stvor-sdk';
        this.namespace = config.namespace ?? 'stvor';
        this.compressed = config.compressed ?? false;
        this.verbose = config.verbose ?? false;
        this.customExporter = config.customExporter;
        if (this.verbose) {
            console.log(`[MetricsExporter] Initialized: ${this.format} format`);
        }
    }
    /**
     * Record metric
     */
    recordMetric(name, value, labels, help) {
        const fullName = `${this.namespace}_${name}`;
        this.metrics.set(fullName, {
            name: fullName,
            value,
            timestamp: Date.now(),
            labels: { service: this.serviceName, ...labels },
            help,
        });
    }
    /**
     * Increment counter
     */
    incrementCounter(name, delta = 1, labels) {
        const fullName = `${this.namespace}_${name}`;
        const existing = this.metrics.get(fullName);
        const value = (existing?.value ?? 0) + delta;
        this.recordMetric(name, value, labels);
    }
    /**
     * Record gauge (e.g., current memory usage)
     */
    recordGauge(name, value, labels) {
        this.recordMetric(name, value, labels);
    }
    /**
     * Record histogram (e.g., response time)
     */
    recordHistogram(name, value, buckets = [1, 5, 10, 50, 100, 500, 1000], labels) {
        // Record main value
        this.recordMetric(`${name}_total`, value, labels);
        // Record bucket counts
        for (const bucket of buckets) {
            if (value <= bucket) {
                this.incrementCounter(`${name}_bucket`, 1, { ...labels, le: String(bucket) });
            }
        }
        // Record sum for average calculation
        const sumName = `${this.namespace}_${name}_sum`;
        const existingSum = this.metrics.get(sumName);
        this.metrics.set(sumName, {
            name: sumName,
            value: (existingSum?.value ?? 0) + value,
            timestamp: Date.now(),
            labels,
        });
        // Increment count
        this.incrementCounter(`${name}_count`, 1, labels);
    }
    /**
     * Export metrics in Prometheus format
     */
    exportPrometheus() {
        let output = '';
        // Group by metric name prefix
        const grouped = new Map();
        for (const metric of Array.from(this.metrics.values())) {
            const prefix = metric.name.split('_').slice(0, -1).join('_');
            if (!grouped.has(prefix)) {
                grouped.set(prefix, []);
            }
            grouped.get(prefix).push(metric);
        }
        // Format each metric
        for (const [prefix, metrics] of Array.from(grouped.entries())) {
            const firstMetric = metrics[0];
            if (firstMetric.help) {
                output += `# HELP ${prefix} ${firstMetric.help}\n`;
            }
            output += `# TYPE ${prefix} gauge\n`;
            for (const metric of metrics) {
                const labels = metric.labels
                    ? `{${Object.entries(metric.labels)
                        .map(([k, v]) => `${k}="${v}"`)
                        .join(', ')}}`
                    : '';
                output += `${metric.name}${labels} ${metric.value}\n`;
            }
            output += '\n';
        }
        return output;
    }
    /**
     * Export metrics as JSON
     */
    exportJSON() {
        const data = {
            format: 'json',
            timestamp: Date.now(),
            metrics: Array.from(this.metrics.values()),
        };
        return JSON.stringify(data, null, 2);
    }
    /**
     * Export metrics as StatsD format
     */
    exportStatsD() {
        let output = '';
        for (const metric of Array.from(this.metrics.values())) {
            // StatsD format: metric_name:value|type
            // Using 'g' for gauge (most common for our use case)
            output += `${metric.name}:${metric.value}|g\n`;
        }
        return output;
    }
    /**
     * Export metrics
     */
    async export() {
        let data;
        switch (this.format) {
            case 'prometheus':
                data = this.exportPrometheus();
                break;
            case 'json':
                data = this.exportJSON();
                break;
            case 'statsd':
                data = this.exportStatsD();
                break;
            default:
                data = this.exportJSON();
        }
        if (this.compressed) {
            // In real implementation, would compress with gzip
            // data = gzip(data);
        }
        this.lastExport = Date.now();
        // Call custom exporter if provided
        if (this.customExporter) {
            await this.customExporter({
                format: this.format,
                timestamp: this.lastExport,
                metrics: Array.from(this.metrics.values()),
            });
        }
        if (this.verbose) {
            console.log(`[MetricsExporter] Exported ${this.metrics.size} metrics (${data.length} bytes)`);
        }
        return data;
    }
    /**
     * Start periodic export
     */
    startPeriodicExport(intervalMs = 60000) {
        if (this.exportInterval) {
            clearInterval(this.exportInterval);
        }
        this.exportInterval = setInterval(async () => {
            try {
                await this.export();
            }
            catch (error) {
                console.error(`[MetricsExporter] Export failed:`, error);
            }
        }, intervalMs);
        if (this.verbose) {
            console.log(`[MetricsExporter] Periodic export started (${intervalMs}ms)`);
        }
    }
    /**
     * Stop periodic export
     */
    stopPeriodicExport() {
        if (this.exportInterval) {
            clearInterval(this.exportInterval);
            this.exportInterval = null;
            if (this.verbose) {
                console.log(`[MetricsExporter] Periodic export stopped`);
            }
        }
    }
    /**
     * Get metrics summary
     */
    getSummary() {
        const metrics = {};
        for (const [name, value] of Array.from(this.metrics.entries())) {
            metrics[name] = value.value;
        }
        return {
            totalMetrics: this.metrics.size,
            lastExportTime: this.lastExport > 0 ? this.lastExport : undefined,
            exportFormat: this.format,
            metrics,
        };
    }
    /**
     * Clear all metrics
     */
    clear() {
        this.metrics.clear();
        if (this.verbose) {
            console.log(`[MetricsExporter] Cleared all metrics`);
        }
    }
    /**
     * Create Prometheus exporter (for use with Prometheus scrape endpoint)
     */
    static createPrometheus(serviceName = 'stvor') {
        return new MetricsExporter({
            format: 'prometheus',
            serviceName,
            namespace: 'stvor',
        });
    }
    /**
     * Create CloudWatch exporter
     */
    static createCloudWatch(customExporter) {
        return new MetricsExporter({
            format: 'json',
            customExporter,
        });
    }
    /**
     * Create StatsD exporter
     */
    static createStatsD(namespace = 'stvor') {
        return new MetricsExporter({
            format: 'statsd',
            namespace,
        });
    }
}
/**
 * Metrics collector (aggregates metrics from multiple sources)
 */
export class MetricsCollector {
    constructor() {
        this.exporters = new Map();
    }
    /**
     * Register exporter
     */
    registerExporter(name, exporter) {
        this.exporters.set(name, exporter);
    }
    /**
     * Get exporter
     */
    getExporter(name) {
        return this.exporters.get(name) ?? null;
    }
    /**
     * Record metric across all exporters
     */
    recordMetric(name, value, labels, help) {
        for (const exporter of Array.from(this.exporters.values())) {
            exporter.recordMetric(name, value, labels, help);
        }
    }
    /**
     * Export all
     */
    async exportAll() {
        const results = {};
        for (const [name, exporter] of Array.from(this.exporters.entries())) {
            try {
                results[name] = await exporter.export();
            }
            catch (error) {
                console.error(`[MetricsCollector] Export from ${name} failed:`, error);
            }
        }
        return results;
    }
    /**
     * Get all summaries
     */
    getAllSummaries() {
        const results = {};
        for (const [name, exporter] of Array.from(this.exporters.entries())) {
            results[name] = exporter.getSummary();
        }
        return results;
    }
}
