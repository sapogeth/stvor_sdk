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
export class MetricsExporter {
  private metrics: Map<string, MetricValue> = new Map();
  private format: 'prometheus' | 'json' | 'statsd';
  private serviceName: string;
  private namespace: string;
  private compressed: boolean;
  private verbose: boolean;
  private customExporter?: (data: ExportFormat) => Promise<void>;
  private lastExport: number = 0;
  private exportInterval: NodeJS.Timeout | null = null;

  constructor(config: ExporterConfig = {}) {
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
  recordMetric(
    name: string,
    value: number,
    labels?: Record<string, string>,
    help?: string,
  ): void {
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
  incrementCounter(name: string, delta: number = 1, labels?: Record<string, string>): void {
    const fullName = `${this.namespace}_${name}`;
    const existing = this.metrics.get(fullName);
    const value = (existing?.value ?? 0) + delta;

    this.recordMetric(name, value, labels);
  }

  /**
   * Record gauge (e.g., current memory usage)
   */
  recordGauge(name: string, value: number, labels?: Record<string, string>): void {
    this.recordMetric(name, value, labels);
  }

  /**
   * Record histogram (e.g., response time)
   */
  recordHistogram(
    name: string,
    value: number,
    buckets: number[] = [1, 5, 10, 50, 100, 500, 1000],
    labels?: Record<string, string>,
  ): void {
    // Record main value
    this.recordMetric(`${name}_total`, value, labels);

    // Record bucket counts
    for (const bucket of buckets) {
      if (value <= bucket) {
        this.incrementCounter(
          `${name}_bucket`,
          1,
          { ...labels, le: String(bucket) },
        );
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
  private exportPrometheus(): string {
    let output = '';

    // Group by metric name prefix
    const grouped = new Map<string, MetricValue[]>();

    for (const metric of Array.from(this.metrics.values())) {
      const prefix = metric.name.split('_').slice(0, -1).join('_');
      if (!grouped.has(prefix)) {
        grouped.set(prefix, []);
      }
      grouped.get(prefix)!.push(metric);
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
  private exportJSON(): string {
    const data: ExportFormat = {
      format: 'json',
      timestamp: Date.now(),
      metrics: Array.from(this.metrics.values()),
    };

    return JSON.stringify(data, null, 2);
  }

  /**
   * Export metrics as StatsD format
   */
  private exportStatsD(): string {
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
  async export(): Promise<string> {
    let data: string;

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
        format: this.format as any,
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
  startPeriodicExport(intervalMs: number = 60000): void {
    if (this.exportInterval) {
      clearInterval(this.exportInterval);
    }

    this.exportInterval = setInterval(async () => {
      try {
        await this.export();
      } catch (error) {
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
  stopPeriodicExport(): void {
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
  getSummary(): {
    totalMetrics: number;
    lastExportTime?: number;
    exportFormat: string;
    metrics: Record<string, number>;
  } {
    const metrics: Record<string, number> = {};

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
  clear(): void {
    this.metrics.clear();
    if (this.verbose) {
      console.log(`[MetricsExporter] Cleared all metrics`);
    }
  }

  /**
   * Create Prometheus exporter (for use with Prometheus scrape endpoint)
   */
  static createPrometheus(serviceName: string = 'stvor'): MetricsExporter {
    return new MetricsExporter({
      format: 'prometheus',
      serviceName,
      namespace: 'stvor',
    });
  }

  /**
   * Create CloudWatch exporter
   */
  static createCloudWatch(
    customExporter: (data: ExportFormat) => Promise<void>,
  ): MetricsExporter {
    return new MetricsExporter({
      format: 'json',
      customExporter,
    });
  }

  /**
   * Create StatsD exporter
   */
  static createStatsD(namespace: string = 'stvor'): MetricsExporter {
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
  private exporters: Map<string, MetricsExporter> = new Map();

  /**
   * Register exporter
   */
  registerExporter(name: string, exporter: MetricsExporter): void {
    this.exporters.set(name, exporter);
  }

  /**
   * Get exporter
   */
  getExporter(name: string): MetricsExporter | null {
    return this.exporters.get(name) ?? null;
  }

  /**
   * Record metric across all exporters
   */
  recordMetric(
    name: string,
    value: number,
    labels?: Record<string, string>,
    help?: string,
  ): void {
    for (const exporter of Array.from(this.exporters.values())) {
      exporter.recordMetric(name, value, labels, help);
    }
  }

  /**
   * Export all
   */
  async exportAll(): Promise<Record<string, string>> {
    const results: Record<string, string> = {};

    for (const [name, exporter] of Array.from(this.exporters.entries())) {
      try {
        results[name] = await exporter.export();
      } catch (error) {
        console.error(`[MetricsCollector] Export from ${name} failed:`, error);
      }
    }

    return results;
  }

  /**
   * Get all summaries
   */
  getAllSummaries(): Record<string, any> {
    const results: Record<string, any> = {};

    for (const [name, exporter] of Array.from(this.exporters.entries())) {
      results[name] = exporter.getSummary();
    }

    return results;
  }
}
