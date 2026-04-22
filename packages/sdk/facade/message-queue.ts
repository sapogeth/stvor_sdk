/**
 * Message Queue for STVOR SDK
 * 
 * Handles:
 * - Message persistence when offline
 * - Automatic retry with backoff
 * - Conflict resolution
 * - Queue management
 * 
 * Stores failed/pending messages for later delivery
 */

export interface QueuedMessage {
  id: string;
  recipient: string;
  data: string; // base64url encoded
  timestamp: number;
  retries: number;
  maxRetries: number;
  backoffMs: number;
  nextRetry: number;
  error?: string;
}

export interface MessageQueueConfig {
  /** Max messages in queue */
  maxQueueSize?: number;
  /** Max retry attempts */
  maxRetries?: number;
  /** Initial backoff in ms */
  initialBackoffMs?: number;
  /** Max backoff in ms */
  maxBackoffMs?: number;
  /** Persistence path (optional) */
  persistencePath?: string;
  /** Enable verbose logging */
  verbose?: boolean;
}

/**
 * Message queue for offline support
 */
export class MessageQueue {
  private queue: Map<string, QueuedMessage> = new Map();
  private maxQueueSize: number;
  private maxRetries: number;
  private initialBackoffMs: number;
  private maxBackoffMs: number;
  private persistencePath?: string;
  private verbose: boolean;
  private processInterval: NodeJS.Timeout | null = null;

  constructor(config: MessageQueueConfig = {}) {
    this.maxQueueSize = config.maxQueueSize ?? 10000;
    this.maxRetries = config.maxRetries ?? 5;
    this.initialBackoffMs = config.initialBackoffMs ?? 1000; // 1 sec
    this.maxBackoffMs = config.maxBackoffMs ?? 60000; // 1 minute
    this.persistencePath = config.persistencePath;
    this.verbose = config.verbose ?? false;

    if (this.verbose) {
      console.log(`[MessageQueue] Initialized (max: ${this.maxQueueSize}, retries: ${this.maxRetries})`);
    }
  }

  /**
   * Add message to queue
   */
  enqueue(recipient: string, data: string): string {
    if (this.queue.size >= this.maxQueueSize) {
      throw new Error(`Queue full (${this.maxQueueSize} messages)`);
    }

    const id = this.generateId();
    const message: QueuedMessage = {
      id,
      recipient,
      data,
      timestamp: Date.now(),
      retries: 0,
      maxRetries: this.maxRetries,
      backoffMs: this.initialBackoffMs,
      nextRetry: Date.now() + this.initialBackoffMs,
    };

    this.queue.set(id, message);

    if (this.verbose) {
      console.log(`[MessageQueue] Enqueued: ${id} to ${recipient}`);
    }

    return id;
  }

  /**
   * Get next message to retry
   */
  getNextToRetry(): QueuedMessage | null {
    const now = Date.now();

    for (const message of Array.from(this.queue.values())) {
      if (message.nextRetry <= now && message.retries < message.maxRetries) {
        return message;
      }
    }

    return null;
  }

  /**
   * Mark message as successfully sent
   */
  markSuccess(id: string): void {
    const message = this.queue.get(id);
    if (message) {
      this.queue.delete(id);
      if (this.verbose) {
        console.log(`[MessageQueue] Success: ${id} (${message.retries} retries)`);
      }
    }
  }

  /**
   * Mark message as failed (will retry)
   */
  markFailed(id: string, error?: string): void {
    const message = this.queue.get(id);
    if (!message) return;

    message.retries++;
    message.error = error;

    if (message.retries >= message.maxRetries) {
      this.queue.delete(id);
      if (this.verbose) {
        console.warn(`[MessageQueue] Expired: ${id} (max retries reached)`);
      }
      return;
    }

    // Exponential backoff
    message.backoffMs = Math.min(
      this.maxBackoffMs,
      message.backoffMs * 2 + Math.random() * 1000,
    );
    message.nextRetry = Date.now() + message.backoffMs;

    if (this.verbose) {
      console.log(
        `[MessageQueue] Failed: ${id} (retry ${message.retries}/${message.maxRetries}, wait ${message.backoffMs}ms)`,
      );
    }
  }

  /**
   * Get all pending messages
   */
  getPending(): QueuedMessage[] {
    return Array.from(this.queue.values()).filter((m) => m.retries < m.maxRetries);
  }

  /**
   * Get messages for specific recipient
   */
  getForRecipient(recipient: string): QueuedMessage[] {
    return Array.from(this.queue.values()).filter((m) => m.recipient === recipient);
  }

  /**
   * Get queue size
   */
  size(): number {
    return this.queue.size;
  }

  /**
   * Get queue status
   */
  getStatus(): {
    total: number;
    pending: number;
    byRecipient: Record<string, number>;
    nextRetryIn: number;
  } {
    const now = Date.now();
    const pending = Array.from(this.queue.values()).filter((m) => m.retries < m.maxRetries);
    const byRecipient: Record<string, number> = {};

    for (const message of pending) {
      byRecipient[message.recipient] = (byRecipient[message.recipient] || 0) + 1;
    }

    const nextRetry = pending.length > 0 ? Math.min(...pending.map((m) => m.nextRetry)) : -1;
    const nextRetryIn = nextRetry >= 0 ? Math.max(0, nextRetry - now) : 0;

    return {
      total: this.queue.size,
      pending: pending.length,
      byRecipient,
      nextRetryIn,
    };
  }

  /**
   * Clear queue
   */
  clear(): void {
    const count = this.queue.size;
    this.queue.clear();
    if (this.verbose) {
      console.log(`[MessageQueue] Cleared ${count} messages`);
    }
  }

  /**
   * Remove specific message
   */
  remove(id: string): boolean {
    const removed = this.queue.delete(id);
    if (removed && this.verbose) {
      console.log(`[MessageQueue] Removed: ${id}`);
    }
    return removed;
  }

  /**
   * Export queue for persistence
   */
  export(): string {
    const messages = Array.from(this.queue.values());
    return JSON.stringify(messages);
  }

  /**
   * Import queue from persistence
   */
  import(data: string): void {
    try {
      const messages = JSON.parse(data) as QueuedMessage[];
      this.queue.clear();

      for (const message of messages) {
        this.queue.set(message.id, message);
      }

      if (this.verbose) {
        console.log(`[MessageQueue] Imported ${messages.length} messages`);
      }
    } catch (error) {
      console.error(`[MessageQueue] Import failed:`, error);
    }
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `msg_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Start automatic retry processing
   */
  startAutoRetry(onRetry: (message: QueuedMessage) => Promise<void>): void {
    if (this.processInterval) {
      clearInterval(this.processInterval);
    }

    this.processInterval = setInterval(async () => {
      const message = this.getNextToRetry();
      if (message) {
        try {
          await onRetry(message);
          this.markSuccess(message.id);
        } catch (error) {
          this.markFailed(message.id, String(error));
        }
      }
    }, 100);

    if (this.verbose) {
      console.log(`[MessageQueue] Auto-retry started`);
    }
  }

  /**
   * Stop automatic retry processing
   */
  stopAutoRetry(): void {
    if (this.processInterval) {
      clearInterval(this.processInterval);
      this.processInterval = null;

      if (this.verbose) {
        console.log(`[MessageQueue] Auto-retry stopped`);
      }
    }
  }
}
