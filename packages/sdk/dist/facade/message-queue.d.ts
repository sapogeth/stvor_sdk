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
    data: string;
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
export declare class MessageQueue {
    private queue;
    private maxQueueSize;
    private maxRetries;
    private initialBackoffMs;
    private maxBackoffMs;
    private persistencePath?;
    private verbose;
    private processInterval;
    constructor(config?: MessageQueueConfig);
    /**
     * Add message to queue
     */
    enqueue(recipient: string, data: string): string;
    /**
     * Get next message to retry
     */
    getNextToRetry(): QueuedMessage | null;
    /**
     * Mark message as successfully sent
     */
    markSuccess(id: string): void;
    /**
     * Mark message as failed (will retry)
     */
    markFailed(id: string, error?: string): void;
    /**
     * Get all pending messages
     */
    getPending(): QueuedMessage[];
    /**
     * Get messages for specific recipient
     */
    getForRecipient(recipient: string): QueuedMessage[];
    /**
     * Get queue size
     */
    size(): number;
    /**
     * Get queue status
     */
    getStatus(): {
        total: number;
        pending: number;
        byRecipient: Record<string, number>;
        nextRetryIn: number;
    };
    /**
     * Clear queue
     */
    clear(): void;
    /**
     * Remove specific message
     */
    remove(id: string): boolean;
    /**
     * Export queue for persistence
     */
    export(): string;
    /**
     * Import queue from persistence
     */
    import(data: string): void;
    /**
     * Generate unique ID
     */
    private generateId;
    /**
     * Start automatic retry processing
     */
    startAutoRetry(onRetry: (message: QueuedMessage) => Promise<void>): void;
    /**
     * Stop automatic retry processing
     */
    stopAutoRetry(): void;
}
