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
/**
 * Message queue for offline support
 */
export class MessageQueue {
    constructor(config = {}) {
        this.queue = new Map();
        this.processInterval = null;
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
    enqueue(recipient, data) {
        if (this.queue.size >= this.maxQueueSize) {
            throw new Error(`Queue full (${this.maxQueueSize} messages)`);
        }
        const id = this.generateId();
        const message = {
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
    getNextToRetry() {
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
    markSuccess(id) {
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
    markFailed(id, error) {
        const message = this.queue.get(id);
        if (!message)
            return;
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
        message.backoffMs = Math.min(this.maxBackoffMs, message.backoffMs * 2 + Math.random() * 1000);
        message.nextRetry = Date.now() + message.backoffMs;
        if (this.verbose) {
            console.log(`[MessageQueue] Failed: ${id} (retry ${message.retries}/${message.maxRetries}, wait ${message.backoffMs}ms)`);
        }
    }
    /**
     * Get all pending messages
     */
    getPending() {
        return Array.from(this.queue.values()).filter((m) => m.retries < m.maxRetries);
    }
    /**
     * Get messages for specific recipient
     */
    getForRecipient(recipient) {
        return Array.from(this.queue.values()).filter((m) => m.recipient === recipient);
    }
    /**
     * Get queue size
     */
    size() {
        return this.queue.size;
    }
    /**
     * Get queue status
     */
    getStatus() {
        const now = Date.now();
        const pending = Array.from(this.queue.values()).filter((m) => m.retries < m.maxRetries);
        const byRecipient = {};
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
    clear() {
        const count = this.queue.size;
        this.queue.clear();
        if (this.verbose) {
            console.log(`[MessageQueue] Cleared ${count} messages`);
        }
    }
    /**
     * Remove specific message
     */
    remove(id) {
        const removed = this.queue.delete(id);
        if (removed && this.verbose) {
            console.log(`[MessageQueue] Removed: ${id}`);
        }
        return removed;
    }
    /**
     * Export queue for persistence
     */
    export() {
        const messages = Array.from(this.queue.values());
        return JSON.stringify(messages);
    }
    /**
     * Import queue from persistence
     */
    import(data) {
        try {
            const messages = JSON.parse(data);
            this.queue.clear();
            for (const message of messages) {
                this.queue.set(message.id, message);
            }
            if (this.verbose) {
                console.log(`[MessageQueue] Imported ${messages.length} messages`);
            }
        }
        catch (error) {
            console.error(`[MessageQueue] Import failed:`, error);
        }
    }
    /**
     * Generate unique ID
     */
    generateId() {
        return `msg_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    }
    /**
     * Start automatic retry processing
     */
    startAutoRetry(onRetry) {
        if (this.processInterval) {
            clearInterval(this.processInterval);
        }
        this.processInterval = setInterval(async () => {
            const message = this.getNextToRetry();
            if (message) {
                try {
                    await onRetry(message);
                    this.markSuccess(message.id);
                }
                catch (error) {
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
    stopAutoRetry() {
        if (this.processInterval) {
            clearInterval(this.processInterval);
            this.processInterval = null;
            if (this.verbose) {
                console.log(`[MessageQueue] Auto-retry stopped`);
            }
        }
    }
}
