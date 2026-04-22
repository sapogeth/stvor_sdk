/**
 * STVOR Web SDK - Enhanced Error Handling
 * Production-ready error management and recovery
 */

/**
 * Error types for STVOR
 */
export enum StvorErrorType {
  // Encryption errors
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  KEY_GENERATION_FAILED = 'KEY_GENERATION_FAILED',
  INVALID_CIPHERTEXT = 'INVALID_CIPHERTEXT',
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',

  // Connection errors
  CONNECTION_REFUSED = 'CONNECTION_REFUSED',
  CONNECTION_TIMEOUT = 'CONNECTION_TIMEOUT',
  CONNECTION_LOST = 'CONNECTION_LOST',
  RELAY_UNREACHABLE = 'RELAY_UNREACHABLE',

  // Storage errors
  STORAGE_QUOTA_EXCEEDED = 'STORAGE_QUOTA_EXCEEDED',
  STORAGE_READ_FAILED = 'STORAGE_READ_FAILED',
  STORAGE_WRITE_FAILED = 'STORAGE_WRITE_FAILED',

  // Validation errors
  INVALID_USER_ID = 'INVALID_USER_ID',
  INVALID_RELAY_URL = 'INVALID_RELAY_URL',
  INVALID_MESSAGE = 'INVALID_MESSAGE',
  INVALID_PEER_ID = 'INVALID_PEER_ID',

  // Protocol errors
  PROTOCOL_MISMATCH = 'PROTOCOL_MISMATCH',
  MESSAGE_FORMAT_ERROR = 'MESSAGE_FORMAT_ERROR',
  UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',

  // Generic errors
  UNKNOWN = 'UNKNOWN',
  UNIMPLEMENTED = 'UNIMPLEMENTED'
}

/**
 * Custom STVOR Error class
 */
export class StvorError extends Error {
  type: StvorErrorType;
  timestamp: number;
  context: Record<string, any>;
  retryable: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';

  constructor(
    message: string,
    type: StvorErrorType = StvorErrorType.UNKNOWN,
    options: {
      context?: Record<string, any>;
      retryable?: boolean;
      severity?: 'low' | 'medium' | 'high' | 'critical';
    } = {}
  ) {
    super(message);
    this.name = 'StvorError';
    this.type = type;
    this.timestamp = Date.now();
    this.context = options.context || {};
    this.retryable = options.retryable ?? false;
    this.severity = options.severity ?? 'high';

    Object.setPrototypeOf(this, StvorError.prototype);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      type: this.type,
      timestamp: this.timestamp,
      context: this.context,
      retryable: this.retryable,
      severity: this.severity,
      stack: this.stack
    };
  }
}

/**
 * Error handler with recovery strategies
 */
export class ErrorHandler {
  private errorLog: StvorError[] = [];
  private maxLogSize = 1000;
  private listeners: Map<StvorErrorType | 'all', Function[]> = new Map();

  /**
   * Handle an error
   */
  handle(error: Error | StvorError, metadata?: Record<string, any>): StvorError {
    let stvorError: StvorError;

    if (error instanceof StvorError) {
      stvorError = error;
    } else {
      stvorError = new StvorError(error.message, StvorErrorType.UNKNOWN, {
        context: metadata
      });
    }

    // Log the error
    this.logError(stvorError);

    // Notify listeners
    this.notifyListeners(stvorError);

    return stvorError;
  }

  /**
   * Log error to history
   */
  private logError(error: StvorError): void {
    this.errorLog.push(error);

    // Keep log size under control
    if (this.errorLog.length > this.maxLogSize) {
      this.errorLog = this.errorLog.slice(-this.maxLogSize);
    }

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('[STVOR Error]', error.toJSON());
    }
  }

  /**
   * Subscribe to errors
   */
  subscribe(
    type: StvorErrorType | 'all',
    callback: (error: StvorError) => void
  ): () => void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, []);
    }
    this.listeners.get(type)!.push(callback);

    // Return unsubscribe function
    return () => {
      const callbacks = this.listeners.get(type);
      if (callbacks) {
        const index = callbacks.indexOf(callback);
        if (index !== -1) {
          callbacks.splice(index, 1);
        }
      }
    };
  }

  /**
   * Notify listeners
   */
  private notifyListeners(error: StvorError): void {
    // Notify specific type listeners
    const typeListeners = this.listeners.get(error.type) || [];
    typeListeners.forEach(callback => callback(error));

    // Notify 'all' listeners
    const allListeners = this.listeners.get('all') || [];
    allListeners.forEach(callback => callback(error));
  }

  /**
   * Get error history
   */
  getHistory(limit?: number): StvorError[] {
    if (limit) {
      return this.errorLog.slice(-limit);
    }
    return [...this.errorLog];
  }

  /**
   * Clear error history
   */
  clearHistory(): void {
    this.errorLog = [];
  }

  /**
   * Get statistics
   */
  getStats() {
    const stats = {
      total: this.errorLog.length,
      byType: {} as Record<string, number>,
      bySeverity: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
      },
      retryable: 0,
      recent24h: 0
    };

    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;

    this.errorLog.forEach(error => {
      // By type
      stats.byType[error.type] = (stats.byType[error.type] || 0) + 1;

      // By severity
      stats.bySeverity[error.severity]++;

      // Retryable
      if (error.retryable) stats.retryable++;

      // Recent 24h
      if (now - error.timestamp < day) stats.recent24h++;
    });

    return stats;
  }
}

/**
 * Recovery strategies
 */
export class RecoveryStrategy {
  /**
   * Retry with exponential backoff
   */
  static async retryWithBackoff<T>(
    fn: () => Promise<T>,
    maxAttempts: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < maxAttempts) {
          const delay = baseDelay * Math.pow(2, attempt - 1);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError;
  }

  /**
   * Circuit breaker pattern
   */
  static createCircuitBreaker<T>(
    fn: () => Promise<T>,
    options: {
      failureThreshold?: number;
      resetTimeout?: number;
      onStateChange?: (state: 'CLOSED' | 'OPEN' | 'HALF_OPEN') => void;
    } = {}
  ) {
    const failureThreshold = options.failureThreshold ?? 5;
    const resetTimeout = options.resetTimeout ?? 60000;

    let state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
    let failures = 0;
    let lastFailureTime = 0;

    const setState = (newState: typeof state) => {
      state = newState;
      options.onStateChange?.(newState);
    };

    return async () => {
      if (state === 'OPEN') {
        const timeSinceLastFailure = Date.now() - lastFailureTime;
        if (timeSinceLastFailure > resetTimeout) {
          setState('HALF_OPEN');
        } else {
          throw new StvorError(
            'Circuit breaker is OPEN',
            StvorErrorType.CONNECTION_REFUSED,
            { retryable: true, severity: 'high' }
          );
        }
      }

      try {
        const result = await fn();
        
        if (state === 'HALF_OPEN') {
          failures = 0;
          setState('CLOSED');
        }

        return result;
      } catch (error) {
        failures++;
        lastFailureTime = Date.now();

        if (failures >= failureThreshold) {
          setState('OPEN');
        }

        throw error;
      }
    };
  }

  /**
   * Fallback value
   */
  static async withFallback<T>(
    fn: () => Promise<T>,
    fallback: T | (() => T)
  ): Promise<T> {
    try {
      return await fn();
    } catch (error) {
      console.warn('Operation failed, using fallback:', error);
      return typeof fallback === 'function' ? (fallback as () => T)() : fallback;
    }
  }

  /**
   * Timeout
   */
  static async withTimeout<T>(
    fn: () => Promise<T>,
    timeoutMs: number
  ): Promise<T> {
    return Promise.race([
      fn(),
      new Promise<T>((_, reject) =>
        setTimeout(
          () =>
            reject(
              new StvorError(
                `Operation timed out after ${timeoutMs}ms`,
                StvorErrorType.CONNECTION_TIMEOUT,
                { retryable: true, severity: 'high' }
              )
            ),
          timeoutMs
        )
      )
    ]);
  }
}

/**
 * Validation utilities
 */
export class Validator {
  static validateUserId(userId: string): void {
    if (!userId || typeof userId !== 'string') {
      throw new StvorError(
        'Invalid userId: must be non-empty string',
        StvorErrorType.INVALID_USER_ID,
        { severity: 'high' }
      );
    }

    if (userId.length > 255) {
      throw new StvorError(
        'Invalid userId: must be less than 255 characters',
        StvorErrorType.INVALID_USER_ID,
        { severity: 'high' }
      );
    }
  }

  static validateRelayUrl(url: string): void {
    try {
      const parsed = new URL(url);
      if (!['ws:', 'wss:'].includes(parsed.protocol)) {
        throw new Error('Invalid protocol');
      }
    } catch (error) {
      throw new StvorError(
        'Invalid relay URL: must be valid WebSocket URL (ws:// or wss://)',
        StvorErrorType.INVALID_RELAY_URL,
        { severity: 'high' }
      );
    }
  }

  static validateMessage(message: any): void {
    if (!message || typeof message !== 'object') {
      throw new StvorError(
        'Invalid message: must be an object',
        StvorErrorType.INVALID_MESSAGE,
        { severity: 'medium' }
      );
    }
  }

  static validatePeerId(peerId: string): void {
    if (!peerId || typeof peerId !== 'string') {
      throw new StvorError(
        'Invalid peerId: must be non-empty string',
        StvorErrorType.INVALID_PEER_ID,
        { severity: 'medium' }
      );
    }
  }
}

/**
 * Error formatter for user display
 */
export class ErrorFormatter {
  static formatForDisplay(error: StvorError): string {
    const messages: Record<StvorErrorType, string> = {
      [StvorErrorType.ENCRYPTION_FAILED]: 'Failed to encrypt message',
      [StvorErrorType.DECRYPTION_FAILED]: 'Failed to decrypt message',
      [StvorErrorType.KEY_GENERATION_FAILED]: 'Failed to generate encryption keys',
      [StvorErrorType.INVALID_CIPHERTEXT]: 'Invalid encrypted message',
      [StvorErrorType.AUTHENTICATION_FAILED]: 'Message authentication failed',
      [StvorErrorType.CONNECTION_REFUSED]: 'Connection refused by relay',
      [StvorErrorType.CONNECTION_TIMEOUT]: 'Connection timeout',
      [StvorErrorType.CONNECTION_LOST]: 'Connection lost',
      [StvorErrorType.RELAY_UNREACHABLE]: 'Relay server unreachable',
      [StvorErrorType.STORAGE_QUOTA_EXCEEDED]: 'Storage quota exceeded',
      [StvorErrorType.STORAGE_READ_FAILED]: 'Failed to read from storage',
      [StvorErrorType.STORAGE_WRITE_FAILED]: 'Failed to write to storage',
      [StvorErrorType.INVALID_USER_ID]: 'Invalid user ID',
      [StvorErrorType.INVALID_RELAY_URL]: 'Invalid relay URL',
      [StvorErrorType.INVALID_MESSAGE]: 'Invalid message format',
      [StvorErrorType.INVALID_PEER_ID]: 'Invalid peer ID',
      [StvorErrorType.PROTOCOL_MISMATCH]: 'Protocol mismatch',
      [StvorErrorType.MESSAGE_FORMAT_ERROR]: 'Message format error',
      [StvorErrorType.UNSUPPORTED_VERSION]: 'Unsupported protocol version',
      [StvorErrorType.UNKNOWN]: 'An unknown error occurred',
      [StvorErrorType.UNIMPLEMENTED]: 'Feature not yet implemented'
    };

    return messages[error.type] || error.message;
  }

  static getSuggestion(error: StvorError): string {
    if (error.retryable) {
      return 'Please try again later';
    }

    switch (error.type) {
      case StvorErrorType.CONNECTION_REFUSED:
      case StvorErrorType.RELAY_UNREACHABLE:
        return 'Check your connection and relay URL';
      case StvorErrorType.STORAGE_QUOTA_EXCEEDED:
        return 'Clear some old messages to free up space';
      case StvorErrorType.AUTHENTICATION_FAILED:
        return 'Message may have been tampered with';
      default:
        return 'Contact support if the problem persists';
    }
  }
}

export default {
  StvorError,
  StvorErrorType,
  ErrorHandler,
  RecoveryStrategy,
  Validator,
  ErrorFormatter
};
