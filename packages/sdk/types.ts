/**
 * STVOR Web SDK - TypeScript Type Definitions
 * Complete type safety for Web SDK
 */

/**
 * User identity and configuration
 */
export interface UserIdentity {
  id: string;
  publicKey: Uint8Array;
  isVerified: boolean;
  lastSeen: number;
}

/**
 * Peer information
 */
export interface Peer {
  id: string;
  publicKey: Uint8Array;
  lastSeen: number;
  isOnline: boolean;
  metadata?: Record<string, any>;
}

/**
 * Encrypted message
 */
export interface EncryptedMessage {
  id: string;
  from: string;
  to: string;
  data: Uint8Array; // nonce + ciphertext + auth tag
  timestamp: number;
  acknowledged?: boolean;
}

/**
 * Decrypted message (after decryption)
 */
export interface DecryptedMessage {
  id: string;
  from: string;
  to: string;
  text: string;
  data?: any;
  timestamp: number;
  encrypted: boolean;
  isAuthenticated: boolean;
}

/**
 * Message payload
 */
export interface MessagePayload {
  text?: string;
  data?: any;
  metadata?: {
    type?: string;
    priority?: 'low' | 'normal' | 'high';
    expiry?: number;
    tags?: string[];
  };
}

/**
 * Encryption keys
 */
export interface EncryptionKeys {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  masterKey: Uint8Array;
  createdAt: number;
  rotatedAt?: number;
}

/**
 * Key pair (public only)
 */
export interface PublicKeyPair {
  publicKey: Uint8Array;
  algorithm: string; // 'X25519'
  createdAt: number;
}

/**
 * Relay configuration
 */
export interface RelayConfig {
  url: string;
  reconnectDelay?: number;
  reconnectMaxDelay?: number;
  backoffMultiplier?: number;
  maxReconnectAttempts?: number;
  timeout?: number;
}

/**
 * SDK configuration
 */
export interface StvorWebSDKConfig {
  userId: string;
  relayUrl: string;
  reconnectDelay?: number;
  reconnectMaxDelay?: number;
  backoffMultiplier?: number;
  maxReconnectAttempts?: number;
  timeout?: number;
  storagePrefix?: string;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  features?: {
    compression?: boolean;
    batching?: boolean;
    retryFailedMessages?: boolean;
    persistMessages?: boolean;
  };
}

/**
 * Connection status
 */
export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

/**
 * Connection state
 */
export interface ConnectionState {
  status: ConnectionStatus;
  isConnected: boolean;
  lastConnectedAt?: number;
  reconnectAttempts: number;
  error?: Error;
}

/**
 * Message queue entry
 */
export interface QueuedMessage {
  id: string;
  peerId: string;
  payload: MessagePayload;
  timestamp: number;
  attempts: number;
  maxAttempts: number;
  nextRetryAt: number;
  encrypted: Uint8Array;
}

/**
 * Connection statistics
 */
export interface ConnectionStats {
  messagesSent: number;
  messagesReceived: number;
  messagesAcknowledged: number;
  messagesFailed: number;
  bytesSent: number;
  bytesReceived: number;
  bytesEncrypted: number;
  bytesDecrypted: number;
  averageLatency: number;
  minLatency: number;
  maxLatency: number;
  uptime: number;
  connectionAttempts: number;
}

/**
 * Encryption statistics
 */
export interface EncryptionStats {
  keysGenerated: number;
  keysRotated: number;
  messagesEncrypted: number;
  messagesDecrypted: number;
  encryptionErrors: number;
  decryptionErrors: number;
  authenticationFailures: number;
  averageEncryptionTime: number;
  averageDecryptionTime: number;
}

/**
 * Health check result
 */
export interface HealthCheckResult {
  healthy: boolean;
  timestamp: number;
  checks: {
    connection: boolean;
    storage: boolean;
    encryption: boolean;
    relay: boolean;
  };
  stats: {
    connection: ConnectionStats;
    encryption: EncryptionStats;
  };
}

/**
 * Event emitter callback types
 */
export type EventCallback<T = any> = (data: T) => void | Promise<void>;

/**
 * Relay event types
 */
export type RelayEventType =
  | 'announce'
  | 'message'
  | 'ack'
  | 'error'
  | 'disconnect'
  | 'reconnect';

/**
 * Relay event
 */
export interface RelayEvent<T = any> {
  type: RelayEventType;
  from?: string;
  to?: string;
  data?: T;
  id?: string;
  timestamp: number;
}

/**
 * Storage interface
 */
export interface StvorStorage {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  keys(): Promise<string[]>;
}

/**
 * Logger interface
 */
export interface StvorLogger {
  debug(message: string, context?: any): void;
  info(message: string, context?: any): void;
  warn(message: string, context?: any): void;
  error(message: string, context?: any): void;
}

/**
 * Message handler type
 */
export type MessageHandler = (msg: DecryptedMessage) => Promise<void>;

/**
 * Connection listener type
 */
export type ConnectionListener = (status: ConnectionStatus) => void | Promise<void>;

/**
 * Error listener type
 */
export type ErrorListener = (error: Error) => void | Promise<void>;

/**
 * Peer listener type
 */
export type PeerListener = (peer: Peer, event: 'online' | 'offline' | 'update') => void | Promise<void>;

/**
 * React hook return types
 */
export interface UseStvorSDKReturn {
  sdk: any | null;
  isConnected: boolean;
  isLoading: boolean;
  error: Error | null;
}

export interface UseEncryptedMessagesReturn {
  messages: Array<{
    id: string;
    from: string;
    to: string;
    text: string;
    timestamp: number;
    encrypted: boolean;
  }>;
  isSending: boolean;
  error: Error | null;
  sendMessage: (text: string) => Promise<void>;
  clearMessages: () => void;
}

export interface UseConnectionStatusReturn {
  status: ConnectionStatus;
  stats: ConnectionStats;
  reconnect: () => Promise<void>;
}

export interface UseEncryptionKeysReturn {
  publicKey: Uint8Array | null;
  isRotating: boolean;
  rotationError: Error | null;
  rotateKeys: () => Promise<void>;
  exportPublicKey: () => number[] | null;
}

export interface UseConnectedPeersReturn {
  peers: Peer[];
}

export interface UseSDKErrorHandlerReturn {
  errors: Array<{
    id: string;
    message: string;
    timestamp: number;
    severity: 'info' | 'warning' | 'error';
  }>;
  addError: (message: string, severity?: 'info' | 'warning' | 'error') => void;
  clearErrors: () => void;
  clearErrorById: (id: string) => void;
}

/**
 * Vue composable return types (similar to React but with computed)
 */
export interface UseStvorSDKVueReturn {
  sdk: any; // Ref<any | null>
  isConnected: any; // Ref<boolean>
  isLoading: any; // Ref<boolean>
  error: any; // Ref<Error | null>
}

/**
 * Batch message operations
 */
export interface BatchOperation {
  peerId: string;
  message: MessagePayload;
  timestamp: number;
}

export interface BatchOperationResult {
  successful: string[];
  failed: Array<{
    peerId: string;
    error: Error;
  }>;
}

/**
 * Recovery strategy options
 */
export interface RetryOptions {
  maxAttempts: number;
  baseDelay: number;
  maxDelay?: number;
  backoffMultiplier?: number;
}

export interface CircuitBreakerOptions {
  failureThreshold: number;
  resetTimeout: number;
  onStateChange?: (state: 'CLOSED' | 'OPEN' | 'HALF_OPEN') => void;
}

/**
 * Validation error context
 */
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

/**
 * Transaction options
 */
export interface TransactionOptions {
  timeout?: number;
  retry?: boolean;
  maxRetries?: number;
}

/**
 * Index definition for storage
 */
export interface IndexDefinition {
  name: string;
  unique: boolean;
  keyPath: string | string[];
}

/**
 * Storage query
 */
export interface StorageQuery {
  where?: Record<string, any>;
  orderBy?: string;
  limit?: number;
  skip?: number;
}

/**
 * Export format options
 */
export type ExportFormat = 'json' | 'csv' | 'binary';

/**
 * Diagnostic info
 */
export interface DiagnosticInfo {
  sdkVersion: string;
  userAgent: string;
  browsers: string;
  storage: {
    available: number;
    used: number;
    quota?: number;
  };
  connection: {
    type: string;
    latency: number;
    bandwidth?: number;
  };
  encryption: {
    algorithm: string;
    keySize: number;
    nonceSize: number;
  };
  performance: {
    memoryUsage?: number;
    cpuUsage?: number;
    uptime: number;
  };
}

export default {
  // Re-export all types
};
