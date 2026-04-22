/**
 * STVOR DX Facade SDK
 * High-level developer experience layer for STVOR E2E encryption
 * 
 * Design goals:
 * - Minimal API surface
 * - Zero crypto knowledge required
 * - Secure by default
 * - Opinionated (no configuration)
 */

// Re-export types
export type { DecryptedMessage, SealedPayload } from './app';
export type { StvorAppConfig, AppToken, UserId, MessageContent } from './types';
export type { ErrorCode } from './errors';
export type { Metrics, SignedMetrics } from './metrics-engine';
export { StvorError } from './errors';

// Re-export classes and functions (Stvor is NOT re-exported here — it lives in facade/stvor.ts)
export { StvorApp, StvorFacadeClient, init, createApp } from './app';
export { ErrorCode as STVOR_ERRORS } from './errors';

// Re-export easy-to-use API
export { StvorEasyAPI, stvorInit, quickStart } from './easy-api';
export type { StvorEasyAPIConfig, MessageHandler } from './easy-api';

// Re-export metrics verification for Dashboard
export { verifyMetricsSignature, MetricsEngine } from './metrics-engine';

// Re-export crypto session management
export { CryptoSessionManager } from './crypto-session';
export type { IdentityKeys, SerializedPublicKeys, IIdentityStore, ISessionStore } from './crypto-session';
export { LocalStorageIdentityStore, LocalStorageSessionStore } from './local-storage-identity-store';

// Re-export file-based storage (Node.js/CLI)
export { FileIdentityStore } from './file-identity-store';
export type { FileIdentityStore as FileIdentityStoreClass } from './file-identity-store';
export { FileSessionStore } from './file-session-store';
export type { FileSessionStore as FileSessionStoreClass } from './file-session-store';
export { FileReplayStore } from './file-replay-store';

// Re-export timing attack protection
export { 
  constantTimeCompare, 
  constantTimeSignatureVerify, 
  constantTimeHmacCompare,
  benchmarkOperation,
  analyzeTimingDistribution,
  verifyCryptoIsConstantTime,
} from './timing-protection';

// Re-export one-time prekey management
export { OTPKeyManager } from './otp-key-manager';
export type { OTPKeyStatus, OTPKeyBundle } from './otp-key-manager';

// Re-export replay protection
export {
  isReplay,
  validateMessage,
  validateMessageWithNonce,
  getCacheStats,
  cleanupExpiredNonces,
  initializeReplayProtection,
  startAutoCleanup,
  stopAutoCleanup,
} from './replay-manager';
export type { IReplayCache } from './replay-manager';

// Re-export Redis replay cache for production
export { RedisReplayCache } from './redis-replay-cache';
export type { RedisClient, RedisReplayCacheConfig } from './redis-replay-cache';

// Re-export TOFU management
export {
  generateFingerprint,
  storeFingerprint,
  verifyFingerprint,
  isFingerprintTrusted,
  getFingerprint,
  revokeTrust,
  trustNewFingerprint,
  listTrustedFingerprints,
  getFingerprintInfo,
  initializeTofu,
} from './tofu-manager';
export type { ITofuStore } from './tofu-manager';

// Re-export universal data codec
export {
  encodeData,
  decodeData,
  encodeToBase64Url,
  decodeFromBase64Url,
  encodeDataSafe,
  decodeDataSafe,
  getEncodedDataType,
  calculateEncodingOverhead,
} from './data-codec';
export type { StvorDataType, StvorEncodedMessage } from './data-codec';

// Re-export batch operations (10x performance)
export {
  batchEncryptMessages,
  batchDecryptMessages,
  batchEstablishSessions,
} from './batch-engine';
export type {
  BatchOptions,
  BatchEncryptedMessage,
  BatchEncryptResult,
  BatchDecryptResult,
} from './batch-engine';

// Re-export resource lifecycle management
export { ResourceLifecycleManager } from './resource-lifecycle';
export type { LifecycleOptions, ResourceStats } from './resource-lifecycle';

// Re-export universal data support
export {
  UniversalDataCodec,
  encodeData as encodeUniversal,
  decodeData as decodeUniversal,
  encodeToBase64Url as encodeUniversalBase64,
  decodeFromBase64Url as decodeUniversalBase64,
} from './universal-data';
export type { StvorData, EncodedData, DecodedData } from './universal-data';

// Re-export simple SDK (main entry point)
export { StvorSDK, createSDK } from './simple-sdk';
export type { SimpleSDKOptions } from './simple-sdk';

// Re-export Phase 2: Rate limiting (DOS protection)
export { RateLimiter } from './rate-limiter';
export type { RateLimitConfig } from './rate-limiter';

// Re-export Phase 2: Message queue (offline support)
export { MessageQueue } from './message-queue';
export type { QueuedMessage, MessageQueueConfig } from './message-queue';

// Re-export Phase 2: Structured logger (monitoring)
export {
  StructuredLogger,
  initializeLogger,
  getLogger,
  LOG_LEVELS,
} from './structured-logger';
export type { LogEntry, LoggerConfig, LoggerMetrics } from './structured-logger';

// Re-export Phase 2: Connection pool (performance)
export { ConnectionPool } from './connection-pool';
export type { PooledConnection, ConnectionPoolConfig } from './connection-pool';

// Re-export Phase 3: Circuit breaker (reliability)
export { CircuitBreaker } from './circuit-breaker';
export type { CircuitBreakerConfig, CircuitState } from './circuit-breaker';

// Re-export Phase 3: Retry policies (resilience)
export { RetryPolicy, RetryManager } from './retry-policy';
export type { RetryPolicyConfig, BackoffStrategy, RetryAttempt } from './retry-policy';

// Re-export Phase 3: Metrics exporter (monitoring)
export { MetricsExporter, MetricsCollector } from './metrics-exporter';
export type { MetricValue, ExportFormat, ExporterConfig } from './metrics-exporter';

// Re-export Phase 3: Analytics engine (insights)
export { AnalyticsEngine } from './analytics-engine';
export type { AnalyticsEvent, AnalyticsReport } from './analytics-engine';
