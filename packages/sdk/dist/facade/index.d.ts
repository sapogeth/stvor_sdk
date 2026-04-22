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
export type { DecryptedMessage, SealedPayload } from './app';
export type { StvorAppConfig, AppToken, UserId, MessageContent } from './types';
export type { ErrorCode } from './errors';
export type { Metrics, SignedMetrics } from './metrics-engine';
export { StvorError } from './errors';
export { StvorApp, StvorFacadeClient, init, createApp } from './app';
export { ErrorCode as STVOR_ERRORS } from './errors';
export { StvorEasyAPI, stvorInit, quickStart } from './easy-api';
export type { StvorEasyAPIConfig, MessageHandler } from './easy-api';
export { verifyMetricsSignature, MetricsEngine } from './metrics-engine';
export { CryptoSessionManager } from './crypto-session';
export type { IdentityKeys, SerializedPublicKeys, IIdentityStore, ISessionStore } from './crypto-session';
export { LocalStorageIdentityStore, LocalStorageSessionStore } from './local-storage-identity-store';
export { FileIdentityStore } from './file-identity-store';
export type { FileIdentityStore as FileIdentityStoreClass } from './file-identity-store';
export { FileSessionStore } from './file-session-store';
export type { FileSessionStore as FileSessionStoreClass } from './file-session-store';
export { FileReplayStore } from './file-replay-store';
export { constantTimeCompare, constantTimeSignatureVerify, constantTimeHmacCompare, benchmarkOperation, analyzeTimingDistribution, verifyCryptoIsConstantTime, } from './timing-protection';
export { OTPKeyManager } from './otp-key-manager';
export type { OTPKeyStatus, OTPKeyBundle } from './otp-key-manager';
export { isReplay, validateMessage, validateMessageWithNonce, getCacheStats, cleanupExpiredNonces, initializeReplayProtection, startAutoCleanup, stopAutoCleanup, } from './replay-manager';
export type { IReplayCache } from './replay-manager';
export { RedisReplayCache } from './redis-replay-cache';
export type { RedisClient, RedisReplayCacheConfig } from './redis-replay-cache';
export { generateFingerprint, storeFingerprint, verifyFingerprint, isFingerprintTrusted, getFingerprint, revokeTrust, trustNewFingerprint, listTrustedFingerprints, getFingerprintInfo, initializeTofu, } from './tofu-manager';
export type { ITofuStore } from './tofu-manager';
export { encodeData, decodeData, encodeToBase64Url, decodeFromBase64Url, encodeDataSafe, decodeDataSafe, getEncodedDataType, calculateEncodingOverhead, } from './data-codec';
export type { StvorDataType, StvorEncodedMessage } from './data-codec';
export { batchEncryptMessages, batchDecryptMessages, batchEstablishSessions, } from './batch-engine';
export type { BatchOptions, BatchEncryptedMessage, BatchEncryptResult, BatchDecryptResult, } from './batch-engine';
export { ResourceLifecycleManager } from './resource-lifecycle';
export type { LifecycleOptions, ResourceStats } from './resource-lifecycle';
export { UniversalDataCodec, encodeData as encodeUniversal, decodeData as decodeUniversal, encodeToBase64Url as encodeUniversalBase64, decodeFromBase64Url as decodeUniversalBase64, } from './universal-data';
export type { StvorData, EncodedData, DecodedData } from './universal-data';
export { StvorSDK, createSDK } from './simple-sdk';
export type { SimpleSDKOptions } from './simple-sdk';
export { RateLimiter } from './rate-limiter';
export type { RateLimitConfig } from './rate-limiter';
export { MessageQueue } from './message-queue';
export type { QueuedMessage, MessageQueueConfig } from './message-queue';
export { StructuredLogger, initializeLogger, getLogger, LOG_LEVELS, } from './structured-logger';
export type { LogEntry, LoggerConfig, LoggerMetrics } from './structured-logger';
export { ConnectionPool } from './connection-pool';
export type { PooledConnection, ConnectionPoolConfig } from './connection-pool';
export { CircuitBreaker } from './circuit-breaker';
export type { CircuitBreakerConfig, CircuitState } from './circuit-breaker';
export { RetryPolicy, RetryManager } from './retry-policy';
export type { RetryPolicyConfig, BackoffStrategy, RetryAttempt } from './retry-policy';
export { MetricsExporter, MetricsCollector } from './metrics-exporter';
export type { MetricValue, ExportFormat, ExporterConfig } from './metrics-exporter';
export { AnalyticsEngine } from './analytics-engine';
export type { AnalyticsEvent, AnalyticsReport } from './analytics-engine';
