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
export { StvorError } from './errors.js';
// Re-export classes and functions (Stvor is NOT re-exported here — it lives in facade/stvor.ts)
export { StvorApp, StvorFacadeClient, init, createApp } from './app.js';
export { ErrorCode as STVOR_ERRORS } from './errors.js';
// Re-export easy-to-use API
export { StvorEasyAPI, stvorInit, quickStart } from './easy-api.js';
// Re-export metrics verification for Dashboard
export { verifyMetricsSignature, MetricsEngine } from './metrics-engine.js';
// Re-export crypto session management
export { CryptoSessionManager } from './crypto-session.js';
export { LocalStorageIdentityStore, LocalStorageSessionStore } from './local-storage-identity-store.js';
// Re-export file-based storage (Node.js/CLI)
export { FileIdentityStore } from './file-identity-store.js';
export { FileSessionStore } from './file-session-store.js';
export { FileReplayStore } from './file-replay-store.js';
// Re-export timing attack protection
export { constantTimeCompare, constantTimeSignatureVerify, constantTimeHmacCompare, benchmarkOperation, analyzeTimingDistribution, verifyCryptoIsConstantTime, } from './timing-protection.js';
// Re-export one-time prekey management
export { OTPKeyManager } from './otp-key-manager.js';
// Re-export replay protection
export { isReplay, validateMessage, validateMessageWithNonce, getCacheStats, cleanupExpiredNonces, initializeReplayProtection, startAutoCleanup, stopAutoCleanup, } from './replay-manager.js';
// Re-export Redis replay cache for production
export { RedisReplayCache } from './redis-replay-cache.js';
// Re-export TOFU management
export { generateFingerprint, storeFingerprint, verifyFingerprint, isFingerprintTrusted, getFingerprint, revokeTrust, trustNewFingerprint, listTrustedFingerprints, getFingerprintInfo, initializeTofu, } from './tofu-manager.js';
// Re-export universal data codec
export { encodeData, decodeData, encodeToBase64Url, decodeFromBase64Url, encodeDataSafe, decodeDataSafe, getEncodedDataType, calculateEncodingOverhead, } from './data-codec.js';
// Re-export batch operations (10x performance)
export { batchEncryptMessages, batchDecryptMessages, batchEstablishSessions, } from './batch-engine.js';
// Re-export resource lifecycle management
export { ResourceLifecycleManager } from './resource-lifecycle.js';
// Re-export universal data support
export { UniversalDataCodec, encodeData as encodeUniversal, decodeData as decodeUniversal, encodeToBase64Url as encodeUniversalBase64, decodeFromBase64Url as decodeUniversalBase64, } from './universal-data.js';
// Re-export simple SDK (main entry point)
export { StvorSDK, createSDK } from './simple-sdk.js';
// Re-export Phase 2: Rate limiting (DOS protection)
export { RateLimiter } from './rate-limiter.js';
// Re-export Phase 2: Message queue (offline support)
export { MessageQueue } from './message-queue.js';
// Re-export Phase 2: Structured logger (monitoring)
export { StructuredLogger, initializeLogger, getLogger, LOG_LEVELS, } from './structured-logger.js';
// Re-export Phase 2: Connection pool (performance)
export { ConnectionPool } from './connection-pool.js';
// Re-export Phase 3: Circuit breaker (reliability)
export { CircuitBreaker } from './circuit-breaker.js';
// Re-export Phase 3: Retry policies (resilience)
export { RetryPolicy, RetryManager } from './retry-policy.js';
// Re-export Phase 3: Metrics exporter (monitoring)
export { MetricsExporter, MetricsCollector } from './metrics-exporter.js';
// Re-export Phase 3: Analytics engine (insights)
export { AnalyticsEngine } from './analytics-engine.js';
