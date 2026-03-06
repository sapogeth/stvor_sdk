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
// Re-export classes and functions
export { StvorApp, StvorFacadeClient, Stvor, init, createApp } from './app.js';
export { ErrorCode as STVOR_ERRORS } from './errors.js';
// Re-export metrics verification for Dashboard
export { verifyMetricsSignature, MetricsEngine } from './metrics-engine.js';
// Re-export crypto session management
export { CryptoSessionManager } from './crypto-session.js';
export { LocalStorageIdentityStore, LocalStorageSessionStore } from './local-storage-identity-store.js';
// Re-export replay protection
export { isReplay, validateMessage, validateMessageWithNonce, getCacheStats, cleanupExpiredNonces, initializeReplayProtection, startAutoCleanup, stopAutoCleanup, } from './replay-manager.js';
// Re-export Redis replay cache for production
export { RedisReplayCache } from './redis-replay-cache.js';
// Re-export TOFU management
export { generateFingerprint, storeFingerprint, verifyFingerprint, isFingerprintTrusted, getFingerprint, revokeTrust, trustNewFingerprint, listTrustedFingerprints, getFingerprintInfo, initializeTofu, } from './tofu-manager.js';
