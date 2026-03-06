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

// Re-export classes and functions
export { StvorApp, StvorFacadeClient, Stvor, init, createApp } from './app';
export { ErrorCode as STVOR_ERRORS } from './errors';

// Re-export metrics verification for Dashboard
export { verifyMetricsSignature, MetricsEngine } from './metrics-engine';

// Re-export crypto session management
export { CryptoSessionManager } from './crypto-session';
export type { IdentityKeys, SerializedPublicKeys, IIdentityStore, ISessionStore } from './crypto-session';
export { LocalStorageIdentityStore, LocalStorageSessionStore } from './local-storage-identity-store';

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
