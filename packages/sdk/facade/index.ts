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
export { verifyMetricsSignature } from './metrics-engine';
