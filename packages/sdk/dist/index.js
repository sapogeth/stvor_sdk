/**
 * STVOR SDK - Main exports
 *
 * Primary API (Node.js + Browser):
 *   import { Stvor } from '@stvor/sdk';
 *   const client = await Stvor.connect({ userId, appToken, relayUrl });
 *
 * Browser-only (zero Node.js deps):
 *   import { StvorWebSDK } from '@stvor/sdk/web';
 */
// ── Primary unified API ───────────────────────────────────────────────────────
export { Stvor, StvorClient, StvorError } from './facade/stvor.js';
// ── DX Facade API (advanced) ──────────────────────────────────────────────────
export * from './facade/index.js';
// ── X3DH + Double Ratchet core ────────────────────────────────────────────────
export * from './ratchet/index.js';
// ── Legacy core API ───────────────────────────────────────────────────────────
export * from './legacy.js';
