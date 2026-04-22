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
export { Stvor, StvorClient, StvorError } from './facade/stvor.js';
export type { StvorConfig, StvorMessage, MessageHandler as StvorMessageHandler } from './facade/stvor.js';
export * from './facade/index.js';
export * from './ratchet/index.js';
export * from './legacy.js';
