/**
 * STVOR SDK - Mock Relay Module
 *
 * Exports the mock relay server for development and testing
 *
 * Usage:
 *   import { startMockRelay } from '@stvor/sdk/mock-relay';
 *   await startMockRelay({ port: 4444 });
 */
export { startMockRelay, MockRelayConfig } from '../dist/mock-relay-server.js';
export * from '../dist/mock-relay-server.js';
