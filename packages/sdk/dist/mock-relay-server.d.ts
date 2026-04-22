#!/usr/bin/env node
/**
 * STVOR Mock Relay Server — HTTP edition
 *
 * Implements the same REST API as the production relay so RelayClient
 * works against it without any changes:
 *
 *   GET  /health
 *   POST /register          { user_id, publicKeys }
 *   GET  /public-key/:userId
 *   POST /message           { to, from, ciphertext, header }
 *   GET  /messages/:userId  → clears the queue
 *   DELETE /message/:id
 *   GET  /stats             (requires auth)
 *
 * Usage:
 *   STVOR_MOCK_PORT=4444 node dist/mock-relay-server.js
 *   STVOR_MOCK_VERBOSE=1  node dist/mock-relay-server.js
 *
 *   const app = await Stvor.init({
 *     appToken: 'stvor_dev_test',
 *     relayUrl: 'http://localhost:4444',
 *   });
 */
import http from 'node:http';
declare const PORT: number;
declare const server: http.Server<typeof http.IncomingMessage, typeof http.ServerResponse>;
export { PORT, server };
