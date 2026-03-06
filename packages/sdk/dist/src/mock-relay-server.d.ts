#!/usr/bin/env node
/**
 * STVOR Mock Relay Server
 *
 * A lightweight local development server that emulates the production
 * STVOR relay over WebSocket. Run it locally to develop and test
 * without internet access or a production relay.
 *
 * Usage:
 *   npx @stvor/sdk mock-relay                   # via npx
 *   npm run mock-relay                           # from SDK root
 *   node dist/mock-relay-server.js               # direct
 *   PORT=9000 node dist/mock-relay-server.js     # custom port
 *   STVOR_MOCK_VERBOSE=1 node dist/mock-relay-server.js  # verbose
 *
 * Accepts any AppToken starting with "stvor_" for easy local testing.
 *
 * Protocol:
 *   Connection: ws://localhost:PORT with Authorization header
 *   Handshake:  Server sends { type: 'handshake', status: 'ok' }
 *   Announce:   { type: 'announce', user: string, pub: string }
 *   Message:    { type: 'message', to: string, from: string, payload: any }
 *   Ack:        { type: 'ack', id: string }
 *   Error:      { type: 'error', code: string, message: string }
 */
import http from 'node:http';
declare const PORT: number;
declare const httpServer: http.Server<typeof http.IncomingMessage, typeof http.ServerResponse>;
declare const wss: any;
export { PORT, wss, httpServer };
