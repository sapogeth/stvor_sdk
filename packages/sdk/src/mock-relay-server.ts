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

import * as WS from 'ws';
import http from 'node:http';

const { WebSocketServer } = WS;

// ── Configuration ────────────────────────────────────────────────────
const PORT = parseInt(process.env.STVOR_MOCK_PORT || process.env.PORT || '4444', 10);
const VERBOSE = process.env.STVOR_MOCK_VERBOSE === '1';

// ── In-memory state ──────────────────────────────────────────────────
/** userId → WebSocket */
const clients = new Map<string, any>();
/** userId → public key (base64) */
const pubkeys = new Map<string, string>();
/** userId → pending messages (for offline delivery) */
const mailboxes = new Map<string, any[]>();

let totalConnections = 0;
let totalMessages = 0;

// ── Helpers ──────────────────────────────────────────────────────────
function log(...args: unknown[]) {
  if (VERBOSE) console.log('[mock-relay]', new Date().toISOString(), ...args);
}

function validateAuth(req: http.IncomingMessage): boolean {
  const auth = req.headers.authorization;
  if (!auth) return false;
  const token = auth.replace(/^Bearer\s+/i, '');
  return token.startsWith('stvor_');
}

function broadcast(obj: unknown, exceptWs?: any) {
  const data = JSON.stringify(obj);
  for (const ws of clients.values()) {
    if (ws !== exceptWs && ws.readyState === 1 /* OPEN */) {
      ws.send(data);
    }
  }
}

// ── HTTP server for health check (and future REST endpoints) ─────────
const httpServer = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);
  
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'ok',
      server: 'stvor-mock-relay',
      version: '1.0.0',
      uptime: process.uptime(),
      connectedUsers: clients.size,
      totalConnections,
      totalMessages,
    }));
  }

  // GET /status/:userId - check if user is online
  const statusMatch = url.pathname.match(/^\/status\/(.+)$/);
  if (statusMatch) {
    const userId = decodeURIComponent(statusMatch[1]);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      userId,
      online: clients.has(userId),
      hasPublicKey: pubkeys.has(userId),
    }));
  }

  // GET /usage - mock unlimited usage
  if (url.pathname === '/usage') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ used: 0, limit: -1 }));
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not Found' }));
});

// ── WebSocket server ─────────────────────────────────────────────────
const wss = new WebSocketServer({ server: httpServer });

wss.on('connection', (ws: any, req: http.IncomingMessage) => {
  totalConnections++;
  
  // ── Auth check ───────────────────────────────────────────────────
  if (!validateAuth(req)) {
    log('Auth failed for connection');
    ws.send(JSON.stringify({
      type: 'handshake',
      status: 'error',
      reason: 'Invalid AppToken. Token must start with "stvor_".',
    }));
    ws.close(4001, 'Unauthorized');
    return;
  }

  // ── Successful handshake ─────────────────────────────────────────
  ws.send(JSON.stringify({ type: 'handshake', status: 'ok' }));
  log('Client connected (auth OK)');

  // Send all known user announcements to the new client
  for (const [user, pub] of pubkeys.entries()) {
    try {
      ws.send(JSON.stringify({ type: 'announce', user, pub }));
    } catch {
      // ignore
    }
  }

  // ── Message handler ──────────────────────────────────────────────
  ws.on('message', (data: Buffer | string) => {
    let msg: any;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    // ── Announce: register user + broadcast public key ────────────
    if (msg.type === 'announce' && msg.user) {
      const oldWs = clients.get(msg.user);
      clients.set(msg.user, ws);
      
      if (msg.pub) {
        pubkeys.set(msg.user, msg.pub);
      }

      log(`User announced: ${msg.user}`);

      // Broadcast announce to all other clients
      broadcast({ type: 'announce', user: msg.user, pub: msg.pub }, ws);

      // Deliver any pending messages
      const pending = mailboxes.get(msg.user) || [];
      if (pending.length > 0) {
        log(`Delivering ${pending.length} pending messages to ${msg.user}`);
        for (const m of pending) {
          try {
            ws.send(JSON.stringify(m));
          } catch {
            // ignore
          }
        }
        mailboxes.set(msg.user, []);
      }
      return;
    }

    // ── Message: route to recipient ──────────────────────────────
    if (msg.type === 'message' && msg.to) {
      totalMessages++;
      const target = clients.get(msg.to);

      if (target && target.readyState === 1 /* OPEN */) {
        // Deliver immediately
        target.send(JSON.stringify(msg));
        log(`Message delivered: ${msg.from} → ${msg.to}`);

        // ACK back to sender
        if (msg.from && ws.readyState === 1 /* OPEN */) {
          ws.send(JSON.stringify({ type: 'ack', id: msg.id ?? null }));
        }
      } else {
        // Store for later delivery
        if (!mailboxes.has(msg.to)) {
          mailboxes.set(msg.to, []);
        }
        mailboxes.get(msg.to)!.push(msg);
        log(`Message queued: ${msg.from} → ${msg.to} (recipient offline)`);

        // Notify sender that message is queued
        if (ws.readyState === 1 /* OPEN */) {
          ws.send(JSON.stringify({
            type: 'queued',
            id: msg.id ?? null,
            to: msg.to,
            message: 'Recipient is offline. Message queued for delivery.',
          }));
        }
      }
      return;
    }

    log('Unknown message type:', msg.type);
  });

  // ── Disconnect ───────────────────────────────────────────────────
  ws.on('close', () => {
    for (const [user, sock] of clients.entries()) {
      if (sock === ws) {
        log(`User disconnected: ${user}`);
        clients.delete(user);
        // Keep public key so reconnecting users can still be found
        // pubkeys.delete(user);  // intentionally NOT deleted
      }
    }
  });

  ws.on('error', (err: Error) => {
    log('WebSocket error:', err.message);
  });
});

// ── Start server ─────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║          STVOR Mock Relay Server v1.0.0             ║');
  console.log('  ╠══════════════════════════════════════════════════════╣');
  console.log(`  ║  WebSocket: ws://localhost:${String(PORT).padEnd(27)}║`);
  console.log(`  ║  Health:    http://localhost:${String(PORT).padEnd(22)}║`);
  console.log('  ║  Auth:      Any token starting with "stvor_"        ║');
  console.log('  ║  Data:      In-memory (resets on restart)           ║');
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log('');
  console.log('  Usage in your app:');
  console.log('');
  console.log("    const app = await Stvor.init({");
  console.log("      appToken: 'stvor_dev_test123',");
  console.log(`      relayUrl: 'ws://localhost:${PORT}'`);
  console.log("    });");
  console.log('');
  console.log('  Set STVOR_MOCK_VERBOSE=1 for detailed logging.');
  console.log('');
});

export { PORT, wss, httpServer };
