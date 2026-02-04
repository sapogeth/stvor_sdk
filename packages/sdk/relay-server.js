#!/usr/bin/env node
import WebSocket, { WebSocketServer } from 'ws';

const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
const wss = new WebSocketServer({ port: PORT });
console.log(`Relay server listening on ws://0.0.0.0:${PORT}`);

// userId -> ws
const clients = new Map();
// userId -> pubkey
const pubkeys = new Map();

function broadcast(obj, exceptWs) {
  const s = JSON.stringify(obj);
  for (const ws of clients.values()) {
    if (ws !== exceptWs && ws.readyState === WebSocket.OPEN) ws.send(s);
  }
}

wss.on('connection', (ws) => {
  // send currently known announces to the freshly connected client
  for (const [user, pub] of pubkeys.entries()) {
    try {
      ws.send(JSON.stringify({ type: 'announce', user, pub }));
    } catch (e) {
      // ignore send errors for initial sync
    }
  }

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data.toString()); } catch (e) { return; }

    if (msg.type === 'announce' && msg.user) {
      clients.set(msg.user, ws);
      if (msg.pub) pubkeys.set(msg.user, msg.pub);
      // broadcast announce to others
      broadcast({ type: 'announce', user: msg.user, pub: msg.pub }, ws);
      return;
    }

    if (msg.type === 'message' && msg.to) {
      const target = clients.get(msg.to);
      // deliver
      if (target && target.readyState === WebSocket.OPEN) {
        target.send(JSON.stringify(msg));
        // ack back to sender
        if (msg.from && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ack', id: msg.id ?? null }));
        }
      } else {
        // not found — send error ack
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'error', code: 'RECIPIENT_NOT_FOUND', to: msg.to }));
        }
      }
      return;
    }
  });

  ws.on('close', () => {
    for (const [user, s] of clients.entries()) if (s === ws) {
      clients.delete(user);
      pubkeys.delete(user);
    }
  });
});
