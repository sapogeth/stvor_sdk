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
import crypto from 'node:crypto';
const PORT = parseInt(process.env.STVOR_MOCK_PORT || process.env.PORT || '4444', 10);
const VERBOSE = process.env.STVOR_MOCK_VERBOSE === '1';
function log(...args) {
    if (VERBOSE)
        console.log('[mock-relay]', new Date().toISOString(), ...args);
}
// projectId → userId → UserEntry
const registry = new Map();
let totalMessages = 0;
function getToken(req) {
    const auth = req.headers['authorization'] ?? '';
    return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}
function validateToken(token) {
    if (!token || !token.startsWith('stvor_'))
        return null;
    return `mock_project_${token.slice(0, 16)}`;
}
function readBody(req) {
    return new Promise((resolve, reject) => {
        let raw = '';
        req.on('data', (chunk) => { raw += chunk; });
        req.on('end', () => {
            try {
                resolve(raw ? JSON.parse(raw) : {});
            }
            catch {
                reject(new Error('Invalid JSON'));
            }
        });
        req.on('error', reject);
    });
}
function send(res, status, body) {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Access-Control-Allow-Origin': '*',
    });
    res.end(payload);
}
const server = http.createServer(async (req, res) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        });
        return res.end();
    }
    const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);
    const path = url.pathname;
    const token = getToken(req);
    // ── GET /health ───────────────────────────────────────────────────────
    if (req.method === 'GET' && path === '/health') {
        return send(res, 200, { status: 'ok', server: 'stvor-mock-relay' });
    }
    // ── POST /register ────────────────────────────────────────────────────
    if (req.method === 'POST' && path === '/register') {
        const projectId = validateToken(token);
        if (!projectId)
            return send(res, 401, { error: 'Invalid token' });
        let body;
        try {
            body = await readBody(req);
        }
        catch {
            return send(res, 400, { error: 'Invalid JSON' });
        }
        const { user_id, publicKeys } = body;
        if (!user_id || typeof user_id !== 'string')
            return send(res, 400, { error: 'Invalid user_id' });
        if (!registry.has(projectId))
            registry.set(projectId, new Map());
        const project = registry.get(projectId);
        project.set(user_id, { publicKeys, messages: [], lastActivity: Date.now() });
        log(`Registered: ${user_id} (project: ${projectId})`);
        return send(res, 200, { status: 'registered' });
    }
    // ── GET /public-key/:userId ───────────────────────────────────────────
    const pkMatch = path.match(/^\/public-key\/(.+)$/);
    if (req.method === 'GET' && pkMatch) {
        const projectId = validateToken(token);
        if (!projectId)
            return send(res, 401, { error: 'Invalid token' });
        const userId = decodeURIComponent(pkMatch[1]);
        const user = registry.get(projectId)?.get(userId);
        if (!user)
            return send(res, 404, { error: 'User not found' });
        return send(res, 200, { publicKeys: user.publicKeys });
    }
    // ── POST /message ─────────────────────────────────────────────────────
    if (req.method === 'POST' && path === '/message') {
        const projectId = validateToken(token);
        if (!projectId)
            return send(res, 401, { error: 'Invalid token' });
        let body;
        try {
            body = await readBody(req);
        }
        catch {
            return send(res, 400, { error: 'Invalid JSON' });
        }
        const { to, from, ciphertext, header } = body;
        if (!to || !from || !ciphertext || header === undefined) {
            return send(res, 400, { error: 'Missing required fields: to, from, ciphertext, header' });
        }
        if (to === from)
            return send(res, 400, { error: 'Cannot send message to yourself' });
        const project = registry.get(projectId);
        const recipient = project?.get(to);
        if (!recipient)
            return send(res, 404, { error: 'Recipient not found' });
        const id = crypto.randomBytes(8).toString('hex');
        recipient.messages.push({ id, from, ciphertext, header, timestamp: new Date().toISOString() });
        recipient.lastActivity = Date.now();
        totalMessages++;
        log(`Message: ${from} → ${to}`);
        return send(res, 200, { status: 'delivered', messageId: id });
    }
    // ── GET /messages/:userId ─────────────────────────────────────────────
    const msgsMatch = path.match(/^\/messages\/(.+)$/);
    if (req.method === 'GET' && msgsMatch) {
        const projectId = validateToken(token);
        if (!projectId)
            return send(res, 401, { error: 'Invalid token' });
        const userId = decodeURIComponent(msgsMatch[1]);
        const project = registry.get(projectId);
        const user = project?.get(userId);
        if (!user)
            return send(res, 404, { error: 'User not found' });
        const messages = user.messages.splice(0);
        user.lastActivity = Date.now();
        log(`Fetched ${messages.length} messages for ${userId}`);
        return send(res, 200, { messages, count: messages.length });
    }
    // ── DELETE /message/:id ───────────────────────────────────────────────
    const delMatch = path.match(/^\/message\/(.+)$/);
    if (req.method === 'DELETE' && delMatch) {
        const projectId = validateToken(token);
        if (!projectId)
            return send(res, 401, { error: 'Invalid token' });
        const msgId = decodeURIComponent(delMatch[1]);
        const project = registry.get(projectId);
        if (project) {
            for (const user of project.values()) {
                const idx = user.messages.findIndex((m) => m.id === msgId);
                if (idx !== -1) {
                    user.messages.splice(idx, 1);
                    return send(res, 200, { status: 'deleted' });
                }
            }
        }
        return send(res, 404, { error: 'Message not found' });
    }
    // ── GET /stats ────────────────────────────────────────────────────────
    if (req.method === 'GET' && path === '/stats') {
        const projectId = validateToken(token);
        if (!projectId)
            return send(res, 401, { error: 'Invalid token' });
        let users = 0, pending = 0;
        for (const project of registry.values()) {
            for (const user of project.values()) {
                users++;
                pending += user.messages.length;
            }
        }
        return send(res, 200, {
            status: 'ok',
            registry: { projects: registry.size, users, pendingMessages: pending },
            totalMessages,
        });
    }
    return send(res, 404, { error: 'Not found' });
});
server.listen(PORT, () => {
    console.log('');
    console.log(`  STVOR Mock Relay (HTTP) — http://localhost:${PORT}`);
    console.log(`  Health: http://localhost:${PORT}/health`);
    console.log(`  Auth:   any token starting with "stvor_"`);
    console.log('');
    console.log('  Usage:');
    console.log(`    const app = await Stvor.init({ appToken: 'stvor_dev_test', relayUrl: 'http://localhost:${PORT}' });`);
    console.log('');
    if (VERBOSE)
        console.log('  Verbose logging enabled.');
});
export { PORT, server };
