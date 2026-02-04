import { WebSocketServer, WebSocket } from 'ws';
import { createServer } from 'http';
import { getProjectIdByApiKey } from '../auth/apiKey.js';
// Error codes for WS close
const WS_CLOSE_CODES = {
    NORMAL: 1000,
    UNAUTHORIZED: 4001,
    INVALID_API_KEY: 4002,
    PROJECT_DISABLED: 4003,
    INTERNAL_ERROR: 4500,
};
export class RelayServer {
    constructor(port = 3002) {
        this.clients = new Map();
        // Project-scoped public keys: projectId -> Map<userId, pubKey>
        this.projectKeys = new Map();
        this.port = port;
        this.httpServer = createServer((req, res) => this.handleHttpRequest(req, res));
        this.wss = new WebSocketServer({
            server: this.httpServer,
            verifyClient: (info, callback) => {
                // Pre-connection validation
                const apiKey = this.extractApiKey(info.req);
                if (!apiKey) {
                    console.log('[Relay] ❌ Connection rejected: missing API key');
                    callback(false, 401, 'Missing API key');
                    return;
                }
                const projectId = getProjectIdByApiKey(apiKey);
                if (!projectId) {
                    console.log('[Relay] ❌ Connection rejected: invalid API key');
                    callback(false, 401, 'Invalid API key');
                    return;
                }
                // Attach projectId to request for later use
                info.req._stvorProjectId = projectId;
                info.req._stvorApiKey = apiKey;
                callback(true);
            }
        });
        this.setupHandlers();
    }
    handleHttpRequest(req, res) {
        // CORS
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
        }
        // Health endpoint
        if (req.url === '/health' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(this.getHealth()));
            return;
        }
        // Stats endpoint (optional, for debugging)
        if (req.url === '/stats' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(this.getStats()));
            return;
        }
        // All other requests get 404 (WebSocket upgrade handled separately)
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
    }
    extractApiKey(req) {
        // Try Authorization header first
        const authHeader = req.headers['authorization'];
        if (authHeader?.startsWith('Bearer ')) {
            return authHeader.slice(7);
        }
        // Try query param as fallback (for browser clients)
        const url = new URL(req.url || '/', `http://${req.headers.host}`);
        const tokenParam = url.searchParams.get('token');
        if (tokenParam) {
            return tokenParam;
        }
        return null;
    }
    setupHandlers() {
        this.wss.on('connection', (ws, req) => {
            const projectId = req._stvorProjectId;
            const clientId = this.generateId();
            const client = {
                ws,
                projectId,
            };
            this.clients.set(clientId, client);
            console.log(`[Relay] ✅ Client connected: ${clientId} (project: ${projectId})`);
            // Send explicit handshake response
            this.sendHandshake(ws, projectId);
            console.log(`[Relay] Handshake sent to client: ${clientId}`);
            // Send all existing keys for this project
            this.sendExistingKeys(ws, projectId);
            ws.on('message', (data) => {
                try {
                    const message = JSON.parse(data.toString());
                    this.handleMessage(clientId, message);
                }
                catch (error) {
                    console.error('[Relay] Invalid message format:', error);
                }
            });
            ws.on('close', () => {
                this.handleDisconnect(clientId);
            });
            ws.on('error', (error) => {
                console.error(`[Relay] Client ${clientId} error:`, error);
            });
        });
    }
    sendHandshake(ws, projectId) {
        const handshake = {
            type: 'handshake',
            status: 'ok',
            projectId,
            relay: 'ready',
            timestamp: new Date().toISOString(),
        };
        ws.send(JSON.stringify(handshake));
        console.log('[Relay] Handshake payload:', handshake);
    }
    sendExistingKeys(ws, projectId) {
        const keys = this.projectKeys.get(projectId);
        if (!keys)
            return;
        for (const [userId, pubKey] of keys) {
            ws.send(JSON.stringify({
                type: 'announce',
                user: userId,
                pub: pubKey,
            }));
        }
    }
    handleMessage(clientId, message) {
        const client = this.clients.get(clientId);
        if (!client)
            return;
        switch (message.type) {
            case 'announce':
                this.handleAnnounce(clientId, client, message);
                break;
            case 'message':
                this.handleDirectMessage(clientId, client, message);
                break;
            default:
                console.log(`[Relay] Unknown message type: ${message.type}`);
        }
    }
    handleAnnounce(clientId, client, message) {
        if (!message.user || !message.pub) {
            console.log(`[Relay] ⚠️ Invalid announce from ${clientId}: missing user or pub`);
            return;
        }
        const { projectId } = client;
        // Store client identity
        client.userId = message.user;
        client.pubKey = message.pub;
        // Initialize project key store if needed
        if (!this.projectKeys.has(projectId)) {
            this.projectKeys.set(projectId, new Map());
        }
        // Store public key for this project
        this.projectKeys.get(projectId).set(message.user, message.pub);
        console.log(`[Relay] 📢 Announce: ${message.user} in project ${projectId}`);
        // Broadcast to ALL clients in the SAME project
        const announceMsg = JSON.stringify({
            type: 'announce',
            user: message.user,
            pub: message.pub,
        });
        let broadcastCount = 0;
        for (const [otherId, otherClient] of this.clients) {
            // Same project, different client, open connection
            if (otherClient.projectId === projectId &&
                otherId !== clientId &&
                otherClient.ws.readyState === WebSocket.OPEN) {
                otherClient.ws.send(announceMsg);
                broadcastCount++;
            }
        }
        console.log(`[Relay] 📡 Broadcasted announce to ${broadcastCount} clients`);
    }
    handleDirectMessage(clientId, client, message) {
        if (!message.to || !message.payload) {
            console.log(`[Relay] ⚠️ Invalid message from ${clientId}: missing to or payload`);
            return;
        }
        const { projectId } = client;
        const recipientId = message.to;
        // Find recipient in SAME project
        let delivered = false;
        for (const [, otherClient] of this.clients) {
            if (otherClient.projectId === projectId &&
                otherClient.userId === recipientId &&
                otherClient.ws.readyState === WebSocket.OPEN) {
                otherClient.ws.send(JSON.stringify({
                    type: 'message',
                    from: client.userId || clientId,
                    to: recipientId,
                    payload: message.payload,
                }));
                delivered = true;
                console.log(`[Relay] 📨 Message delivered: ${client.userId} → ${recipientId}`);
                break;
            }
        }
        if (!delivered) {
            console.log(`[Relay] ⚠️ Message not delivered: ${recipientId} not found in project ${projectId}`);
        }
    }
    handleDisconnect(clientId) {
        const client = this.clients.get(clientId);
        if (!client)
            return;
        this.clients.delete(clientId);
        console.log(`[Relay] 👋 Client disconnected: ${clientId} (user: ${client.userId || 'unknown'})`);
    }
    generateId() {
        return Math.random().toString(36).substring(2, 15) +
            Math.random().toString(36).substring(2, 15);
    }
    start() {
        this.httpServer.listen(this.port, () => {
            console.log(`🔌 Relay server running on ws://localhost:${this.port}`);
            console.log(`   Auth: API key required (Bearer token or ?token=...)`);
        });
    }
    stop() {
        this.wss.close();
        this.httpServer.close();
    }
    getStats() {
        const projectStats = {};
        for (const [, client] of this.clients) {
            projectStats[client.projectId] = (projectStats[client.projectId] || 0) + 1;
        }
        return {
            totalClients: this.clients.size,
            totalProjects: this.projectKeys.size,
            projectStats,
        };
    }
    getHealth() {
        return {
            status: 'ok',
            clients: this.clients.size,
            uptime: process.uptime(),
        };
    }
}
// Standalone mode
if (import.meta.url === `file://${process.argv[1]}`) {
    const relay = new RelayServer(parseInt(process.env.RELAY_PORT || '3002'));
    relay.start();
}
export default RelayServer;
