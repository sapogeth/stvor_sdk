import fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { getProjectIdByApiKey } from '../auth/apiKey.js';
import * as db from '../storage/db.js';
const registry = new Map();
let cleanupHandle = null;
// TTL для сообщений: 10 минут
const MESSAGE_TTL_MS = 10 * 60 * 1000;
// Cleanup interval: каждые 5 минут
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
// Max размер сообщения: 32KB
const MAX_MESSAGE_SIZE = 32 * 1024;
// Max messages per user (prevent memory exhaustion)
const MAX_PENDING_MESSAGES = 1000;
// Max users per project
const MAX_USERS_PER_PROJECT = 10000;
function getAuthToken(req) {
    const auth = req.headers['authorization'];
    return auth?.startsWith('Bearer ') ? auth.slice(7) : null;
}
function validateUserId(userId) {
    return typeof userId === 'string' && userId.length > 0 && userId.length <= 256;
}
function validateMessage(msg) {
    return msg && typeof msg === 'object' &&
        typeof msg.from === 'string' && msg.from.length > 0 &&
        typeof msg.ciphertext === 'string' &&
        typeof msg.header === 'object';
}
export class RelayServer {
    constructor(port = 3002) {
        const app = fastify({ logger: false });
        // Rate limiting: 100 requests per minute per IP
        app.register(rateLimit, {
            max: 100,
            timeWindow: '1 minute',
            errorResponseBuilder: () => ({
                error: 'Too many requests',
                message: 'Rate limit exceeded. Max 100 requests per minute.'
            })
        });
        // Cleanup старых сообщений каждые 5 минут
        cleanupHandle = setInterval(() => this.cleanupOldMessages(), CLEANUP_INTERVAL_MS);
        // Graceful shutdown: SIGTERM и SIGINT
        const gracefulShutdown = () => {
            console.log('[Relay] Received shutdown signal, stopping...');
            if (cleanupHandle) {
                clearInterval(cleanupHandle);
                cleanupHandle = null;
            }
            registry.clear();
            process.exit(0);
        };
        process.on('SIGTERM', gracefulShutdown);
        process.on('SIGINT', gracefulShutdown);
        // Register basic health endpoint BEFORE cors
        app.get('/health', (req, reply) => {
            return { status: 'ok' };
        });
        app.register(cors).then(() => {
            app.post('/register', (req, reply) => {
                const token = getAuthToken(req);
                if (!token)
                    return reply.status(401).send({ error: 'Missing token' });
                const projectId = getProjectIdByApiKey(token);
                if (!projectId)
                    return reply.status(401).send({ error: 'Invalid token' });
                const { user_id, publicKeys } = req.body;
                // Validate user_id
                if (!validateUserId(user_id)) {
                    return reply.status(400).send({ error: 'Invalid user_id: must be non-empty string (max 256 chars)' });
                }
                // Validate publicKeys
                if (!publicKeys || typeof publicKeys !== 'object') {
                    return reply.status(400).send({ error: 'Invalid publicKeys: must be an object' });
                }
                // Check project registry size
                if (!registry.has(projectId)) {
                    registry.set(projectId, new Map());
                }
                const project = registry.get(projectId);
                if (project.size >= MAX_USERS_PER_PROJECT && !project.has(user_id)) {
                    return reply.status(429).send({ error: 'Project user limit exceeded' });
                }
                project.set(user_id, {
                    publicKeys,
                    messages: [],
                    lastActivity: Date.now()
                });
                console.log(`[Relay] Registered: ${user_id} (project: ${projectId})`);
                return { status: 'registered' };
            });
            app.get('/public-key/:userId', (req, reply) => {
                const token = getAuthToken(req);
                if (!token)
                    return reply.status(401).send({ error: 'Missing token' });
                const projectId = getProjectIdByApiKey(token);
                if (!projectId)
                    return reply.status(401).send({ error: 'Invalid token' });
                const project = registry.get(projectId);
                const userId = req.params.userId;
                const user = project?.get(userId);
                if (!user)
                    return reply.status(404).send({ error: 'User not found' });
                return { publicKeys: user.publicKeys };
            });
            app.post('/message', async (req, reply) => {
                const token = getAuthToken(req);
                if (!token)
                    return reply.status(401).send({ error: 'Missing token' });
                const projectId = getProjectIdByApiKey(token);
                if (!projectId)
                    return reply.status(401).send({ error: 'Invalid token' });
                const { to, from, ciphertext, header } = req.body;
                // Validate all fields
                if (!validateUserId(to)) {
                    return reply.status(400).send({ error: 'Invalid recipient user_id' });
                }
                if (!validateUserId(from)) {
                    return reply.status(400).send({ error: 'Invalid sender user_id' });
                }
                if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
                    return reply.status(400).send({ error: 'Invalid ciphertext' });
                }
                if (typeof header !== 'object') {
                    return reply.status(400).send({ error: 'Invalid header' });
                }
                // Prevent self-messages
                if (to === from) {
                    return reply.status(400).send({ error: 'Cannot send message to yourself' });
                }
                // Проверка размера сообщения
                if (ciphertext.length > MAX_MESSAGE_SIZE) {
                    return reply.status(400).send({
                        error: 'Message too large',
                        maxSize: MAX_MESSAGE_SIZE,
                        receivedSize: ciphertext.length
                    });
                }
                const project = registry.get(projectId);
                const recipient = project?.get(to);
                if (!recipient) {
                    return reply.status(404).send({ error: 'Recipient not found' });
                }
                // Check pending message queue size
                if (recipient.messages.length >= MAX_PENDING_MESSAGES) {
                    return reply.status(429).send({
                        error: 'Recipient message queue full',
                        maxMessages: MAX_PENDING_MESSAGES
                    });
                }
                recipient.messages.push({
                    from,
                    ciphertext,
                    header,
                    timestamp: new Date().toISOString(),
                    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
                });
                recipient.lastActivity = Date.now();
                // 🔥 АНАЛИТИКА: Записываем событие отправки сообщения
                try {
                    await db.recordAnalyticsEvent({
                        projectId,
                        event: 'message_sent',
                        userId: from,
                        sessionId: `relay_${Date.now()}`,
                        messageSize: ciphertext.length,
                        userAgent: req.headers['user-agent'] || 'unknown',
                        sdkVersion: req.headers['x-stvor-version'] || 'unknown',
                        timestamp: Date.now(),
                        ip: req.ip || 'unknown'
                    });
                }
                catch (error) {
                    console.warn('[Analytics] Failed to record message event:', error);
                }
                console.log(`[Relay] Message: ${from} → ${to} (project: ${projectId})`);
                return { status: 'delivered', messageId: recipient.messages[recipient.messages.length - 1].id };
            });
            app.get('/messages/:userId', (req, reply) => {
                const token = getAuthToken(req);
                if (!token)
                    return reply.status(401).send({ error: 'Missing token' });
                const projectId = getProjectIdByApiKey(token);
                if (!projectId)
                    return reply.status(401).send({ error: 'Invalid token' });
                const userId = req.params.userId;
                if (!validateUserId(userId)) {
                    return reply.status(400).send({ error: 'Invalid user_id' });
                }
                const project = registry.get(projectId);
                if (!project) {
                    return reply.status(404).send({ error: 'Project not found' });
                }
                const user = project.get(userId);
                if (!user) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                const messages = user.messages;
                user.messages = [];
                user.lastActivity = Date.now();
                console.log(`[Relay] Retrieved ${messages.length} messages for ${userId} (project: ${projectId})`);
                return { messages, count: messages.length };
            });
            // Stats endpoint - no auth required (for monitoring)
            app.get('/stats', (req, reply) => {
                let totalProjects = 0;
                let totalUsers = 0;
                let totalMessages = 0;
                for (const [_, project] of Array.from(registry.entries())) {
                    totalProjects++;
                    for (const [_, userData] of Array.from(project.entries())) {
                        totalUsers++;
                        totalMessages += userData.messages.length;
                    }
                }
                return {
                    status: 'ok',
                    registry: {
                        projects: totalProjects,
                        users: totalUsers,
                        pendingMessages: totalMessages
                    },
                    limits: {
                        maxUsersPerProject: MAX_USERS_PER_PROJECT,
                        maxMessagesPerUser: MAX_PENDING_MESSAGES,
                        maxMessageSize: MAX_MESSAGE_SIZE,
                        messageTtlMs: MESSAGE_TTL_MS
                    }
                };
            });
            app.listen({ port, host: '0.0.0.0' }, (err) => {
                if (err) {
                    console.error('[Relay] Failed:', err);
                    process.exit(1);
                }
                console.log(`[Relay] ✅ HTTP Relay on port ${port}`);
            });
        });
    }
    stop() {
        // app already closed via fastify lifecycle
    }
    // Очистка старых сообщений для предотвращения утечки памяти
    cleanupOldMessages() {
        try {
            const now = Date.now();
            let cleaned = 0;
            let usersRemoved = 0;
            let projectsRemoved = 0;
            for (const [projectId, users] of Array.from(registry.entries())) {
                for (const [userId, userData] of Array.from(users.entries())) {
                    const beforeCount = userData.messages.length;
                    userData.messages = userData.messages.filter(msg => now - new Date(msg.timestamp).getTime() < MESSAGE_TTL_MS);
                    cleaned += beforeCount - userData.messages.length;
                    // Remove inactive users (30 minutes inactivity)
                    if (now - userData.lastActivity > 30 * 60 * 1000) {
                        users.delete(userId);
                        usersRemoved++;
                    }
                }
                // Remove empty projects
                if (users.size === 0) {
                    registry.delete(projectId);
                    projectsRemoved++;
                }
            }
            if (cleaned > 0 || usersRemoved > 0 || projectsRemoved > 0) {
                console.log(`[Relay] Cleanup: removed ${cleaned} messages, ${usersRemoved} inactive users, ${projectsRemoved} empty projects`);
            }
        }
        catch (error) {
            console.error('[Relay] Cleanup error:', error);
        }
    }
}
export async function startRelay() {
    const port = process.env.RELAY_PORT || 3002;
    new RelayServer(Number(port));
}
if (import.meta.url === `file://${process.argv[1]}`) {
    startRelay();
}
