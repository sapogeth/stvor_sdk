import fastify from 'fastify';
import cors from '@fastify/cors';
import { getProjectIdByApiKey } from '../auth/apiKey.js';
const registry = new Map();
function getAuthToken(req) {
    const auth = req.headers['authorization'];
    return auth?.startsWith('Bearer ') ? auth.slice(7) : null;
}
export class RelayServer {
    constructor(port = 3002) {
        const app = fastify();
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
                if (!user_id || !publicKeys)
                    return reply.status(400).send({ error: 'Missing fields' });
                if (!registry.has(projectId))
                    registry.set(projectId, new Map());
                registry.get(projectId).set(user_id, { publicKeys, messages: [] });
                console.log(`[Relay] Registered: ${user_id}`);
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
                const user = project?.get(req.params.userId);
                if (!user)
                    return reply.status(404).send({ error: 'User not found' });
                return { publicKeys: user.publicKeys };
            });
            app.post('/message', (req, reply) => {
                const token = getAuthToken(req);
                if (!token)
                    return reply.status(401).send({ error: 'Missing token' });
                const projectId = getProjectIdByApiKey(token);
                if (!projectId)
                    return reply.status(401).send({ error: 'Invalid token' });
                const { to, from, ciphertext, header } = req.body;
                if (!to || !from || !ciphertext || !header)
                    return reply.status(400).send({ error: 'Missing fields' });
                const project = registry.get(projectId);
                const recipient = project?.get(to);
                if (!recipient)
                    return reply.status(404).send({ error: 'Recipient not found' });
                recipient.messages.push({ from, ciphertext, header, timestamp: new Date().toISOString() });
                console.log(`[Relay] Message: ${from} → ${to}`);
                return { status: 'delivered' };
            });
            app.get('/messages/:userId', (req, reply) => {
                const token = getAuthToken(req);
                if (!token)
                    return reply.status(401).send({ error: 'Missing token' });
                const projectId = getProjectIdByApiKey(token);
                if (!projectId)
                    return reply.status(401).send({ error: 'Invalid token' });
                const project = registry.get(projectId);
                const user = project?.get(req.params.userId);
                if (!user)
                    return reply.status(404).send({ error: 'User not found' });
                const messages = user.messages;
                user.messages = [];
                return { messages };
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
}
export async function startRelay() {
    const port = process.env.RELAY_PORT || 3002;
    new RelayServer(Number(port));
}
if (import.meta.url === `file://${process.argv[1]}`) {
    startRelay();
}
