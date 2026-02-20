import fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { getProjectIdByApiKey } from '../auth/apiKey.js';
import * as db from '../storage/db.js';

const registry = new Map<string, Map<string, { publicKeys: any; messages: any[]; lastActivity: number }>>();
let cleanupHandle: ReturnType<typeof setInterval> | null = null;

// TTL для сообщений: 10 минут
const MESSAGE_TTL_MS = 10 * 60 * 1000;
// Cleanup interval: каждые 5 минут
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
// Max размер сообщения: 32KB
const MAX_MESSAGE_SIZE = 32 * 1024;

function getAuthToken(req: any): string | null {
  const auth = req.headers['authorization'];
  return auth?.startsWith('Bearer ') ? auth.slice(7) : null;
}

export class RelayServer {
  constructor(port: number = 3002) {
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
      app.post<{ Body: any }>('/register', (req, reply) => {
        const token = getAuthToken(req);
        if (!token) return reply.status(401).send({ error: 'Missing token' });

        const projectId = getProjectIdByApiKey(token);
        if (!projectId) return reply.status(401).send({ error: 'Invalid token' });

        const { user_id, publicKeys } = req.body as any;
        if (!user_id || !publicKeys) return reply.status(400).send({ error: 'Missing fields' });

        if (!registry.has(projectId)) registry.set(projectId, new Map());
        registry.get(projectId)!.set(user_id, { 
          publicKeys, 
          messages: [],
          lastActivity: Date.now()
        });

        console.log(`[Relay] Registered: ${user_id}`);
        return { status: 'registered' };
      });

      app.get<{ Params: { userId: string } }>('/public-key/:userId', (req, reply) => {
        const token = getAuthToken(req);
        if (!token) return reply.status(401).send({ error: 'Missing token' });

        const projectId = getProjectIdByApiKey(token);
        if (!projectId) return reply.status(401).send({ error: 'Invalid token' });

        const project = registry.get(projectId);
        const userId = req.params.userId;
        const user = project?.get(userId);
        if (!user) return reply.status(404).send({ error: 'User not found' });

        return { publicKeys: user.publicKeys };
      });

      app.post<{ Body: any }>('/message', async (req, reply) => {
        const token = getAuthToken(req);
        if (!token) return reply.status(401).send({ error: 'Missing token' });

        const projectId = getProjectIdByApiKey(token);
        if (!projectId) return reply.status(401).send({ error: 'Invalid token' });

        const { to, from, ciphertext, header } = req.body as any;
        if (!to || !from || !ciphertext || !header) return reply.status(400).send({ error: 'Missing fields' });

        // Проверка размера сообщения
        if (ciphertext.length > MAX_MESSAGE_SIZE) {
          return reply.status(400).send({ error: 'Message too large' });
        }

        const project = registry.get(projectId);
        const recipient = project?.get(to);
        if (!recipient) return reply.status(404).send({ error: 'Recipient not found' });

        recipient.messages.push({ from, ciphertext, header, timestamp: new Date().toISOString() });
        recipient.lastActivity = Date.now();  // Обновляем активность получателя

        // 🔥 АНАЛИТИКА: Записываем событие отправки сообщения
        try {
          await db.recordAnalyticsEvent({
            projectId,
            event: 'message_sent',
            userId: from,
            sessionId: `relay_${Date.now()}`,
            messageSize: ciphertext.length,
            userAgent: (req.headers['user-agent'] as string) || 'unknown',
            sdkVersion: (req.headers['x-stvor-version'] as string) || 'unknown',
            timestamp: Date.now(),
            ip: (req.ip as string) || 'unknown'
          });
        } catch (error) {
          console.warn('[Analytics] Failed to record message event:', error);
        }

        console.log(`[Relay] Message: ${from} → ${to}`);
        return { status: 'delivered' };
      });

      app.get<{ Params: { userId: string } }>('/messages/:userId', (req, reply) => {
        const token = getAuthToken(req);
        if (!token) return reply.status(401).send({ error: 'Missing token' });

        const projectId = getProjectIdByApiKey(token);
        if (!projectId) return reply.status(401).send({ error: 'Invalid token' });

        const project = registry.get(projectId);
        const userId = req.params.userId;
        const user = project?.get(userId);
        if (!user) return reply.status(404).send({ error: 'User not found' });

        const messages = user.messages;
        user.messages = [];
        user.lastActivity = Date.now();  // Обновляем активность

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

  stop(): void {
    // app already closed via fastify lifecycle
  }

  // Очистка старых сообщений для предотвращения утечки памяти
  private cleanupOldMessages(): void {
    try {
      const now = Date.now();
      let cleaned = 0;

      for (const [projectId, users] of Array.from(registry.entries())) {
        for (const [userId, userData] of Array.from(users.entries())) {
          const beforeCount = userData.messages.length;
          userData.messages = userData.messages.filter(
            msg => now - new Date(msg.timestamp).getTime() < MESSAGE_TTL_MS
          );
          cleaned += beforeCount - userData.messages.length;

          if (now - userData.lastActivity > 30 * 60 * 1000) {
            users.delete(userId);
          }
        }

        if (users.size === 0) {
          registry.delete(projectId);
        }
      }

      if (cleaned > 0) {
        console.log(`[Relay] Cleanup: removed ${cleaned} old messages`);
      }
    } catch (error) {
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

