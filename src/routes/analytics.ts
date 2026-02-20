import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as db from '../storage/db.js';
import { getProjectIdByApiKey } from '../auth/apiKey.js';

type AnalyticsEventBody = {
  handshakes: number;
  messagesEncrypted: number;
  messagesDecrypted: number;
  errors: number;
  sdkVersion?: string;
  timestamp?: number;
};

export default async function analyticsRoutes(app: FastifyInstance) {

  // POST /analytics/event - агрегированные метрики SDK
  app.post<{ Body: AnalyticsEventBody }>('/event', async (req: FastifyRequest<{ Body: AnalyticsEventBody }>, reply: FastifyReply) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) {
      return reply.status(401).send({ error: 'Missing auth token' });
    }

    const projectId = getProjectIdByApiKey(token);
    if (!projectId) {
      return reply.status(401).send({ error: 'Invalid token' });
    }

    const {
      handshakes,
      messagesEncrypted,
      messagesDecrypted,
      errors,
      sdkVersion,
      timestamp
    } = req.body;

    // Validate and sanitize input values
    const MAX_HANDSHAKES = 1000000;
    const MAX_MESSAGES = 10000000;

    if (
      typeof handshakes !== 'number' ||
      typeof messagesEncrypted !== 'number' ||
      typeof messagesDecrypted !== 'number' ||
      typeof errors !== 'number'
    ) {
      return reply.status(400).send({ error: 'Invalid payload' });
    }

    if (
      handshakes < 0 ||
      messagesEncrypted < 0 ||
      messagesDecrypted < 0 ||
      errors < 0
    ) {
      return reply.status(400).send({ error: 'Negative values not allowed' });
    }

    // Protect against absurd values (replay/abuse)
    if (
      handshakes > MAX_HANDSHAKES ||
      messagesEncrypted > MAX_MESSAGES ||
      messagesDecrypted > MAX_MESSAGES ||
      errors > MAX_MESSAGES
    ) {
      return reply.status(400).send({ error: 'Values exceed maximum allowed' });
    }

    try {
      await db.recordDailyStats({
        projectId,
        handshakes,
        messagesEncrypted,
        messagesDecrypted,
        errors,
        sdkVersion: sdkVersion || 'unknown',
        timestamp: typeof timestamp === 'number' ? timestamp : Date.now()
      });

      return reply.send({ status: 'recorded' });
    } catch {
      return reply.status(500).send({ error: 'Failed to record analytics' });
    }
  });

  // GET /analytics/dashboard - агрегированная статистика
  app.get('/dashboard', async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const totalStats = await db.getTotalAnalytics();
      const recentStats = await db.getRecentAnalytics(30);
      const sdkVersions = await db.getSdkVersionStats();

      return reply.send({
        total: totalStats,
        recent: recentStats,
        sdkVersions,
        generatedAt: Date.now()
      });
    } catch {
      return reply.status(500).send({ error: 'Failed to load analytics' });
    }
  });

  // GET /analytics/project/:projectId - статистика конкретного проекта
  app.get<{ Params: { projectId: string } }>(
    '/project/:projectId',
    async (req: FastifyRequest<{ Params: { projectId: string } }>, reply: FastifyReply) => {
      const { projectId } = req.params;
      const token = req.headers['authorization']?.replace('Bearer ', '');

      if (!token) {
        return reply.status(401).send({ error: 'Missing auth token' });
      }

      const access = await db.verifyProjectAccess(projectId, token);
      if (!access) {
        return reply.status(403).send({ error: 'Access denied' });
      }

      try {
        const projectStats = await db.getProjectAnalytics(projectId);
        return reply.send(projectStats);
      } catch {
        return reply.status(500).send({ error: 'Failed to load project analytics' });
      }
    }
  );

  // GET /analytics/realtime - агрегированная realtime статистика
  app.get('/realtime', async (_req: FastifyRequest, reply: FastifyReply) => {
    try {
      const realtime = await db.getRealtimeStats();
      return reply.send(realtime);
    } catch {
      return reply.status(500).send({ error: 'Failed to load realtime stats' });
    }
  });
}