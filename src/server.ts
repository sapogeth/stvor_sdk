import * as path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { relayIdentity } from './identity/relayIdentity.js';
import { initStorage } from './storage/json.js';
import { registerAuthMiddleware } from './middleware/auth.js';
import { createProjectWithApiKey, storeApiKey } from './auth/apiKey.js';
import healthRoutes from './routes/health.js';
import projectsRoutes from './routes/projects.js';
import e2eRoutes from './routes/e2e.js';
import db, { initDb } from './storage/db.js';
import { RelayServer } from './relay/server.js';

dotenv.config();

// Initialize persistent storage FIRST
initStorage();
relayIdentity.init();

const app = Fastify({ logger: true });

// Register auth middleware globally FIRST
registerAuthMiddleware(app);

const start = async () => {
  // Try to connect to database (optional - fallback to JSON storage if unavailable)
  try {
    await initDb();
    console.log('✅ PostgreSQL connected');
  } catch (error) {
    console.warn('⚠️ PostgreSQL not available, using JSON storage fallback');
  }

  await app.register(cors, {
    origin: [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:3001',
      'http://127.0.0.1:3001',
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
  });

  // Rate limiting
  await app.register(rateLimit, {
    max: 100,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      error: 'Too many requests',
      message: 'Rate limit exceeded. Please try again later.',
    }),
  });

  app.get('/__routes', async () => {
    return app.printRoutes();
  });

  // Bootstrap: ONLY in development
  app.post('/bootstrap', async (_req, reply) => {
    if (process.env.NODE_ENV === 'production') {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'Bootstrap endpoint is not available in production'
      });
    }

    const { projectId, apiKey } = createProjectWithApiKey();
    return reply.send({ project_id: projectId, api_key: apiKey });
  });

  // Import key: ONLY in development (for migration/testing)
  app.post('/import-key', async (req, reply) => {
    if (process.env.NODE_ENV === 'production') {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'Import endpoint is not available in production'
      });
    }

    const { api_key, project_id } = req.body as { api_key: string; project_id: string };
    if (!api_key || !project_id) {
      return reply.code(400).send({ error: 'api_key and project_id required' });
    }
    storeApiKey(api_key, project_id);
    return reply.send({ ok: true });
  });

  app.register(healthRoutes);
  app.register(projectsRoutes);
  app.register(e2eRoutes);

  // /usage endpoint - get current quota usage
  app.get('/usage', async (request: FastifyRequest, reply: FastifyReply) => {
    const appToken = request.headers['authorization']?.replace('Bearer ', '');
    if (!appToken) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    const usage = await db.getUsage(appToken);
    if (!usage) {
      return reply.status(404).send({ error: 'AppToken not found' });
    }

    return reply.send(usage);
  });

  // /limits endpoint - get quota limits
  app.get('/limits', async (request: FastifyRequest, reply: FastifyReply) => {
    const appToken = request.headers['authorization']?.replace('Bearer ', '');
    if (!appToken) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }

    const limits = await db.getLimits(appToken);
    if (!limits) {
      return reply.status(404).send({ error: 'AppToken not found' });
    }

    return reply.send(limits);
  });

  // /projects endpoint - create new project with token
  app.post('/api/projects', async (request: FastifyRequest, reply: FastifyReply) => {
    const { name } = request.body as { name?: string };
    if (!name) {
      return reply.status(400).send({ error: 'Project name is required' });
    }

    try {
      const project = await db.createProject(name);
      const appToken = await db.createToken(project.id, 'free');
      return reply.send({ 
        projectId: project.id, 
        appToken,
        plan: 'free',
        limit: 1000
      });
    } catch (error) {
      return reply.status(500).send({ error: 'Failed to create project' });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const fastifyStatic = (await import('@fastify/static')).default;
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    app.register(fastifyStatic, {
      root: path.join(__dirname, '../ui'),
      prefix: '/',
      index: ['index.html'],
    });
  }
  await app.listen({ port: 3001, host: '0.0.0.0' });
  console.log('🚀 STVOR API running on http://localhost:3001');

  // Start WebSocket relay server
  const relayPort = parseInt(process.env.RELAY_PORT || '3002');
  const relay = new RelayServer(relayPort);
  relay.start();
};

start().catch(err => {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
});
