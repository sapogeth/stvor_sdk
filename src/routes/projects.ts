import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'crypto';
import { generateApiKey, storeApiKey } from '../auth/apiKey.js';

export default async function projectsRoutes(fastify: FastifyInstance) {
  fastify.post('/projects', async (_request: FastifyRequest, reply: FastifyReply) => {
    const project_id = randomUUID();
    const api_key = generateApiKey();
    storeApiKey(api_key, project_id);
    reply.send({ project_id, api_key });
  });
}
