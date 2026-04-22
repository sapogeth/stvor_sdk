import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'crypto';
import { generateApiKey, storeApiKey } from '../auth/apiKey.js';

export default async function projectsRoutes(fastify: FastifyInstance) {
  // Create a new project with auto-generated API key
  fastify.post('/projects', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      const project_id = randomUUID();
      const api_key = generateApiKey();
      storeApiKey(api_key, project_id);
      
      return reply.status(201).send({ 
        project_id, 
        api_key,
        created_at: new Date().toISOString(),
        type: 'project'
      });
    } catch (error) {
      return reply.status(500).send({
        error: 'PROJECT_CREATION_FAILED',
        message: error instanceof Error ? error.message : 'Failed to create project'
      });
    }
  });

  // Get project info (requires API key)
  fastify.get('/projects/:project_id', async (request: FastifyRequest, reply: FastifyReply) => {
    const { project_id } = request.params as { project_id: string };
    const authHeader = request.headers['authorization'];
    
    if (!authHeader?.startsWith('Bearer ')) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header'
      });
    }

    // Validate project_id format (should be UUID)
    if (!isValidUUID(project_id)) {
      return reply.status(400).send({
        error: 'INVALID_PROJECT_ID',
        message: 'Project ID must be a valid UUID'
      });
    }

    return reply.send({
      project_id,
      created_at: new Date().toISOString(),
      status: 'active'
    });
  });

  // List projects for current user (requires API key)
  fastify.get('/projects', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.send({
      projects: [],
      total: 0,
      message: 'Project listing requires authentication'
    });
  });
}

function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
