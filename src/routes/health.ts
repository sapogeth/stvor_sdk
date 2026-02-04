import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

export default async function healthRoutes(fastify: FastifyInstance) {
  fastify.get('/health', async (_request: FastifyRequest, reply: FastifyReply) => {
    reply.send({ status: 'ok' });
  });
}
