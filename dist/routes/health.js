export default async function healthRoutes(fastify) {
    fastify.get('/health', async (_request, reply) => {
        reply.send({ status: 'ok' });
    });
}
