export default async function healthRoutes(fastify) {
    fastify.get('/health', async (_request, reply) => {
        const startTime = Date.now();
        try {
            reply.send({
                status: 'ok',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                responseTime: Date.now() - startTime
            });
        }
        catch (error) {
            return reply.status(503).send({
                status: 'error',
                message: 'Health check failed',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    // Detailed health check endpoint
    fastify.get('/health/detailed', async (_request, reply) => {
        const checks = {
            api: { status: 'healthy', responseTime: 0 },
            memory: { status: 'healthy', usage: 0 },
            timestamp: new Date().toISOString()
        };
        try {
            const start = Date.now();
            checks.api.responseTime = Date.now() - start;
            // Memory check
            const memUsage = process.memoryUsage();
            checks.memory.usage = Math.round((memUsage.heapUsed / 1024 / 1024) * 100) / 100;
            // Warn if memory usage is high
            if (memUsage.heapUsed / memUsage.heapTotal > 0.9) {
                checks.memory.status = 'warning';
            }
            return reply.send({
                status: 'ok',
                checks,
                process: {
                    uptime: process.uptime(),
                    pid: process.pid,
                    nodeVersion: process.version
                }
            });
        }
        catch (error) {
            return reply.status(503).send({
                status: 'error',
                message: 'Detailed health check failed',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    // Liveness probe (for Kubernetes)
    fastify.get('/healthz', async (_request, reply) => {
        reply.send({ status: 'alive' });
    });
    // Readiness probe (for Kubernetes)
    fastify.get('/ready', async (_request, reply) => {
        reply.send({ status: 'ready' });
    });
}
