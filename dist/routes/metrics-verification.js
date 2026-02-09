import { createHmac } from 'crypto';
import * as db from '../storage/db.js';
export default async function metricsRoutes(app) {
    // POST /api/metrics/attest
    app.post('/attest', async (req, reply) => {
        const { appToken, attestation } = req.body;
        if (!appToken || !attestation) {
            return reply.status(400).send({ error: 'Missing appToken or attestation' });
        }
        const project = await db.getProjectByToken(appToken);
        if (!project) {
            console.error(`[Metrics] Unknown appToken: ${appToken.slice(0, 20)}***`);
            return reply.status(401).send({ error: 'Invalid appToken' });
        }
        const verification = await verifyAttestation(attestation, appToken, project);
        if (!verification.valid) {
            await db.insertAuditLog({
                projectId: project.id,
                event: 'METRICS_ATTESTATION_REJECTED',
                reason: verification.reason,
                attestationId: attestation.attestationId,
                sessionId: attestation.sessionId,
            });
            return reply.status(400).send({
                error: 'Attestation verification failed',
                reason: verification.reason,
            });
        }
        try {
            await db.insertVerifiedMetrics({
                projectId: project.id,
                sessionId: attestation.sessionId,
                metrics: attestation.metrics,
                sequenceNumber: attestation.sequenceNumber,
                timestamp: attestation.timestamp,
                verifiedAt: Date.now(),
                proof: attestation.proof,
            });
            await db.insertAuditLog({
                projectId: project.id,
                event: 'METRICS_ATTESTATION_VERIFIED',
                attestationId: attestation.attestationId,
                sessionId: attestation.sessionId,
            });
            return reply.send({
                status: 'verified',
                sequenceNumber: attestation.sequenceNumber,
            });
        }
        catch (error) {
            console.error('[Metrics] Storage error:', error);
            return reply.status(500).send({ error: 'Internal server error' });
        }
    });
    // GET /api/metrics
    app.get('/', async (req, reply) => {
        const { projectId } = req.query;
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!projectId || !token) {
            return reply.status(401).send({ error: 'Missing projectId or auth token' });
        }
        const access = await db.verifyProjectAccess?.(projectId, token);
        if (!access) {
            return reply.status(403).send({ error: 'Access denied' });
        }
        const verified = await db.getLatestVerifiedMetrics?.(projectId);
        if (!verified) {
            return reply.send({
                status: 'no_verified_activity',
                metrics: null,
                message: 'No verified E2EE activity for this project',
            });
        }
        return reply.send({
            status: 'verified',
            metrics: verified.metrics,
            sessionId: verified.sessionId,
            sequenceNumber: verified.sequenceNumber,
            timestamp: verified.timestamp,
            verifiedAt: verified.verifiedAt,
        });
    });
    // GET /api/metrics/audit
    app.get('/audit', async (req, reply) => {
        const { projectId } = req.query;
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (!projectId || !token) {
            return reply.status(401).send({ error: 'Missing projectId or auth' });
        }
        const isAdmin = await db.verifyAdminAccess?.(projectId, token);
        if (!isAdmin) {
            return reply.status(403).send({ error: 'Admin access required' });
        }
        const audit = await db.getMetricsAuditLog?.(projectId);
        return reply.send({ audit });
    });
}
async function verifyAttestation(attestation, appToken, project) {
    if (!verifyProof(attestation, appToken)) {
        return { valid: false, reason: 'Signature verification failed' };
    }
    const now = Date.now();
    const maxAge = 5 * 60 * 1000;
    if (now - attestation.timestamp > maxAge) {
        return { valid: false, reason: 'Attestation timestamp too old' };
    }
    if (attestation.timestamp > now + 60 * 1000) {
        return { valid: false, reason: 'Attestation timestamp in future' };
    }
    if (await hasSeenAttestationId(project.id, attestation.attestationId)) {
        return { valid: false, reason: 'Attestation already processed' };
    }
    const lastSeq = await getLastSequenceNumber(project.id, attestation.sessionId);
    if (lastSeq !== null && attestation.sequenceNumber !== lastSeq + 1) {
        return { valid: false, reason: 'Sequence number not monotonic' };
    }
    return { valid: true, reason: 'All verifications passed' };
}
function verifyProof(attestation, appToken) {
    const attestationKey = deriveAttestationKey(appToken);
    const payload = JSON.stringify({
        metrics: attestation.metrics,
        sessionId: attestation.sessionId,
        sequenceNumber: attestation.sequenceNumber,
        timestamp: attestation.timestamp,
        attestationId: attestation.attestationId,
    });
    const hmac = createHmac('sha256', attestationKey);
    hmac.update(payload);
    const computedProof = hmac.digest('hex');
    return constantTimeCompare(computedProof, attestation.proof);
}
function deriveAttestationKey(appToken) {
    const salt = Buffer.alloc(32, 0);
    const info = Buffer.from('stvor-metrics-attestation-v1');
    const hmacExtract = createHmac('sha256', salt);
    hmacExtract.update(appToken);
    const prk = hmacExtract.digest();
    const hmacExpand = createHmac('sha256', prk);
    hmacExpand.update(info);
    hmacExpand.update(Buffer.from([1]));
    return hmacExpand.digest();
}
function constantTimeCompare(a, b) {
    if (a.length !== b.length)
        return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}
async function hasSeenAttestationId(projectId, attestationId) {
    try {
        const result = await db.query?.('SELECT COUNT(*) as cnt FROM verified_metrics WHERE project_id = $1 AND attestation_id = $2', [projectId, attestationId]);
        return result?.rows[0]?.cnt > 0 || false;
    }
    catch {
        return false;
    }
}
async function getLastSequenceNumber(projectId, sessionId) {
    try {
        const result = await db.query?.('SELECT MAX(sequence_number) as max_seq FROM verified_metrics WHERE project_id = $1 AND session_id = $2', [projectId, sessionId]);
        return result?.rows[0]?.max_seq ?? null;
    }
    catch {
        return null;
    }
}
