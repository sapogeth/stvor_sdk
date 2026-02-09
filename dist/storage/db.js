import { Pool } from 'pg';
import dotenv from 'dotenv';
dotenv.config();
// PostgreSQL connection pool
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'stvor',
    password: process.env.DB_PASSWORD || 'stvor123',
    port: parseInt(process.env.DB_PORT || '5432'),
});
let isDbAvailable = false;
// Initialize database connection
export async function initDb() {
    try {
        const client = await pool.connect();
        console.log('✅ Database connected');
        isDbAvailable = true;
        client.release();
    }
    catch (error) {
        console.error('❌ Database connection failed:', error);
        isDbAvailable = false;
        throw error;
    }
}
export function isDatabaseAvailable() {
    return isDbAvailable;
}
// Query helper
export async function query(text, params) {
    return pool.query(text, params);
}
// Token operations
export async function getToken(token) {
    const { rows } = await pool.query(`SELECT token, project_id, plan, used_messages, monthly_message_limit, reset_at
     FROM app_tokens
     WHERE token = $1`, [token]);
    return rows[0] || null;
}
export async function createToken(projectId, plan = 'free') {
    const token = `stvor_live_${Math.random().toString(36).slice(2, 14)}`;
    const limits = {
        free: 1000,
        starter: 10000,
        unlimited: -1,
    };
    await pool.query(`INSERT INTO app_tokens (token, project_id, plan, used_messages, monthly_message_limit, reset_at)
     VALUES ($1, $2, $3, 0, $4, DATE_TRUNC('month', NOW()) + INTERVAL '1 month')`, [token, projectId, plan, limits[plan]]);
    return token;
}
export async function incrementUsage(token) {
    const { rows } = await pool.query(`UPDATE app_tokens
     SET used_messages = used_messages + 1
     WHERE token = $1
       AND (plan = 'unlimited' OR used_messages < monthly_message_limit)
     RETURNING used_messages AS used, monthly_message_limit AS limit`, [token]);
    return rows[0] || null;
}
export async function getUsage(token) {
    if (!isDbAvailable) {
        // Fallback: return mock data for development
        return {
            plan: 'free',
            used: 0,
            limit: 1000,
            reset_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        };
    }
    const { rows } = await pool.query(`SELECT plan, used_messages AS used, monthly_message_limit AS limit, reset_at
     FROM app_tokens
     WHERE token = $1`, [token]);
    return rows[0] || null;
}
export async function getLimits(token) {
    if (!isDbAvailable) {
        // Fallback: return mock data for development
        return {
            plan: 'free',
            limit: 1000,
            reset_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        };
    }
    const { rows } = await pool.query(`SELECT plan, monthly_message_limit AS limit, reset_at
     FROM app_tokens
     WHERE token = $1`, [token]);
    return rows[0] || null;
}
// Project operations
export async function createProject(name) {
    const { rows } = await pool.query(`INSERT INTO projects (name) VALUES ($1) RETURNING id, name, created_at`, [name]);
    return rows[0];
}
export async function getProject(id) {
    const { rows } = await pool.query(`SELECT id, name, created_at FROM projects WHERE id = $1`, [id]);
    return rows[0] || null;
}
// Reset monthly quotas (run via cron job)
export async function resetMonthlyQuotas() {
    await pool.query(`UPDATE app_tokens
     SET used_messages = 0, reset_at = DATE_TRUNC('month', NOW()) + INTERVAL '1 month'
     WHERE reset_at <= NOW()`);
}
// ═══════════════════════════════════════════════════════════════════════════
// METRICS OPERATIONS (Backend verification)
// ═══════════════════════════════════════════════════════════════════════════
export async function getProjectByToken(appToken) {
    try {
        const { rows } = await pool.query(`SELECT p.id, p.name FROM projects p
       JOIN app_tokens t ON p.id = t.project_id
       WHERE t.token = $1 LIMIT 1`, [appToken]);
        return rows[0] || null;
    }
    catch (error) {
        console.error('[DB] getProjectByToken error:', error);
        return null;
    }
}
export async function insertVerifiedMetrics(verified) {
    try {
        const { rows } = await pool.query(`INSERT INTO verified_metrics 
       (project_id, session_id, metrics, sequence_number, attestation_id, 
        attestation_timestamp, verified_at, proof)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`, [
            verified.projectId,
            verified.sessionId,
            JSON.stringify(verified.metrics),
            verified.sequenceNumber,
            verified.attestationId || verified.sessionId + '_' + verified.sequenceNumber,
            verified.timestamp,
            verified.verifiedAt,
            verified.proof,
        ]);
        return rows[0];
    }
    catch (error) {
        console.error('[DB] insertVerifiedMetrics error:', error);
        throw error;
    }
}
export async function getLatestVerifiedMetrics(projectId) {
    try {
        const { rows } = await pool.query(`SELECT project_id, session_id, metrics, sequence_number, attestation_id,
              attestation_timestamp, verified_at
       FROM verified_metrics
       WHERE project_id = $1
       ORDER BY sequence_number DESC
       LIMIT 1`, [projectId]);
        if (!rows[0])
            return null;
        return {
            projectId: rows[0].project_id,
            sessionId: rows[0].session_id,
            metrics: JSON.parse(rows[0].metrics),
            sequenceNumber: rows[0].sequence_number,
            attestationId: rows[0].attestation_id,
            timestamp: rows[0].attestation_timestamp,
            verifiedAt: rows[0].verified_at,
        };
    }
    catch (error) {
        console.error('[DB] getLatestVerifiedMetrics error:', error);
        return null;
    }
}
export async function insertAuditLog(log) {
    try {
        await pool.query(`INSERT INTO metrics_audit_log 
       (project_id, session_id, attestation_id, event_type, reason)
       VALUES ($1, $2, $3, $4, $5)`, [
            log.projectId,
            log.sessionId || null,
            log.attestationId || null,
            log.event || log.eventType || 'unknown',
            log.reason || null,
        ]);
    }
    catch (error) {
        console.error('[DB] insertAuditLog error:', error);
    }
}
export async function getMetricsAuditLog(projectId, limit = 100) {
    try {
        const { rows } = await pool.query(`SELECT id, project_id, session_id, attestation_id, event_type, reason, created_at
       FROM metrics_audit_log
       WHERE project_id = $1
       ORDER BY created_at DESC
       LIMIT $2`, [projectId, limit]);
        return rows;
    }
    catch (error) {
        console.error('[DB] getMetricsAuditLog error:', error);
        return [];
    }
}
export async function verifyProjectAccess(projectId, token) {
    try {
        // Check if token is valid and has access to projectId
        const { rows } = await pool.query(`SELECT t.project_id FROM app_tokens t
       WHERE t.token = $1 AND t.project_id::text = $2 LIMIT 1`, [token, projectId]);
        return rows.length > 0;
    }
    catch (error) {
        console.error('[DB] verifyProjectAccess error:', error);
        return false;
    }
}
export async function verifyAdminAccess(projectId, token) {
    // In a real system, check admin role; for now, same as verifyProjectAccess
    return verifyProjectAccess(projectId, token);
}
export const db = {
    query,
    getToken,
    createToken,
    incrementUsage,
    getUsage,
    getLimits,
    createProject,
    getProject,
    resetMonthlyQuotas,
    getProjectByToken,
    insertVerifiedMetrics,
    getLatestVerifiedMetrics,
    insertAuditLog,
    getMetricsAuditLog,
    verifyProjectAccess,
    verifyAdminAccess,
};
export default db;
