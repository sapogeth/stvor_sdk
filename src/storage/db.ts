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
export async function initDb(): Promise<void> {
  try {
    const client = await pool.connect();
    console.log('✅ Database connected');
    isDbAvailable = true;
    client.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    isDbAvailable = false;
    throw error;
  }
}

export function isDatabaseAvailable(): boolean {
  return isDbAvailable;
}

// Query helper
export async function query(text: string, params?: any[]) {
  return pool.query(text, params);
}

// Token operations
export async function getToken(token: string) {
  const { rows } = await pool.query(
    `SELECT token, project_id, plan, used_messages, monthly_message_limit, reset_at
     FROM app_tokens
     WHERE token = $1`,
    [token]
  );
  return rows[0] || null;
}

export async function createToken(projectId: number, plan: 'free' | 'starter' | 'unlimited' = 'free') {
  const token = `stvor_live_${Math.random().toString(36).slice(2, 14)}`;
  const limits = {
    free: 1000,
    starter: 10000,
    unlimited: -1,
  };

  await pool.query(
    `INSERT INTO app_tokens (token, project_id, plan, used_messages, monthly_message_limit, reset_at)
     VALUES ($1, $2, $3, 0, $4, DATE_TRUNC('month', NOW()) + INTERVAL '1 month')`,
    [token, projectId, plan, limits[plan]]
  );

  return token;
}

export async function incrementUsage(token: string): Promise<{ used: number; limit: number } | null> {
  const { rows } = await pool.query(
    `UPDATE app_tokens
     SET used_messages = used_messages + 1
     WHERE token = $1
       AND (plan = 'unlimited' OR used_messages < monthly_message_limit)
     RETURNING used_messages AS used, monthly_message_limit AS limit`,
    [token]
  );
  return rows[0] || null;
}

export async function getUsage(token: string) {
  if (!isDbAvailable) {
    // Fallback: return mock data for development
    return {
      plan: 'free',
      used: 0,
      limit: 1000,
      reset_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    };
  }
  const { rows } = await pool.query(
    `SELECT plan, used_messages AS used, monthly_message_limit AS limit, reset_at
     FROM app_tokens
     WHERE token = $1`,
    [token]
  );
  return rows[0] || null;
}

// Analytics functions

// Record aggregated daily stats (stores latest cumulative values)
export async function recordDailyStats(stats: {
  projectId: string;
  handshakes: number;
  messagesEncrypted: number;
  messagesDecrypted: number;
  errors: number;
  sdkVersion: string;
  timestamp: number;
}) {
  // Validate values to prevent abuse
  const MAX_HANDSHAKES = 1000000;
  const MAX_MESSAGES = 10000000;
  
  if (
    stats.handshakes > MAX_HANDSHAKES ||
    stats.messagesEncrypted > MAX_MESSAGES ||
    stats.messagesDecrypted > MAX_MESSAGES ||
    stats.errors > MAX_MESSAGES
  ) {
    console.warn('[Analytics] Rejected absurd analytics values:', {
      handshakes: stats.handshakes,
      messagesEncrypted: stats.messagesEncrypted,
      messagesDecrypted: stats.messagesDecrypted,
      errors: stats.errors
    });
    return;
  }

  if (!isDbAvailable) {
    console.log('[Analytics] DB unavailable, skipping daily stats');
    return;
  }

  const date = new Date(stats.timestamp).toISOString().split('T')[0];
  
  // Use MAX for cumulative values - protects against concurrent SDK instances
  // If Instance A sends 100 and Instance B sends 50, we store MAX = 100
  await pool.query(
    `INSERT INTO analytics_daily_stats 
      (project_id, date, messages_encrypted, messages_decrypted, handshakes, errors, unique_sessions, sdk_versions)
    VALUES ($1, $2, $3, $4, $5, $6, $5, $7)
    ON CONFLICT (project_id, date) DO UPDATE SET
      messages_encrypted = GREATEST(analytics_daily_stats.messages_encrypted, EXCLUDED.messages_encrypted),
      messages_decrypted = GREATEST(analytics_daily_stats.messages_decrypted, EXCLUDED.messages_decrypted),
      handshakes = GREATEST(analytics_daily_stats.handshakes, EXCLUDED.handshakes),
      errors = GREATEST(analytics_daily_stats.errors, EXCLUDED.errors),
      unique_sessions = GREATEST(analytics_daily_stats.unique_sessions, EXCLUDED.unique_sessions),
      sdk_versions = COALESCE(analytics_daily_stats.sdk_versions, '{}'::jsonb) || EXCLUDED.sdk_versions`,
    [
      parseInt(stats.projectId),
      date,
      stats.messagesEncrypted,
      stats.messagesDecrypted,
      stats.handshakes,
      stats.errors,
      JSON.stringify({ [stats.sdkVersion]: stats.handshakes })
    ]
  );
}

export async function recordAnalyticsEvent(event: {
  projectId: string;
  event: string;
  userId: string;
  sessionId: string;
  messageSize: number;
  userAgent: string;
  sdkVersion: string;
  timestamp: number;
  ip: string;
}) {
  if (!isDbAvailable) {
    console.log('[Analytics] DB unavailable, skipping event:', event.event);
    return;
  }

  await pool.query(
    `SELECT record_analytics_event($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      event.projectId,
      event.event,
      event.userId,
      event.sessionId,
      event.messageSize,
      event.userAgent,
      event.sdkVersion,
      event.ip,
      event.timestamp
    ]
  );
}

export async function getTotalAnalytics() {
  if (!isDbAvailable) {
    return {
      totalMessages: 0,
      totalProjects: 0,
      totalUsers: 0,
      totalBytes: 0
    };
  }

  const { rows } = await pool.query(`
    SELECT 
      COUNT(*) FILTER (WHERE event IN ('message_encrypted', 'message_decrypted')) as total_messages,
      COUNT(DISTINCT project_id) as total_projects,
      COUNT(DISTINCT user_id) as total_users,
      SUM(message_size) as total_bytes
    FROM analytics_events
  `);

  return rows[0] || { total_messages: 0, total_projects: 0, total_users: 0, total_bytes: 0 };
}

export async function getRecentAnalytics(days: number = 30) {
  if (!isDbAvailable) {
    return [];
  }

  const { rows } = await pool.query(`
    SELECT 
      DATE_TRUNC('day', created_at) as date,
      COUNT(*) FILTER (WHERE event = 'message_encrypted') as encrypted,
      COUNT(*) FILTER (WHERE event = 'message_decrypted') as decrypted,
      COUNT(DISTINCT user_id) as active_users,
      COUNT(DISTINCT session_id) as sessions
    FROM analytics_events 
    WHERE created_at >= NOW() - INTERVAL '${days} days'
    GROUP BY DATE_TRUNC('day', created_at)
    ORDER BY date DESC
  `);

  return rows;
}

export async function getTopProjectsByActivity(limit: number = 10) {
  if (!isDbAvailable) {
    return [];
  }

  const { rows } = await pool.query(`
    SELECT 
      p.name,
      p.id,
      COUNT(ae.id) as total_events,
      COUNT(*) FILTER (WHERE ae.event = 'message_encrypted') as messages_encrypted,
      COUNT(DISTINCT ae.user_id) as unique_users
    FROM projects p
    LEFT JOIN analytics_events ae ON p.id = ae.project_id
    GROUP BY p.id, p.name
    ORDER BY total_events DESC
    LIMIT $1
  `, [limit]);

  return rows;
}

export async function getGeographicStats() {
  if (!isDbAvailable) {
    return [];
  }

  // Simplified geographic stats based on IP (you'd need IP geolocation service)
  const { rows } = await pool.query(`
    SELECT 
      'Unknown' as country,
      COUNT(*) as message_count
    FROM analytics_events
    WHERE event IN ('message_encrypted', 'message_decrypted')
    GROUP BY ip_address
    ORDER BY message_count DESC
    LIMIT 10
  `);

  return rows;
}

export async function getSdkVersionStats() {
  if (!isDbAvailable) {
    return [];
  }

  const { rows } = await pool.query(`
    SELECT 
      sdk_version,
      COUNT(*) as usage_count,
      COUNT(DISTINCT project_id) as projects_count
    FROM analytics_events
    WHERE sdk_version IS NOT NULL AND sdk_version != 'unknown'
    GROUP BY sdk_version
    ORDER BY usage_count DESC
  `);

  return rows;
}

export async function getProjectAnalytics(projectId: string) {
  if (!isDbAvailable) {
    return null;
  }

  const { rows } = await pool.query(`
    SELECT 
      COUNT(*) FILTER (WHERE event = 'message_encrypted') as messages_encrypted,
      COUNT(*) FILTER (WHERE event = 'message_decrypted') as messages_decrypted,
      COUNT(DISTINCT user_id) as unique_users,
      COUNT(DISTINCT session_id) as unique_sessions,
      SUM(message_size) as total_bytes,
      MIN(created_at) as first_activity,
      MAX(created_at) as last_activity
    FROM analytics_events
    WHERE project_id = $1
  `, [projectId]);

  return rows[0];
}

export async function getRealtimeStats() {
  if (!isDbAvailable) {
    return { active_now: 0, messages_last_hour: 0 };
  }

  const { rows } = await pool.query(`
    SELECT 
      COUNT(DISTINCT session_id) FILTER (WHERE created_at >= NOW() - INTERVAL '5 minutes') as active_now,
      COUNT(*) FILTER (WHERE event IN ('message_encrypted', 'message_decrypted') AND created_at >= NOW() - INTERVAL '1 hour') as messages_last_hour
    FROM analytics_events
  `);

  return rows[0] || { active_now: 0, messages_last_hour: 0 };
}

export async function verifyProjectAccess(projectId: string, token: string): Promise<boolean> {
  if (!isDbAvailable) {
    return true; // Allow access in development mode
  }

  const { rows } = await pool.query(`
    SELECT 1 FROM app_tokens at
    JOIN projects p ON p.id = at.project_id
    WHERE p.id = $1 AND at.token = $2
  `, [projectId, token]);

  return rows.length > 0;
}

export async function getLimits(token: string) {
  if (!isDbAvailable) {
    // Fallback: return mock data for development
    return {
      plan: 'free',
      limit: 1000,
      reset_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    };
  }
  const { rows } = await pool.query(
    `SELECT plan, monthly_message_limit AS limit, reset_at
     FROM app_tokens
     WHERE token = $1`,
    [token]
  );
  return rows[0] || null;
}

// Project operations
export async function createProject(name: string) {
  const { rows } = await pool.query(
    `INSERT INTO projects (name) VALUES ($1) RETURNING id, name, created_at`,
    [name]
  );
  return rows[0];
}

export async function getProject(id: number) {
  const { rows } = await pool.query(
    `SELECT id, name, created_at FROM projects WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

// Reset monthly quotas (run via cron job)
export async function resetMonthlyQuotas() {
  await pool.query(
    `UPDATE app_tokens
     SET used_messages = 0, reset_at = DATE_TRUNC('month', NOW()) + INTERVAL '1 month'
     WHERE reset_at <= NOW()`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// METRICS OPERATIONS (Backend verification)
// ═══════════════════════════════════════════════════════════════════════════

export async function getProjectByToken(appToken: string) {
  try {
    const { rows } = await pool.query(
      `SELECT p.id, p.name FROM projects p
       JOIN app_tokens t ON p.id = t.project_id
       WHERE t.token = $1 LIMIT 1`,
      [appToken]
    );
    return rows[0] || null;
  } catch (error) {
    console.error('[DB] getProjectByToken error:', error);
    return null;
  }
}

export async function insertVerifiedMetrics(verified: any) {
  try {
    const { rows } = await pool.query(
      `INSERT INTO verified_metrics 
       (project_id, session_id, metrics, sequence_number, attestation_id, 
        attestation_timestamp, verified_at, proof)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [
        verified.projectId,
        verified.sessionId,
        JSON.stringify(verified.metrics),
        verified.sequenceNumber,
        verified.attestationId || verified.sessionId + '_' + verified.sequenceNumber,
        verified.timestamp,
        verified.verifiedAt,
        verified.proof,
      ]
    );
    return rows[0];
  } catch (error) {
    console.error('[DB] insertVerifiedMetrics error:', error);
    throw error;
  }
}

export async function getLatestVerifiedMetrics(projectId: string) {
  try {
    const { rows } = await pool.query(
      `SELECT project_id, session_id, metrics, sequence_number, attestation_id,
              attestation_timestamp, verified_at
       FROM verified_metrics
       WHERE project_id = $1
       ORDER BY sequence_number DESC
       LIMIT 1`,
      [projectId]
    );
    if (!rows[0]) return null;
    
    return {
      projectId: rows[0].project_id,
      sessionId: rows[0].session_id,
      metrics: JSON.parse(rows[0].metrics),
      sequenceNumber: rows[0].sequence_number,
      attestationId: rows[0].attestation_id,
      timestamp: rows[0].attestation_timestamp,
      verifiedAt: rows[0].verified_at,
    };
  } catch (error) {
    console.error('[DB] getLatestVerifiedMetrics error:', error);
    return null;
  }
}

export async function insertAuditLog(log: any) {
  try {
    await pool.query(
      `INSERT INTO metrics_audit_log 
       (project_id, session_id, attestation_id, event_type, reason)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        log.projectId,
        log.sessionId || null,
        log.attestationId || null,
        log.event || log.eventType || 'unknown',
        log.reason || null,
      ]
    );
  } catch (error) {
    console.error('[DB] insertAuditLog error:', error);
  }
}

export async function getMetricsAuditLog(projectId: string, limit: number = 100) {
  try {
    const { rows } = await pool.query(
      `SELECT id, project_id, session_id, attestation_id, event_type, reason, created_at
       FROM metrics_audit_log
       WHERE project_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [projectId, limit]
    );
    return rows;
  } catch (error) {
    console.error('[DB] getMetricsAuditLog error:', error);
    return [];
  }
}

export async function verifyAdminAccess(projectId: string, token: string): Promise<boolean> {
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
