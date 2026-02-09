-- STVOR v3.0 - Metrics Verification Schema
-- 
-- This migration creates tables for backend-verified metrics
-- 
-- Trust Model:
-- - SDK (Node.js) creates attestations
-- - Backend (this schema) stores only VERIFIED metrics
-- - Dashboard reads ONLY from these tables (never generates data)

-- ═══════════════════════════════════════════════════════════════════════════
-- Verified Metrics Table
-- ═══════════════════════════════════════════════════════════════════════════
-- Stores ONLY metrics that have passed backend verification
-- - Proof is cryptographically valid
-- - Timestamp is fresh (< 5 min old)
-- - No replay (attestationId unique)
-- - Monotonic (counters never roll back)

CREATE TABLE verified_metrics (
  id SERIAL PRIMARY KEY,
  
  -- Project & session identification
  project_id VARCHAR(255) NOT NULL,
  session_id VARCHAR(255) NOT NULL,
  
  -- Metrics data (JSON to allow future expansion)
  metrics JSONB NOT NULL,
  
  -- Attestation tracking
  sequence_number BIGINT NOT NULL,
  attestation_id VARCHAR(255) NOT NULL UNIQUE,
  
  -- Timestamps
  attestation_timestamp BIGINT NOT NULL,
  verified_at BIGINT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  
  -- For audit/debugging
  proof VARCHAR(255) NOT NULL,
  
  -- INVARIANTS
  -- - (project_id, session_id, sequence_number) must be unique (no duplicates)
  -- - attestation_id must be unique (anti-replay)
  -- - Counters in metrics never decrease per (project_id, session_id)
  
  UNIQUE(project_id, session_id, sequence_number),
  UNIQUE(attestation_id)
);

-- Indexes for fast queries
CREATE INDEX idx_verified_metrics_project_session 
  ON verified_metrics(project_id, session_id);

CREATE INDEX idx_verified_metrics_project_time 
  ON verified_metrics(project_id, created_at DESC);

CREATE INDEX idx_verified_metrics_attestation_id 
  ON verified_metrics(attestation_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- Metrics Audit Log
-- ═══════════════════════════════════════════════════════════════════════════
-- Logs ALL metric attestation events:
-- - METRICS_ATTESTATION_RECEIVED: SDK sent attestation
-- - METRICS_ATTESTATION_VERIFIED: Passed all verification checks
-- - METRICS_ATTESTATION_REJECTED: Failed verification (reason logged)
-- - METRICS_VIEWED: Dashboard fetched metrics

CREATE TABLE metrics_audit_log (
  id SERIAL PRIMARY KEY,
  
  -- Identification
  project_id VARCHAR(255) NOT NULL,
  session_id VARCHAR(255),
  attestation_id VARCHAR(255),
  
  -- Event tracking
  event_type VARCHAR(100) NOT NULL,  -- e.g., 'VERIFIED', 'REJECTED'
  reason VARCHAR(500),                 -- Reason for rejection or other details
  
  -- Timestamp
  created_at TIMESTAMP DEFAULT NOW(),
  
  -- For searching specific problems
  UNIQUE(project_id, attestation_id, created_at)
);

-- Indexes for queries
CREATE INDEX idx_metrics_audit_log_project_time 
  ON metrics_audit_log(project_id, created_at DESC);

CREATE INDEX idx_metrics_audit_log_attestation 
  ON metrics_audit_log(attestation_id);

CREATE INDEX idx_metrics_audit_log_event_type 
  ON metrics_audit_log(event_type, created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════
-- DEPLOYMENT NOTES
-- ═══════════════════════════════════════════════════════════════════════════
--
-- 1. Run this migration after deploying v3.0 SDK + Backend
-- 2. No data migration needed (fresh tables)
-- 3. Verify tables exist:
--    SELECT table_name FROM information_schema.tables 
--    WHERE table_name IN ('verified_metrics', 'metrics_audit_log');
--
-- 4. Test metrics flow:
--    a) SDK records event (messagesEncrypted++)
--    b) SDK sends attestation to POST /api/metrics/attest
--    c) Backend verifies proof and stores in verified_metrics
--    d) Dashboard fetches from GET /api/metrics
--    e) Verify returned data matches SDK recording
--
-- 5. Monitor audit log for rejections:
--    SELECT event_type, COUNT(*) FROM metrics_audit_log 
--    GROUP BY event_type;
--
-- ═══════════════════════════════════════════════════════════════════════════
