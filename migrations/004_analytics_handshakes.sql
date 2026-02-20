-- Analytics: Add handshakes and errors columns
-- Migration: 004_analytics_handshakes.sql

ALTER TABLE analytics_daily_stats 
ADD COLUMN IF NOT EXISTS handshakes INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS errors INTEGER DEFAULT 0;

-- Update the record_analytics_event function to also update handshakes and errors
CREATE OR REPLACE FUNCTION record_analytics_event(
    p_project_id INTEGER,
    p_event VARCHAR,
    p_user_id VARCHAR,
    p_session_id VARCHAR,
    p_message_size INTEGER,
    p_user_agent TEXT,
    p_sdk_version VARCHAR,
    p_ip INET,
    p_timestamp BIGINT
) RETURNS VOID AS $$
BEGIN
    INSERT INTO analytics_events 
        (project_id, event, user_id, session_id, message_size, user_agent, sdk_version, ip_address, timestamp)
    VALUES 
        (p_project_id, p_event, p_user_id, p_session_id, p_message_size, p_user_agent, p_sdk_version, p_ip, p_timestamp);
    
    -- Update SDK version tracking
    INSERT INTO sdk_versions (version, first_seen, last_seen) 
    VALUES (p_sdk_version, NOW(), NOW())
    ON CONFLICT (version) DO UPDATE SET last_seen = NOW();
    
    -- Update daily aggregation
    INSERT INTO analytics_daily_stats (project_id, date, messages_encrypted, active_users, unique_sessions, total_bytes_encrypted, handshakes, errors)
    VALUES (
        p_project_id, 
        CURRENT_DATE, 
        CASE WHEN p_event = 'message_encrypted' THEN 1 ELSE 0 END,
        1,
        1,
        COALESCE(p_message_size, 0),
        CASE WHEN p_event = 'handshake' THEN 1 ELSE 0 END,
        CASE WHEN p_event = 'error' THEN 1 ELSE 0 END
    )
    ON CONFLICT (project_id, date) DO UPDATE SET
        messages_encrypted = analytics_daily_stats.messages_encrypted + CASE WHEN p_event = 'message_encrypted' THEN 1 ELSE 0 END,
        messages_decrypted = analytics_daily_stats.messages_decrypted + CASE WHEN p_event = 'message_decrypted' THEN 1 ELSE 0 END,
        total_bytes_encrypted = analytics_daily_stats.total_bytes_encrypted + COALESCE(p_message_size, 0),
        handshakes = analytics_daily_stats.handshakes + CASE WHEN p_event = 'handshake' THEN 1 ELSE 0 END,
        errors = analytics_daily_stats.errors + CASE WHEN p_event = 'error' THEN 1 ELSE 0 END;
END;
$$ LANGUAGE plpgsql;
