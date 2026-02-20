-- Analytics Schema - SDK Usage Tracking
-- Migration: 003_analytics_schema.sql

CREATE TABLE IF NOT EXISTS analytics_events (
    id BIGSERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    event VARCHAR(50) NOT NULL,
    user_id VARCHAR(255),
    session_id VARCHAR(100),
    message_size INTEGER DEFAULT 0,
    user_agent TEXT,
    sdk_version VARCHAR(20),
    ip_address INET,
    timestamp BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_analytics_events_project_id ON analytics_events(project_id);
CREATE INDEX idx_analytics_events_timestamp ON analytics_events(timestamp);
CREATE INDEX idx_analytics_events_event ON analytics_events(event);
CREATE INDEX idx_analytics_events_session ON analytics_events(session_id);

-- Aggregated stats for performance
CREATE TABLE IF NOT EXISTS analytics_daily_stats (
    id BIGSERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    date DATE NOT NULL,
    messages_encrypted INTEGER DEFAULT 0,
    messages_decrypted INTEGER DEFAULT 0,
    active_users INTEGER DEFAULT 0,
    total_bytes_encrypted BIGINT DEFAULT 0,
    unique_sessions INTEGER DEFAULT 0,
    sdk_versions JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(project_id, date)
);

CREATE INDEX idx_daily_stats_project_date ON analytics_daily_stats(project_id, date);

-- SDK version tracking
CREATE TABLE IF NOT EXISTS sdk_versions (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) UNIQUE NOT NULL,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW()
);

-- Geographic stats (approximate)
CREATE TABLE IF NOT EXISTS analytics_geographic (
    id BIGSERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    country_code CHAR(2),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    message_count INTEGER DEFAULT 1,
    last_activity TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_analytics_geo_project ON analytics_geographic(project_id);
CREATE INDEX idx_analytics_geo_country ON analytics_geographic(country_code);

-- Real-time activity tracking
CREATE TABLE IF NOT EXISTS realtime_activity (
    id BIGSERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id),
    activity_type VARCHAR(50) NOT NULL,
    count INTEGER DEFAULT 1,
    window_start TIMESTAMP NOT NULL,
    window_end TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_realtime_project_time ON realtime_activity(project_id, window_start);

-- Popular insert function for analytics events
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
    INSERT INTO analytics_daily_stats (project_id, date, messages_encrypted, active_users, unique_sessions, total_bytes_encrypted)
    VALUES (
        p_project_id, 
        CURRENT_DATE, 
        CASE WHEN p_event = 'message_encrypted' THEN 1 ELSE 0 END,
        1,
        1,
        COALESCE(p_message_size, 0)
    )
    ON CONFLICT (project_id, date) DO UPDATE SET
        messages_encrypted = analytics_daily_stats.messages_encrypted + CASE WHEN p_event = 'message_encrypted' THEN 1 ELSE 0 END,
        messages_decrypted = analytics_daily_stats.messages_decrypted + CASE WHEN p_event = 'message_decrypted' THEN 1 ELSE 0 END,
        total_bytes_encrypted = analytics_daily_stats.total_bytes_encrypted + COALESCE(p_message_size, 0);
END;
$$ LANGUAGE plpgsql;