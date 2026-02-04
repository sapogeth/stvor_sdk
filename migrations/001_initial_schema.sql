-- PostgreSQL Schema for STVOR

-- Projects Table
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- App Tokens Table (for quotas/freemium)
CREATE TABLE IF NOT EXISTS app_tokens (
    token VARCHAR(64) PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    plan VARCHAR(20) CHECK (plan IN ('free', 'starter', 'unlimited')) DEFAULT 'free',
    used_messages INTEGER DEFAULT 0,
    monthly_message_limit INTEGER DEFAULT 1000,
    reset_at TIMESTAMP DEFAULT DATE_TRUNC('month', NOW()) + INTERVAL '1 month',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, username)
);

-- Identity Keys Table
CREATE TABLE IF NOT EXISTS identity_keys (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    private_key BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
);

-- Fingerprints Table
CREATE TABLE IF NOT EXISTS fingerprints (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
);

-- Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    peer_id INT REFERENCES users(id) ON DELETE CASCADE,
    root_key BYTEA NOT NULL,
    chain_key BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Message Deliveries Table (for tracking usage)
CREATE TABLE IF NOT EXISTS message_deliveries (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(64) NOT NULL,
    app_token VARCHAR(64) REFERENCES app_tokens(token) ON DELETE CASCADE,
    delivered_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(message_id, app_token)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_app_tokens_project ON app_tokens(project_id);
CREATE INDEX IF NOT EXISTS idx_users_project ON users(project_id);
CREATE INDEX IF NOT EXISTS idx_message_deliveries_token ON message_deliveries(app_token);