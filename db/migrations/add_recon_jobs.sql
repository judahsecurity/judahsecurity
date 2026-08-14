-- Dual Interceptor worker job queue (Mac + Ubuntu)
-- Safe to run multiple times.

CREATE TABLE IF NOT EXISTS recon_jobs (
    id VARCHAR(36) PRIMARY KEY,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL,
    session_id VARCHAR(128),
    url VARCHAR(2048) NOT NULL,
    scope VARCHAR(512),
    max_pages INTEGER DEFAULT 20,
    interact INTEGER DEFAULT 1,
    prefer JSONB DEFAULT '["mac","ubuntu"]'::jsonb,
    opts JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(32) DEFAULT 'queued',
    worker_kind VARCHAR(32),
    worker_id VARCHAR(128),
    claimed_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    result JSONB,
    created_by_user_id INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_recon_jobs_status ON recon_jobs(status);
CREATE INDEX IF NOT EXISTS ix_recon_jobs_session_id ON recon_jobs(session_id);
CREATE INDEX IF NOT EXISTS ix_recon_jobs_organization_id ON recon_jobs(organization_id);
CREATE INDEX IF NOT EXISTS ix_recon_jobs_created_at ON recon_jobs(created_at);

CREATE TABLE IF NOT EXISTS recon_worker_heartbeats (
    worker_id VARCHAR(128) PRIMARY KEY,
    worker_kind VARCHAR(32) NOT NULL,
    hostname VARCHAR(256),
    meta JSONB DEFAULT '{}'::jsonb,
    last_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_recon_worker_heartbeats_kind ON recon_worker_heartbeats(worker_kind);
CREATE INDEX IF NOT EXISTS ix_recon_worker_heartbeats_last_seen ON recon_worker_heartbeats(last_seen);
