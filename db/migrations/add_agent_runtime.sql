-- Durable agent runtime, governed skills, and notification delivery.

CREATE TABLE IF NOT EXISTS agent_runs (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE NOT NULL,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    mode VARCHAR(20) NOT NULL DEFAULT 'assist',
    objective TEXT,
    current_phase VARCHAR(64),
    current_step VARCHAR(255),
    iteration_count INTEGER NOT NULL DEFAULT 0,
    progress INTEGER NOT NULL DEFAULT 0,
    price_limit_usd DOUBLE PRECISION,
    cost_usd DOUBLE PRECISION,
    worker_id VARCHAR(255),
    lease_expires_at TIMESTAMP,
    heartbeat_at TIMESTAMP,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_agent_runs_org_status_updated
    ON agent_runs (organization_id, status, updated_at);

CREATE TABLE IF NOT EXISTS agent_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    run_id VARCHAR(64) NOT NULL REFERENCES agent_runs(session_id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    event_type VARCHAR(64) NOT NULL,
    agent_id VARCHAR(128),
    step_id VARCHAR(128),
    severity VARCHAR(32),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_agent_events_run_created ON agent_events (run_id, created_at);
CREATE INDEX IF NOT EXISTS ix_agent_events_org_type ON agent_events (organization_id, event_type);

CREATE TABLE IF NOT EXISTS agent_commands (
    id BIGSERIAL PRIMARY KEY,
    command_id VARCHAR(64) UNIQUE NOT NULL,
    run_id VARCHAR(64) NOT NULL REFERENCES agent_runs(session_id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    command_type VARCHAR(32) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    issued_by VARCHAR(64),
    claimed_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_at TIMESTAMP,
    completed_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_agent_commands_run_status
    ON agent_commands (run_id, status, created_at);

CREATE TABLE IF NOT EXISTS agent_checkpoints (
    run_id VARCHAR(64) PRIMARY KEY REFERENCES agent_runs(session_id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    state_digest VARCHAR(64) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_skill_versions (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    skill_id VARCHAR(64) NOT NULL,
    version VARCHAR(64) NOT NULL,
    manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    content_hash VARCHAR(64) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by VARCHAR(64),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agent_skill_version UNIQUE (organization_id, skill_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_skill_global_version
    ON agent_skill_versions (skill_id, version) WHERE organization_id IS NULL;

CREATE TABLE IF NOT EXISTS agent_notification_endpoints (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    config_ref VARCHAR(255) NOT NULL,
    event_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    minimum_severity VARCHAR(32),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agent_notification_endpoint_name UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS agent_notification_deliveries (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES agent_notification_endpoints(id) ON DELETE CASCADE,
    event_id VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agent_notification_delivery UNIQUE (endpoint_id, event_id)
);
