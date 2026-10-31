-- One durable, bounded scheduled assessment per target and schedule tick.
CREATE TABLE IF NOT EXISTS agent_autonomy_work (
    id VARCHAR(64) PRIMARY KEY,
    schedule_id INTEGER NOT NULL REFERENCES scan_schedules(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target VARCHAR(512) NOT NULL,
    session_id VARCHAR(64) NOT NULL UNIQUE,
    status VARCHAR(24) NOT NULL DEFAULT 'queued',
    prompt TEXT NOT NULL DEFAULT '',
    revisions JSONB NOT NULL DEFAULT '[]'::jsonb,
    turns INTEGER NOT NULL DEFAULT 0,
    max_turns INTEGER NOT NULL DEFAULT 3,
    price_limit_usd DOUBLE PRECISION NOT NULL DEFAULT 8,
    spent_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_total_seconds INTEGER NOT NULL DEFAULT 3600,
    limits JSONB NOT NULL DEFAULT '{}'::jsonb,
    lease_owner VARCHAR(64) NOT NULL DEFAULT '',
    lease_until TIMESTAMP,
    turn_started_at TIMESTAMP,
    stop_reason TEXT NOT NULL DEFAULT '',
    answer TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    notification_sent BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS ix_agent_autonomy_work_schedule_id ON agent_autonomy_work(schedule_id);
CREATE INDEX IF NOT EXISTS ix_agent_autonomy_work_status ON agent_autonomy_work(status);
ALTER TABLE agent_autonomy_work ADD COLUMN IF NOT EXISTS turn_started_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS agent_run_snapshots (
    session_id VARCHAR(64) PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
