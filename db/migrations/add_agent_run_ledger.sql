-- Durable agent run status and append-only action receipts.
CREATE TABLE IF NOT EXISTS agent_run_ledger (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    objective TEXT NOT NULL DEFAULT '',
    mode VARCHAR(20) NOT NULL DEFAULT 'assist',
    status VARCHAR(24) NOT NULL DEFAULT 'running',
    reason TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deadline_at TIMESTAMP,
    ended_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_agent_run_ledger_session_id
    ON agent_run_ledger (session_id);

CREATE TABLE IF NOT EXISTS agent_action_receipts (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES agent_run_ledger(id) ON DELETE CASCADE,
    action_id VARCHAR(64) NOT NULL,
    event VARCHAR(24) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    target VARCHAR(512) NOT NULL DEFAULT '',
    phase VARCHAR(32) NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_agent_action_receipts_run_id
    ON agent_action_receipts (run_id);
CREATE INDEX IF NOT EXISTS ix_agent_action_receipts_action_id
    ON agent_action_receipts (action_id);

CREATE TABLE IF NOT EXISTS agent_hypothesis_coverage (
    run_id VARCHAR(64) NOT NULL REFERENCES agent_run_ledger(id) ON DELETE CASCADE,
    hypothesis_id VARCHAR(64) NOT NULL,
    title VARCHAR(240) NOT NULL DEFAULT '',
    specialist VARCHAR(64) NOT NULL DEFAULT '',
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    blocked_reason VARCHAR(300) NOT NULL DEFAULT '',
    evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (run_id, hypothesis_id)
);
