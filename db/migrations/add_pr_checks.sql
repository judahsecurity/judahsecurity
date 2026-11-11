-- Pull-request security checks (source analysis + Prowl live handoff).
CREATE TABLE IF NOT EXISTS pr_checks (
    id VARCHAR(32) PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    asset_id INTEGER REFERENCES assets(id),
    agent_key_id VARCHAR(32),
    repository VARCHAR(200) NOT NULL DEFAULT '',
    pull_request INTEGER,
    head_sha VARCHAR(64) NOT NULL DEFAULT '',
    base_sha VARCHAR(64) NOT NULL DEFAULT '',
    conclusion VARCHAR(20) NOT NULL DEFAULT 'neutral',
    fail_on VARCHAR(20) NOT NULL DEFAULT 'medium',
    findings JSON DEFAULT '[]'::json,
    routes JSON DEFAULT '[]'::json,
    summary JSON DEFAULT '{}'::json,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_pr_checks_organization_id ON pr_checks (organization_id);
CREATE INDEX IF NOT EXISTS ix_pr_checks_asset_id ON pr_checks (asset_id);
CREATE INDEX IF NOT EXISTS ix_pr_checks_created_at ON pr_checks (created_at);
