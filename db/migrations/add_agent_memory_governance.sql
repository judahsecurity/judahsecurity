ALTER TABLE agent_palace_drawers
    ADD COLUMN IF NOT EXISTS trust_level VARCHAR(32) NOT NULL DEFAULT 'observed',
    ADD COLUMN IF NOT EXISTS retention_class VARCHAR(32) NOT NULL DEFAULT 'engagement',
    ADD COLUMN IF NOT EXISTS provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP,
    ADD COLUMN IF NOT EXISTS quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS quarantine_reason VARCHAR(512),
    ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS ix_palace_trust_level ON agent_palace_drawers (trust_level);
CREATE INDEX IF NOT EXISTS ix_palace_retention_class ON agent_palace_drawers (retention_class);
CREATE INDEX IF NOT EXISTS ix_palace_expires_at ON agent_palace_drawers (expires_at);
CREATE INDEX IF NOT EXISTS ix_palace_quarantined ON agent_palace_drawers (quarantined);
