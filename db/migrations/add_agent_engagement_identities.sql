-- Operator-approved test identities for authenticated assessments.
--
-- The restart snapshot deliberately drops live credentials (see run_snapshot),
-- so a resumed run or an authz hypothesis would otherwise idle waiting for an
-- operator to re-enter working creds. This durable, org-scoped table lets an
-- operator pre-register approved identities (secret encrypted at rest with the
-- shared Fernet cipher). The autonomy turn re-hydrates them into the in-memory
-- engagement brain only when the run's limits authorize that identity label and
-- a scope host matches; the secrets are never written back into the snapshot.
CREATE TABLE IF NOT EXISTS agent_engagement_identities (
    id               SERIAL PRIMARY KEY,
    organization_id  INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    schedule_id      INTEGER REFERENCES scan_schedules(id) ON DELETE CASCADE,
    label            VARCHAR(64) NOT NULL,          -- matches an allowed_identities entry
    username         VARCHAR(256) NOT NULL DEFAULT '',
    secret_encrypted TEXT NOT NULL DEFAULT '',      -- Fernet, shared with api_configs
    secret_type      VARCHAR(32) NOT NULL DEFAULT 'password',
    valid_on         JSONB NOT NULL DEFAULT '[]'::jsonb,  -- in-scope hosts this identity is for
    login_url        VARCHAR(512) NOT NULL DEFAULT '',
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    approved_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    notes            TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_engagement_identity UNIQUE (organization_id, schedule_id, label)
);
CREATE INDEX IF NOT EXISTS ix_agent_engagement_identities_org
    ON agent_engagement_identities (organization_id);
CREATE INDEX IF NOT EXISTS ix_agent_engagement_identities_schedule
    ON agent_engagement_identities (schedule_id);
