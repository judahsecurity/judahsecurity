-- Bitbucket Cloud source-code integration.
-- The backend also creates this table via create_all and adds the enum label
-- on startup; this file is for manually-managed databases.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON e.enumtypid = t.oid
        WHERE t.typname = 'assettype'
          AND e.enumlabel = 'REPOSITORY'
    ) THEN
        ALTER TYPE assettype ADD VALUE 'REPOSITORY';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS bitbucket_integrations (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace VARCHAR(100) NOT NULL,
    workspace_url VARCHAR(500) NOT NULL,
    access_token_encrypted TEXT NOT NULL,
    scan_secrets BOOLEAN NOT NULL DEFAULT TRUE,
    max_repo_size_mb INTEGER NOT NULL DEFAULT 500,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    continuous_sync_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 1440,
    last_tested_at TIMESTAMP,
    last_test_ok BOOLEAN,
    last_sync_at TIMESTAMP,
    last_sync_ok BOOLEAN,
    last_sync_stats JSON,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_bitbucket_org_workspace UNIQUE (organization_id, workspace)
);

CREATE INDEX IF NOT EXISTS ix_bitbucket_integrations_organization_id
    ON bitbucket_integrations (organization_id);
