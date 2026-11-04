-- Source code manager integrations (Azure DevOps repository discovery + secret scanning).
-- Applied automatically by SQLAlchemy create_all; kept here for manual deployments.

ALTER TYPE assettype ADD VALUE IF NOT EXISTS 'REPOSITORY';

CREATE TABLE IF NOT EXISTS scm_integrations (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL DEFAULT 'azure_devops',
    connection_name VARCHAR(255) NOT NULL,
    scope_url VARCHAR(1000) NOT NULL,
    scm_organization VARCHAR(255) NOT NULL,
    scm_project VARCHAR(255),
    auth_method VARCHAR(32) NOT NULL DEFAULT 'pat',
    access_token_encrypted TEXT,
    tenant_id VARCHAR(255),
    client_id VARCHAR(255),
    client_secret_encrypted TEXT,
    secret_scanning_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    include_unverified_secrets BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    continuous_sync_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 1440,
    last_tested_at TIMESTAMP,
    last_test_ok BOOLEAN,
    last_sync_at TIMESTAMP,
    last_sync_ok BOOLEAN,
    last_sync_stats JSON,
    last_scan_id INTEGER,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_scm_org_provider_connection UNIQUE (organization_id, provider, connection_name)
);

CREATE INDEX IF NOT EXISTS ix_scm_integrations_organization_id ON scm_integrations (organization_id);
CREATE INDEX IF NOT EXISTS ix_scm_integrations_provider ON scm_integrations (provider);
