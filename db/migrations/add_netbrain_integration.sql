CREATE TABLE IF NOT EXISTS netbrain_integrations (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    base_url VARCHAR(500) NOT NULL,
    username_encrypted TEXT NOT NULL,
    password_encrypted TEXT NOT NULL,
    authentication_id VARCHAR(255),
    tenant_id VARCHAR(128) NOT NULL,
    domain_id VARCHAR(128) NOT NULL,
    verify_ssl BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    continuous_sync_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 360,
    max_config_age_hours INTEGER NOT NULL DEFAULT 24,
    auto_mitigate_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_tested_at TIMESTAMP,
    last_test_ok BOOLEAN,
    last_sync_at TIMESTAMP,
    last_sync_ok BOOLEAN,
    last_sync_stats JSON DEFAULT '{}'::json,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_netbrain_org_name UNIQUE (organization_id, name)
);

CREATE INDEX IF NOT EXISTS ix_netbrain_integrations_organization_id
    ON netbrain_integrations (organization_id);
