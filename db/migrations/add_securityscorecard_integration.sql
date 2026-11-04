CREATE TABLE IF NOT EXISTS securityscorecard_integrations (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_name VARCHAR(255) NOT NULL,
    api_key_encrypted TEXT NOT NULL,
    import_assets BOOLEAN NOT NULL DEFAULT TRUE,
    import_vulnerabilities BOOLEAN NOT NULL DEFAULT TRUE,
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
    CONSTRAINT uq_securityscorecard_org_connection UNIQUE (organization_id, connection_name)
);

CREATE INDEX IF NOT EXISTS ix_securityscorecard_integrations_organization_id
    ON securityscorecard_integrations (organization_id);
