CREATE TABLE IF NOT EXISTS crowdstrike_integrations (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_name VARCHAR(255) NOT NULL,
    cloud_region VARCHAR(20) NOT NULL,
    client_id_encrypted TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    import_external_assets BOOLEAN NOT NULL DEFAULT TRUE,
    import_hosts BOOLEAN NOT NULL DEFAULT TRUE,
    import_spotlight BOOLEAN NOT NULL DEFAULT TRUE,
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
    CONSTRAINT uq_crowdstrike_org_connection UNIQUE (organization_id, connection_name)
);

CREATE INDEX IF NOT EXISTS ix_crowdstrike_integrations_organization_id ON crowdstrike_integrations (organization_id);

CREATE TABLE IF NOT EXISTS crowdstrike_asset_links (
    id SERIAL PRIMARY KEY,
    integration_id INTEGER NOT NULL REFERENCES crowdstrike_integrations(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source_kind VARCHAR(20) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    cid VARCHAR(100),
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_crowdstrike_source_link UNIQUE (integration_id, source_kind, source_id)
);

CREATE INDEX IF NOT EXISTS ix_crowdstrike_asset_links_integration_id ON crowdstrike_asset_links (integration_id);
CREATE INDEX IF NOT EXISTS ix_crowdstrike_asset_links_asset_id ON crowdstrike_asset_links (asset_id);
