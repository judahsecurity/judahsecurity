-- NetBrain calculated route evidence. Application startup also creates this table.
CREATE TABLE IF NOT EXISTS netbrain_paths (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    integration_id INTEGER REFERENCES netbrain_integrations(id) ON DELETE SET NULL,
    source_integration_id INTEGER NOT NULL,
    task_id VARCHAR(128) NOT NULL,
    source_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source_ip VARCHAR(45) NOT NULL,
    target_ip VARCHAR(45) NOT NULL,
    source_scope_id VARCHAR(255) NOT NULL,
    target_scope_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    domain_id VARCHAR(128) NOT NULL,
    gateway_ip VARCHAR(45) NOT NULL,
    gateway_device VARCHAR(255) NOT NULL,
    gateway_interface VARCHAR(255) NOT NULL,
    protocol INTEGER NOT NULL,
    destination_port INTEGER NOT NULL DEFAULT 0,
    is_live BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    hop_list JSON NOT NULL DEFAULT '[]',
    error VARCHAR(500),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    graph_projected_at TIMESTAMP,
    CONSTRAINT uq_netbrain_path_task UNIQUE (integration_id, task_id)
);
CREATE INDEX IF NOT EXISTS ix_netbrain_paths_organization_id ON netbrain_paths(organization_id);
CREATE INDEX IF NOT EXISTS ix_netbrain_paths_integration_id ON netbrain_paths(integration_id);
CREATE INDEX IF NOT EXISTS ix_netbrain_paths_source_asset_id ON netbrain_paths(source_asset_id);
CREATE INDEX IF NOT EXISTS ix_netbrain_paths_target_asset_id ON netbrain_paths(target_asset_id);
