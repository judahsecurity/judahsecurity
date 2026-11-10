-- User-defined, read-only Wiz GraphQL pulls and the rows they return.
-- (The backend also creates these tables on startup via Base.metadata.create_all.)

CREATE TABLE IF NOT EXISTS wiz_custom_queries (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    integration_id INTEGER NOT NULL REFERENCES wiz_integrations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    query TEXT NOT NULL,
    variables JSON,
    connection_path VARCHAR(255),
    page_size INTEGER NOT NULL DEFAULT 100,
    max_pages INTEGER NOT NULL DEFAULT 50,
    asset_host_field VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMP,
    last_run_ok BOOLEAN,
    last_run_stats JSON,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_wiz_custom_query_name UNIQUE (integration_id, name)
);

CREATE INDEX IF NOT EXISTS ix_wiz_custom_queries_organization_id ON wiz_custom_queries (organization_id);
CREATE INDEX IF NOT EXISTS ix_wiz_custom_queries_integration_id ON wiz_custom_queries (integration_id);

CREATE TABLE IF NOT EXISTS wiz_custom_query_records (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    query_id INTEGER NOT NULL REFERENCES wiz_custom_queries(id) ON DELETE CASCADE,
    external_id VARCHAR(500) NOT NULL,
    data JSON,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    is_present BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_wiz_custom_query_record UNIQUE (query_id, external_id)
);

CREATE INDEX IF NOT EXISTS ix_wiz_custom_query_records_organization_id ON wiz_custom_query_records (organization_id);
CREATE INDEX IF NOT EXISTS ix_wiz_custom_query_records_query_id ON wiz_custom_query_records (query_id);
CREATE INDEX IF NOT EXISTS ix_wiz_custom_query_records_asset_id ON wiz_custom_query_records (asset_id);
CREATE INDEX IF NOT EXISTS ix_wiz_custom_query_records_is_present ON wiz_custom_query_records (is_present);
