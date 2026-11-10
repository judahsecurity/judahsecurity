-- Cross-source finding identity: one canonical vulnerability, many source observations.
-- Applied automatically at startup by app.main.apply_finding_identity_migrations
-- (columns) and Base.metadata.create_all (table); kept here for manual deploys.

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cves JSON;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS dedup_key VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS port_service_id INTEGER
    REFERENCES port_services(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS ix_vulnerabilities_dedup_key ON vulnerabilities (dedup_key);
CREATE INDEX IF NOT EXISTS ix_vulnerabilities_port_service_id ON vulnerabilities (port_service_id);

CREATE TABLE IF NOT EXISTS finding_observations (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    source VARCHAR(50) NOT NULL,
    vendor_finding_id VARCHAR(255) NOT NULL,
    vendor_severity VARCHAR(50),
    state VARCHAR(20) NOT NULL DEFAULT 'open',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_finding_observation_source_id UNIQUE (organization_id, source, vendor_finding_id)
);

CREATE INDEX IF NOT EXISTS ix_finding_observations_organization_id ON finding_observations (organization_id);
CREATE INDEX IF NOT EXISTS ix_finding_observations_vulnerability_id ON finding_observations (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_finding_observations_source ON finding_observations (source);
CREATE INDEX IF NOT EXISTS ix_finding_observations_state ON finding_observations (state);
