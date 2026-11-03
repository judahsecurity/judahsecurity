-- Provider assertions and their provenance remain separate from Judah validation runs.
CREATE TABLE IF NOT EXISTS finding_source_evidence (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    source VARCHAR(50) NOT NULL,
    source_finding_id VARCHAR(255) NOT NULL,
    evidence_key VARCHAR(100) NOT NULL,
    detection_method VARCHAR(100) NOT NULL,
    basis VARCHAR(50) NOT NULL,
    source_status VARCHAR(50),
    summary TEXT,
    details JSON NOT NULL DEFAULT '{}',
    observed_at TIMESTAMP,
    first_ingested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_ingested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_finding_source_evidence UNIQUE (vulnerability_id, source, evidence_key)
);
CREATE INDEX IF NOT EXISTS ix_finding_source_evidence_organization_id ON finding_source_evidence (organization_id);
CREATE INDEX IF NOT EXISTS ix_finding_source_evidence_vulnerability_id ON finding_source_evidence (vulnerability_id);

-- Paths can be stored before every provider node has a matching Judah asset.
CREATE TABLE IF NOT EXISTS exposure_paths (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source VARCHAR(50) NOT NULL,
    source_instance_id VARCHAR(100) NOT NULL,
    source_path_id VARCHAR(255) NOT NULL,
    title VARCHAR(500),
    source_status VARCHAR(50),
    source_observed_at TIMESTAMP,
    first_ingested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_ingested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details JSON NOT NULL DEFAULT '{}',
    CONSTRAINT uq_exposure_path_source UNIQUE (organization_id, source, source_instance_id, source_path_id)
);
CREATE INDEX IF NOT EXISTS ix_exposure_paths_organization_id ON exposure_paths (organization_id);

CREATE TABLE IF NOT EXISTS exposure_path_steps (
    id SERIAL PRIMARY KEY,
    path_id INTEGER NOT NULL REFERENCES exposure_paths(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    from_source_ref VARCHAR(255),
    to_source_ref VARCHAR(255),
    from_asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    to_asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    edge_type VARCHAR(100) NOT NULL,
    source_claim TEXT,
    proof_state VARCHAR(20) NOT NULL DEFAULT 'asserted',
    evidence JSON NOT NULL DEFAULT '[]',
    observed_at TIMESTAMP,
    finding_validation_id INTEGER REFERENCES finding_validations(id) ON DELETE SET NULL,
    validated_at TIMESTAMP,
    CONSTRAINT uq_exposure_path_step_position UNIQUE (path_id, position),
    CONSTRAINT ck_exposure_path_proof_state CHECK (proof_state IN ('asserted', 'observed', 'validated', 'blocked', 'unknown'))
);
CREATE INDEX IF NOT EXISTS ix_exposure_path_steps_path_id ON exposure_path_steps (path_id);
CREATE INDEX IF NOT EXISTS ix_exposure_path_steps_from_asset_id ON exposure_path_steps (from_asset_id);
CREATE INDEX IF NOT EXISTS ix_exposure_path_steps_to_asset_id ON exposure_path_steps (to_asset_id);
CREATE INDEX IF NOT EXISTS ix_exposure_path_steps_vulnerability_id ON exposure_path_steps (vulnerability_id);
