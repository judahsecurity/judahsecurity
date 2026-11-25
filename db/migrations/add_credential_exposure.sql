-- Workforce identities (ServiceNow sys_user today) and leaked-credential exposures.
-- Only scoring attributes are stored; exposures hold fingerprints, never secrets.

CREATE TABLE IF NOT EXISTS identities (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source VARCHAR(30) NOT NULL,
    source_id VARCHAR(100) NOT NULL,
    email VARCHAR(320),
    username VARCHAR(255),
    aliases JSON NOT NULL DEFAULT '[]',
    display_name VARCHAR(255),
    employee_number VARCHAR(100),
    title VARCHAR(255),
    department VARCHAR(255),
    manager_name VARCHAR(255),
    manager_source_id VARCHAR(100),
    worker_type VARCHAR(50),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_vip BOOLEAN NOT NULL DEFAULT FALSE,
    groups JSON NOT NULL DEFAULT '[]',
    is_privileged BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_factors JSON NOT NULL DEFAULT '[]',
    last_seen_in_source_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_identity_org_source_id UNIQUE (organization_id, source, source_id)
);

CREATE INDEX IF NOT EXISTS ix_identities_organization_id ON identities (organization_id);
CREATE INDEX IF NOT EXISTS ix_identities_org_email ON identities (organization_id, email);
CREATE INDEX IF NOT EXISTS ix_identities_org_risk ON identities (organization_id, risk_score);

CREATE TABLE IF NOT EXISTS identity_source_syncs (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source VARCHAR(30) NOT NULL,
    running BOOLEAN NOT NULL DEFAULT FALSE,
    last_sync_started_at TIMESTAMP,
    last_sync_at TIMESTAMP,
    last_sync_ok BOOLEAN,
    last_sync_stats JSON,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_identity_sync_org_source UNIQUE (organization_id, source)
);

CREATE INDEX IF NOT EXISTS ix_identity_source_syncs_organization_id
    ON identity_source_syncs (organization_id);

CREATE TABLE IF NOT EXISTS credential_exposures (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    identity_id INTEGER REFERENCES identities(id) ON DELETE SET NULL,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    dedup_key VARCHAR(64) NOT NULL,
    identifier VARCHAR(320) NOT NULL,
    identifier_domain VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    source_type VARCHAR(30) NOT NULL,
    source_name VARCHAR(255),
    credential_type VARCHAR(30) NOT NULL DEFAULT 'email_only',
    secret_fingerprint VARCHAR(40),
    data_classes JSON NOT NULL DEFAULT '[]',
    affected_url VARCHAR(2000),
    affected_host VARCHAR(255),
    leak_date TIMESTAMP,
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    priority_score INTEGER NOT NULL DEFAULT 0,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    score_factors JSON NOT NULL DEFAULT '[]',
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_credexp_org_dedup UNIQUE (organization_id, dedup_key)
);

CREATE INDEX IF NOT EXISTS ix_credential_exposures_organization_id ON credential_exposures (organization_id);
CREATE INDEX IF NOT EXISTS ix_credential_exposures_identity_id ON credential_exposures (identity_id);
CREATE INDEX IF NOT EXISTS ix_credential_exposures_asset_id ON credential_exposures (asset_id);
CREATE INDEX IF NOT EXISTS ix_credexp_org_priority ON credential_exposures (organization_id, priority_score);
CREATE INDEX IF NOT EXISTS ix_credexp_org_identifier ON credential_exposures (organization_id, identifier);

-- Infostealer login URLs per organization domain (Hudson Rock) and the latest
-- provider summary per domain.
CREATE TABLE IF NOT EXISTS stealer_url_exposures (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    provider VARCHAR(50) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    url VARCHAR(2000) NOT NULL,
    host VARCHAR(255),
    audience VARCHAR(20) NOT NULL,
    occurrence INTEGER NOT NULL DEFAULT 0,
    login_category VARCHAR(30),
    last_compromised_at TIMESTAMP,
    priority_score INTEGER NOT NULL DEFAULT 0,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    score_factors JSON NOT NULL DEFAULT '[]',
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_stealer_url_org UNIQUE (organization_id, provider, url, audience)
);

CREATE INDEX IF NOT EXISTS ix_stealer_url_exposures_organization_id ON stealer_url_exposures (organization_id);
CREATE INDEX IF NOT EXISTS ix_stealer_url_exposures_asset_id ON stealer_url_exposures (asset_id);
CREATE INDEX IF NOT EXISTS ix_stealer_url_exposures_host ON stealer_url_exposures (host);
CREATE INDEX IF NOT EXISTS ix_stealer_url_org_priority ON stealer_url_exposures (organization_id, priority_score);

CREATE TABLE IF NOT EXISTS stealer_domain_summaries (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    summary JSON NOT NULL DEFAULT '{}',
    fetched_at TIMESTAMP,
    CONSTRAINT uq_stealer_summary_org UNIQUE (organization_id, provider, domain)
);

CREATE INDEX IF NOT EXISTS ix_stealer_domain_summaries_organization_id
    ON stealer_domain_summaries (organization_id);

-- Harvested addresses are stored as EMAIL assets. Databases created before
-- EMAIL was added to the enum need the value.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'assettype') AND NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON e.enumtypid = t.oid
        WHERE t.typname = 'assettype'
          AND e.enumlabel = 'EMAIL'
    ) THEN
        ALTER TYPE assettype ADD VALUE 'EMAIL';
    END IF;
END $$;

-- Authorized domains for leaked-credential collection and ingest (the
-- engagement boundary). Only in-scope records are ever stored.
CREATE TABLE IF NOT EXISTS exposure_scopes (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    include_subdomains BOOLEAN NOT NULL DEFAULT TRUE,
    audience_scope VARCHAR(20) NOT NULL DEFAULT 'both',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    authorized_by VARCHAR(255),
    authorization_note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_exposure_scope_org_domain UNIQUE (organization_id, domain)
);

CREATE INDEX IF NOT EXISTS ix_exposure_scopes_organization_id ON exposure_scopes (organization_id);
CREATE INDEX IF NOT EXISTS ix_exposure_scopes_domain ON exposure_scopes (domain);
