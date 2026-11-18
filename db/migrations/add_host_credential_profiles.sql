-- Credential profiles and password-vault connections for agentless host checks
-- (backend/app/models/host_credential.py). Startup create_all also creates these.
CREATE TABLE IF NOT EXISTS host_secret_stores (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    provider VARCHAR(40) NOT NULL,
    config JSON NOT NULL DEFAULT '{}',
    secret_encrypted TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_tested_at TIMESTAMP,
    last_test_ok BOOLEAN,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_host_secret_store_org_name UNIQUE (organization_id, name)
);
CREATE INDEX IF NOT EXISTS ix_host_secret_stores_organization_id ON host_secret_stores (organization_id);

CREATE TABLE IF NOT EXISTS host_credential_profiles (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    kind VARCHAR(10) NOT NULL,
    username VARCHAR(255) NOT NULL DEFAULT '',
    secret_source VARCHAR(20) NOT NULL DEFAULT 'stored',
    secret_encrypted TEXT,
    secret_store_id INTEGER REFERENCES host_secret_stores(id) ON DELETE RESTRICT,
    secret_ref JSON NOT NULL DEFAULT '{}',
    targets JSON NOT NULL DEFAULT '[]',
    priority INTEGER NOT NULL DEFAULT 100,
    options JSON NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_tested_at TIMESTAMP,
    last_test_ok BOOLEAN,
    last_error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_host_credential_profile_org_name UNIQUE (organization_id, name)
);
CREATE INDEX IF NOT EXISTS ix_host_credential_profiles_organization_id ON host_credential_profiles (organization_id);
CREATE INDEX IF NOT EXISTS ix_host_credential_profiles_secret_store_id ON host_credential_profiles (secret_store_id);
