-- Migration: durable traffic recording + finding traffic bindings
-- Fresh databases get these tables from SQLAlchemy create_all at backend
-- startup; this file is for manual deployment paths.

CREATE TABLE IF NOT EXISTS traffic_exchanges (
    id                SERIAL PRIMARY KEY,
    organization_id   INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source            VARCHAR(20) NOT NULL DEFAULT 'agent',
    session_id        VARCHAR(64),
    artifact_id       VARCHAR(32),
    hypothesis_id     VARCHAR(64),
    identity          VARCHAR(64),
    capture_id        VARCHAR(64),
    page_url          TEXT,
    agent_key_id      INTEGER,
    method            VARCHAR(16) NOT NULL,
    url               TEXT NOT NULL,
    host              VARCHAR(255) NOT NULL,
    path              TEXT,
    status_code       INTEGER,
    request_headers   JSON DEFAULT '{}'::json,
    request_body      TEXT,
    response_headers  JSON DEFAULT '{}'::json,
    response_body     TEXT,
    response_length   INTEGER,
    elapsed_ms        INTEGER,
    truncated         INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_organization_id ON traffic_exchanges (organization_id);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_source ON traffic_exchanges (source);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_session_id ON traffic_exchanges (session_id);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_artifact_id ON traffic_exchanges (artifact_id);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_capture_id ON traffic_exchanges (capture_id);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_host ON traffic_exchanges (host);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_status_code ON traffic_exchanges (status_code);
CREATE INDEX IF NOT EXISTS ix_traffic_exchanges_created_at ON traffic_exchanges (created_at);
CREATE INDEX IF NOT EXISTS ix_traffic_org_host_created ON traffic_exchanges (organization_id, host, created_at);
CREATE INDEX IF NOT EXISTS ix_traffic_org_artifact ON traffic_exchanges (organization_id, artifact_id);

CREATE TABLE IF NOT EXISTS vulnerability_traffic_refs (
    id                SERIAL PRIMARY KEY,
    vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    organization_id   INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    traffic_id        INTEGER REFERENCES traffic_exchanges(id) ON DELETE CASCADE,
    artifact_id       VARCHAR(32),
    position          INTEGER NOT NULL DEFAULT 0,
    note              VARCHAR(500),
    bound_by          VARCHAR(20) NOT NULL DEFAULT 'agent',
    bound_by_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_vulnerability_traffic_refs_vulnerability_id ON vulnerability_traffic_refs (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_vulnerability_traffic_refs_organization_id ON vulnerability_traffic_refs (organization_id);
