-- Normalize finding scope and provenance. Safe to rerun on PostgreSQL.
-- vulnerabilities.id and asset_id remain the compatibility identity/anchor.

CREATE TABLE IF NOT EXISTS finding_targets (
    id               SERIAL PRIMARY KEY,
    organization_id  INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    asset_id         INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_key       VARCHAR(64) NOT NULL,
    port             INTEGER,
    protocol         VARCHAR(10),
    service_name     VARCHAR(100),
    url              VARCHAR(2048),
    verification     VARCHAR(20) NOT NULL DEFAULT 'reported',
    first_seen       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_finding_targets_key UNIQUE (vulnerability_id, target_key)
);
CREATE INDEX IF NOT EXISTS ix_finding_targets_vulnerability_id ON finding_targets (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_finding_targets_org_asset ON finding_targets (organization_id, asset_id);

CREATE TABLE IF NOT EXISTS finding_observations (
    id                SERIAL PRIMARY KEY,
    organization_id   INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vulnerability_id  INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    scan_id           INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    source            VARCHAR(100) NOT NULL,
    source_instance   VARCHAR(255) NOT NULL DEFAULT '',
    source_record_id  VARCHAR(500),
    source_record_key VARCHAR(64) NOT NULL,
    rule_id           VARCHAR(255),
    title             VARCHAR(500),
    severity          VARCHAR(20),
    confidence        VARCHAR(20),
    description       TEXT,
    first_seen        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    seen_count        INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT uq_finding_observations_source_record
        UNIQUE (organization_id, source, source_instance, source_record_key)
);
CREATE INDEX IF NOT EXISTS ix_finding_observations_finding_seen
    ON finding_observations (vulnerability_id, last_seen);

CREATE TABLE IF NOT EXISTS finding_observation_targets (
    observation_id INTEGER NOT NULL REFERENCES finding_observations(id) ON DELETE CASCADE,
    target_id      INTEGER NOT NULL REFERENCES finding_targets(id) ON DELETE CASCADE,
    PRIMARY KEY (observation_id, target_id)
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    id             SERIAL PRIMARY KEY,
    observation_id INTEGER NOT NULL REFERENCES finding_observations(id) ON DELETE CASCADE,
    target_id      INTEGER REFERENCES finding_targets(id) ON DELETE CASCADE,
    kind           VARCHAR(30) NOT NULL,
    value          TEXT NOT NULL,
    value_hash     VARCHAR(64) NOT NULL,
    observed_at    TIMESTAMP,
    CONSTRAINT uq_finding_evidence_item UNIQUE (observation_id, kind, value_hash)
);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_observation_id ON finding_evidence (observation_id);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_target_id ON finding_evidence (target_id);

CREATE TABLE IF NOT EXISTS finding_identifiers (
    id               SERIAL PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    kind             VARCHAR(20) NOT NULL,
    value            VARCHAR(255) NOT NULL,
    CONSTRAINT uq_finding_identifiers_value UNIQUE (vulnerability_id, kind, value)
);
CREATE INDEX IF NOT EXISTS ix_finding_identifiers_vulnerability_id ON finding_identifiers (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_finding_identifiers_kind_value ON finding_identifiers (kind, value);

-- Backfill only facts already represented by first-class legacy columns.
-- The legacy primary asset is an anchor, not proof that every IP in a
-- description is affected. Historical source records are not reconstructed.
INSERT INTO finding_targets (
    organization_id, vulnerability_id, asset_id, target_key, verification,
    first_seen, last_seen
)
SELECT a.organization_id, v.id, a.id, 'asset:' || a.id, 'reported',
       COALESCE(v.first_detected, v.created_at, CURRENT_TIMESTAMP),
       COALESCE(v.last_detected, v.created_at, CURRENT_TIMESTAMP)
FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
ON CONFLICT (vulnerability_id, target_key) DO NOTHING;

INSERT INTO finding_identifiers (vulnerability_id, kind, value)
SELECT id, 'cve', upper(cve_id) FROM vulnerabilities WHERE cve_id ~* '^CVE-[0-9]{4}-[0-9]{4,}$'
ON CONFLICT (vulnerability_id, kind, value) DO NOTHING;
INSERT INTO finding_identifiers (vulnerability_id, kind, value)
SELECT id, 'cwe', upper(cwe_id) FROM vulnerabilities WHERE cwe_id ~* '^CWE-[0-9]+$'
ON CONFLICT (vulnerability_id, kind, value) DO NOTHING;
