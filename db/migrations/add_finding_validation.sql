-- Migration: Finding validation + detection-logic feedback
-- Adds:
--   * finding_validations   — one row per Aegis Vanguard validator-agent run on a finding
--   * detection_feedback     — template_id-keyed log of incorrect detection logic
--   * vulnerabilities.validation_status / last_validation_verdict / last_validated_at
--
-- Enum-backed columns are created as VARCHAR here so this migration is safe to
-- run by hand on existing databases (fresh databases get their schema from
-- SQLAlchemy Base.metadata.create_all in backend/app/main.py).

-- ── finding_validations ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS finding_validations (
    id                    SERIAL PRIMARY KEY,
    vulnerability_id      INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    organization_id       INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Enum-backed columns store the SQLAlchemy Enum member NAME (e.g. 'QUEUED').
    status                VARCHAR(20) NOT NULL DEFAULT 'QUEUED',
    verdict               VARCHAR(30),
    confidence            VARCHAR(20),
    recommended_severity  VARCHAR(20),
    reasoning             TEXT,
    evidence              TEXT,
    template_logic_issue  TEXT,
    error                 VARCHAR(255),
    raw_output            JSONB DEFAULT '{}'::jsonb,
    requested_by_user_id  INTEGER REFERENCES users(id),
    created_at            TIMESTAMP DEFAULT NOW(),
    started_at            TIMESTAMP,
    completed_at          TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_finding_validations_vuln
    ON finding_validations (vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_finding_validations_org
    ON finding_validations (organization_id);
CREATE INDEX IF NOT EXISTS idx_finding_validations_status
    ON finding_validations (status);
CREATE INDEX IF NOT EXISTS idx_finding_validations_verdict
    ON finding_validations (verdict);
CREATE INDEX IF NOT EXISTS idx_finding_validations_created_at
    ON finding_validations (created_at);

-- ── detection_feedback ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS detection_feedback (
    id                        SERIAL PRIMARY KEY,
    organization_id           INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    template_id               VARCHAR(255) NOT NULL,
    detected_by               VARCHAR(100),
    verdict                   VARCHAR(50),
    logic_issue               TEXT NOT NULL,
    upstream_report           TEXT,
    example_vulnerability_id  INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    finding_validation_id     INTEGER REFERENCES finding_validations(id) ON DELETE SET NULL,
    source                    VARCHAR(30) DEFAULT 'validator_agent',
    reported_by_user_id       INTEGER REFERENCES users(id),
    created_at                TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_detection_feedback_org
    ON detection_feedback (organization_id);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_template
    ON detection_feedback (template_id);
CREATE INDEX IF NOT EXISTS idx_detection_feedback_created_at
    ON detection_feedback (created_at);

-- ── vulnerabilities: denormalized validation columns ────────────────────────
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS validation_status VARCHAR(20);
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS last_validation_verdict VARCHAR(30);
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_validation_status
    ON vulnerabilities (validation_status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_last_validation_verdict
    ON vulnerabilities (last_validation_verdict);

DO $$
BEGIN
    RAISE NOTICE 'Finding validation + detection feedback schema added successfully!';
END $$;
