-- Migration: Pattern-based detection suppression
-- Adds detection_suppression: a per-(organization, template) rollup that turns
-- repeated false-positive signals into an analyst-approvable suppression rule.
--
-- Enum-backed columns are stored as VARCHAR (SQLAlchemy persists the enum member
-- NAME, e.g. 'RECOMMENDED') so this migration is safe to run by hand. Fresh
-- databases get their schema from SQLAlchemy Base.metadata.create_all.

CREATE TABLE IF NOT EXISTS detection_suppression (
    id                    SERIAL PRIMARY KEY,
    organization_id       INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    template_id           VARCHAR(255) NOT NULL,
    detected_by           VARCHAR(100),
    status                VARCHAR(20) NOT NULL DEFAULT 'RECOMMENDED',
    host_count            INTEGER DEFAULT 0,
    threshold             INTEGER DEFAULT 0,
    signal_breakdown      JSONB DEFAULT '{}'::jsonb,
    first_flagged_at      TIMESTAMP DEFAULT NOW(),
    last_evaluated_at     TIMESTAMP DEFAULT NOW(),
    approved_by_user_id   INTEGER REFERENCES users(id),
    approved_at           TIMESTAMP,
    dismissed_by_user_id  INTEGER REFERENCES users(id),
    dismissed_at          TIMESTAMP,
    created_at            TIMESTAMP DEFAULT NOW(),
    updated_at            TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_detection_suppression_org_template UNIQUE (organization_id, template_id)
);

CREATE INDEX IF NOT EXISTS idx_detection_suppression_org
    ON detection_suppression (organization_id);
CREATE INDEX IF NOT EXISTS idx_detection_suppression_template
    ON detection_suppression (template_id);
CREATE INDEX IF NOT EXISTS idx_detection_suppression_status
    ON detection_suppression (status);

DO $$
BEGIN
    RAISE NOTICE 'Detection suppression schema added successfully!';
END $$;
