-- Migration: remediation retest on finding validations
-- Applied automatically at backend startup (main.py); kept for manual paths.
ALTER TABLE finding_validations ADD COLUMN IF NOT EXISTS purpose VARCHAR(20) NOT NULL DEFAULT 'validate';
ALTER TABLE finding_validations ADD COLUMN IF NOT EXISTS retest_outcome VARCHAR(30);
ALTER TABLE finding_validations ADD COLUMN IF NOT EXISTS retest_notes TEXT;
CREATE INDEX IF NOT EXISTS ix_finding_validations_purpose ON finding_validations (purpose);
