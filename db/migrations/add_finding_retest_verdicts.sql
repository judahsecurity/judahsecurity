-- Retest verdicts for finding_validations.verdict.
--
-- Databases built from add_finding_validation.sql store the verdict as
-- VARCHAR and need no change. Databases whose schema came from SQLAlchemy
-- create_all have a native validationverdict enum; the backend adds these
-- labels at startup (apply_validation_verdict_migrations). This file does the
-- same by hand. Safe to re-run.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'validationverdict') THEN
        ALTER TYPE validationverdict ADD VALUE IF NOT EXISTS 'FIXED';
        ALTER TYPE validationverdict ADD VALUE IF NOT EXISTS 'INCONCLUSIVE';
    END IF;
END $$;
