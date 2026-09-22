BEGIN;

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS opes_risk_model jsonb;

COMMIT;
