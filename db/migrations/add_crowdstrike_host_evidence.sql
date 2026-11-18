-- Falcon host evidence switches (backend/app/services/falcon_host_evidence.py).
-- Both default off: nothing is collected until an admin enables it.
ALTER TABLE crowdstrike_integrations ADD COLUMN IF NOT EXISTS collect_host_evidence BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE crowdstrike_integrations ADD COLUMN IF NOT EXISTS host_evidence_rtr BOOLEAN NOT NULL DEFAULT FALSE;
