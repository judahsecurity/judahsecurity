-- Durable Nuclei provenance for the CVE exploitation timeline.
ALTER TABLE custom_nuclei_templates
    ADD COLUMN IF NOT EXISTS content_digest VARCHAR(64);
ALTER TABLE custom_nuclei_templates
    ADD COLUMN IF NOT EXISTS released_at TIMESTAMP;
ALTER TABLE custom_nuclei_templates
    ADD COLUMN IF NOT EXISTS enabled_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS ix_custom_nuclei_templates_released_at
    ON custom_nuclei_templates (released_at);
CREATE INDEX IF NOT EXISTS ix_custom_nuclei_templates_enabled_at
    ON custom_nuclei_templates (enabled_at);
