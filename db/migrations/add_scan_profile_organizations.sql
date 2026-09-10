-- Tenant ownership for reusable scan profiles. Safe to run repeatedly.

ALTER TABLE scan_profiles
    ADD COLUMN IF NOT EXISTS organization_id INTEGER
    REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE scan_profiles
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(100);

-- Replace the legacy global name constraint with scope-aware uniqueness.
ALTER TABLE scan_profiles DROP CONSTRAINT IF EXISTS scan_profiles_name_key;
DROP INDEX IF EXISTS ix_scan_profiles_name;

CREATE INDEX IF NOT EXISTS ix_scan_profiles_name_lookup ON scan_profiles(name);
CREATE INDEX IF NOT EXISTS ix_scan_profiles_organization_id ON scan_profiles(organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_profiles_builtin_name
    ON scan_profiles (LOWER(name)) WHERE organization_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_profiles_org_name
    ON scan_profiles (organization_id, LOWER(name)) WHERE organization_id IS NOT NULL;
