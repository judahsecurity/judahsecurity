-- AI-written fix pull requests for independently verified findings.
CREATE TABLE IF NOT EXISTS fix_requests (
    id VARCHAR(32) PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),
    created_by_user_id INTEGER REFERENCES users(id),
    repository VARCHAR(200) NOT NULL,
    base_branch VARCHAR(200) NOT NULL DEFAULT '',
    branch VARCHAR(200) NOT NULL DEFAULT '',
    pr_number INTEGER,
    pr_url VARCHAR(500),
    status VARCHAR(30) NOT NULL DEFAULT 'pr_open',
    files JSON DEFAULT '[]'::json,
    summary TEXT,
    preview_origin VARCHAR(300),
    verification JSON DEFAULT '{}'::json,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_fix_requests_organization_id ON fix_requests (organization_id);
CREATE INDEX IF NOT EXISTS ix_fix_requests_vulnerability_id ON fix_requests (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_fix_requests_status ON fix_requests (status);
