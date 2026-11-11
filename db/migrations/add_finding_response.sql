-- Vulnerability response: triage gate, SLA tracking, owner notices, event log/outbox.
-- Created automatically at startup by Base.metadata.create_all; kept here for manual deploys.

CREATE TABLE IF NOT EXISTS finding_responses (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vulnerability_id INTEGER NOT NULL UNIQUE REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    triage_status VARCHAR(20) NOT NULL DEFAULT 'pending_triage',
    triaged_by VARCHAR(255),
    triaged_at TIMESTAMP,
    triage_note TEXT,
    sla_tier VARCHAR(20),
    internet_accessible BOOLEAN,
    sla_days INTEGER,
    sla_started_at TIMESTAMP,
    sla_due_at TIMESTAMP,
    sla_breached BOOLEAN NOT NULL DEFAULT FALSE,
    reminders_sent JSON,
    owner_email VARCHAR(320),
    owner_team VARCHAR(255),
    finding_type VARCHAR(100),
    notified_at TIMESTAMP,
    notified_via VARCHAR(50),
    ticket_key VARCHAR(100),
    ticket_url VARCHAR(1000),
    closed_out_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_finding_responses_organization_id ON finding_responses (organization_id);
CREATE INDEX IF NOT EXISTS ix_finding_responses_triage_status ON finding_responses (triage_status);
CREATE INDEX IF NOT EXISTS ix_finding_responses_sla_tier ON finding_responses (sla_tier);
CREATE INDEX IF NOT EXISTS ix_finding_responses_sla_due_at ON finding_responses (sla_due_at);
CREATE INDEX IF NOT EXISTS ix_finding_responses_sla_breached ON finding_responses (sla_breached);

CREATE TABLE IF NOT EXISTS finding_events (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    action VARCHAR(50),
    executor VARCHAR(20),
    status VARCHAR(20) NOT NULL DEFAULT 'recorded',
    actor VARCHAR(255),
    payload JSON,
    result JSON,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_attempt_at TIMESTAMP,
    delivered_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_finding_events_organization_id ON finding_events (organization_id);
CREATE INDEX IF NOT EXISTS ix_finding_events_vulnerability_id ON finding_events (vulnerability_id);
CREATE INDEX IF NOT EXISTS ix_finding_events_event_type ON finding_events (event_type);
CREATE INDEX IF NOT EXISTS ix_finding_events_action ON finding_events (action);
CREATE INDEX IF NOT EXISTS ix_finding_events_status ON finding_events (status);
CREATE INDEX IF NOT EXISTS ix_finding_events_next_attempt_at ON finding_events (next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_finding_events_created_at ON finding_events (created_at);
