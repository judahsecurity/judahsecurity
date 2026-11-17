-- Durable, append-only fact stream that wakes the planner on worker-recorded
-- facts (captures, credentials, verified findings), independent of whether the
-- model remembered to call queue_finding_followups and surviving restarts.
--
-- Thin rows: evidence bytes stay in the evidence store; these are pointers plus
-- a redacted, value-free payload. Idempotent on event_uuid and on
-- (organization_id, dedupe_key) so a worker retry or restart cannot enqueue the
-- same fact twice. A NULL consumed_at marks work the planner has not yet turned
-- into a hypothesis.
CREATE TABLE IF NOT EXISTS agent_fact_events (
    id              BIGSERIAL PRIMARY KEY,                 -- total order for consumption
    event_uuid      VARCHAR(64) NOT NULL UNIQUE,           -- idempotency across retries
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_id      VARCHAR(64) NOT NULL,
    work_id         VARCHAR(64),
    run_id          VARCHAR(64),
    kind            VARCHAR(32) NOT NULL,                  -- capture|differential|credential|verified_finding
    target          VARCHAR(512) NOT NULL DEFAULT '',
    dedupe_key      VARCHAR(128) NOT NULL,                 -- one fact -> one hypothesis
    scope           JSONB NOT NULL DEFAULT '{}'::jsonb,    -- allowed_hosts/identities for RoE re-check
    evidence_ids    JSONB NOT NULL DEFAULT '[]'::jsonb,    -- pointers into the evidence store
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,    -- redacted, value-free
    consumed_at     TIMESTAMP,                             -- planner watermark
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_fact_event_dedupe UNIQUE (organization_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS ix_agent_fact_events_session
    ON agent_fact_events (session_id, id);
CREATE INDEX IF NOT EXISTS ix_agent_fact_events_unconsumed
    ON agent_fact_events (session_id, id) WHERE consumed_at IS NULL;
