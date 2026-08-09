-- Migration: Trickest-style workflow builder
-- Adds workflows, versions, scripts, runs, node runs, and artifacts.
-- Enum-backed columns are VARCHAR for hand-run safety on existing DBs.

CREATE TABLE IF NOT EXISTS workflows (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    kind                VARCHAR(20) NOT NULL DEFAULT 'workflow',
    latest_version_id   INTEGER,
    is_library          BOOLEAN DEFAULT FALSE,
    created_by          VARCHAR(255),
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflows_org ON workflows (organization_id);
CREATE INDEX IF NOT EXISTS idx_workflows_kind ON workflows (kind);

CREATE TABLE IF NOT EXISTS workflow_versions (
    id              SERIAL PRIMARY KEY,
    workflow_id     INTEGER NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL DEFAULT 1,
    graph           JSONB DEFAULT '{}'::jsonb,
    input_ports     JSONB DEFAULT '[]'::jsonb,
    output_ports    JSONB DEFAULT '[]'::jsonb,
    created_by      VARCHAR(255),
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_versions_wf ON workflow_versions (workflow_id);

CREATE TABLE IF NOT EXISTS workflow_scripts (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    language            VARCHAR(20) NOT NULL DEFAULT 'python',
    source              TEXT NOT NULL DEFAULT '',
    input_ports         JSONB DEFAULT '[]'::jsonb,
    output_ports        JSONB DEFAULT '[]'::jsonb,
    params_schema       JSONB DEFAULT '{}'::jsonb,
    created_by          VARCHAR(255),
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_scripts_org ON workflow_scripts (organization_id);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id                  SERIAL PRIMARY KEY,
    workflow_id         INTEGER NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    version_id          INTEGER NOT NULL REFERENCES workflow_versions(id),
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    inputs              JSONB DEFAULT '{}'::jsonb,
    continue_on_error   BOOLEAN DEFAULT FALSE,
    progress            INTEGER DEFAULT 0,
    current_step        VARCHAR(255),
    error_message       TEXT,
    started_by          VARCHAR(255),
    started_at          TIMESTAMP,
    completed_at        TIMESTAMP,
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_runs_org ON workflow_runs (organization_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_status ON workflow_runs (status);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_wf ON workflow_runs (workflow_id);

CREATE TABLE IF NOT EXISTS workflow_node_runs (
    id                  SERIAL PRIMARY KEY,
    run_id              INTEGER NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    node_id             VARCHAR(128) NOT NULL,
    node_type           VARCHAR(64) NOT NULL,
    node_label          VARCHAR(255),
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    inputs              JSONB DEFAULT '{}'::jsonb,
    outputs             JSONB DEFAULT '{}'::jsonb,
    logs                TEXT,
    error_message       TEXT,
    started_at          TIMESTAMP,
    completed_at        TIMESTAMP,
    created_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_run ON workflow_node_runs (run_id);
CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_node ON workflow_node_runs (node_id);
CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_status ON workflow_node_runs (status);

CREATE TABLE IF NOT EXISTS workflow_artifacts (
    id                  SERIAL PRIMARY KEY,
    run_id              INTEGER NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    organization_id     INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    node_id             VARCHAR(128) NOT NULL,
    port                VARCHAR(128) NOT NULL,
    path                VARCHAR(1024) NOT NULL,
    filename            VARCHAR(255),
    content_type        VARCHAR(128),
    byte_size           BIGINT DEFAULT 0,
    created_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_artifacts_run ON workflow_artifacts (run_id);
CREATE INDEX IF NOT EXISTS idx_workflow_artifacts_org ON workflow_artifacts (organization_id);
CREATE INDEX IF NOT EXISTS idx_workflow_artifacts_node ON workflow_artifacts (node_id);
