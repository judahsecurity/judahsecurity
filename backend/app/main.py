"""Main FastAPI application entry point."""

import logging
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.rate_limit import register_rate_limiting
from app.db.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.netblock import Netblock  # Import to ensure table creation
from app.models.finding_exception import FindingException  # Required for Vulnerability relationship resolution
from app.models.jira_integration import JiraIntegration, JiraTicket  # noqa: F401 — ensure tables are created
from app.models.servicenow_integration import ServiceNowIntegration, ServiceNowDelivery  # noqa: F401 — ensure tables are created
from app.models.censys_integration import CensysAsmIntegration  # noqa: F401 — ensure table is created
from app.models.hackerone_integration import HackerOneIntegration, HackerOneReportLink  # noqa: F401 — ensure tables are created
from app.models.panorama_integration import PanoramaIntegration  # noqa: F401 — ensure table is created
from app.models.f5_integration import F5Integration  # noqa: F401 — ensure table is created
from app.models.akamai_integration import AkamaiWafIntegration  # noqa: F401 — ensure table is created
from app.models.cloudflare_integration import CloudflareWafIntegration  # noqa: F401 — ensure table is created
from app.models.vm_scanner_integration import VmScannerIntegration  # noqa: F401 — ensure table is created
from app.models.custom_nuclei_template import CustomNucleiTemplate  # noqa: F401 — ensure table is created
from app.api.routes import auth, users, organizations, assets, vulnerabilities, scans, discovery, nuclei, ports, screenshots, external_discovery, waybackurls, netblocks, labels, scan_schedules, tools, sni_discovery, scan_config, acquisitions, oracle, agent
from app.api.routes import integrations
from app.api.routes import scoring as scoring_router
from app.api.routes import threat_intel as threat_intel_router
from app.api.routes import custom_templates as custom_templates_router
from app.api.routes import remediation as remediation_router
from app.api.routes import exceptions as exceptions_router
from app.api.routes import github_secrets as github_secrets_router
from app.api.routes import agent_knowledge as agent_knowledge_router
from app.api.routes import agent_confirmations as agent_confirmations_router
from app.api.routes import agent_skills as agent_skills_router
from app.api.routes import roe as roe_router
from app.api.routes import delphi as delphi_router
from app.api.routes import ingestion as ingestion_router
from app.api.routes import graph as graph_router
from app.api.routes import reports as reports_router
from app.api.routes import pentest as pentest_router
from app.api.routes import app_structure as app_structure_router
from app.api.routes import mcp as mcp_router
from app.api.routes import mitre as mitre_router
from app.api.routes import llm_red_team as llm_red_team_router
from app.api.routes import detection_feedback as detection_feedback_router
from app.api.routes import detection_suppression as detection_suppression_router
from app.api.routes import recon as recon_router
from app.api.routes import workflows as workflows_router
from app.api.routes import attacks as attacks_router
from app.models.agent_palace import AgentPalaceDrawer  # noqa: F401 — palace memory table
from app.models.recon_job import ReconJob, ReconWorkerHeartbeat  # noqa: F401 — interceptor workers
from app.models.sitemap_entry import SitemapEntry  # noqa: F401 — Praetorian-style app sitemap
from app.models.workflow import (  # noqa: F401 — ensure workflow tables are created
    Workflow,
    WorkflowVersion,
    WorkflowScript,
    WorkflowRun,
    WorkflowNodeRun,
    WorkflowArtifact,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
# Judah Security - Attack Surface Management API

A comprehensive platform for discovering and managing your organization's external attack surface.

## Features

- **Asset Discovery**: Automatically discover domains, subdomains, IPs, and URLs
- **Port & Service Tracking**: Track exposed ports with port-protocol-service structure
- **Technology Fingerprinting**: Identify web technologies using Wappalyzer-style detection
- **Vulnerability Scanning**: Run Nuclei scans with configurable profiles
- **ProjectDiscovery Tools**: Integrated subfinder, httpx, dnsx, naabu, katana
- **Aegis Oracle**: OPES exploitability scoring, attack-path classification, analyst briefs
- **Multi-tenant**: Support for multiple organizations with RBAC

## Port & Service Reporting

Track and report on exposed services with structured data:
- **Format**: `port-protocol-service` (e.g., `443-tcp-https`, `22-tcp-ssh`)
- **Reports**: Distribution by port, service, risky ports summary
- **Risk Flagging**: Automatic flagging of dangerous ports
    """,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Trust proxy headers from nginx so FastAPI knows requests arrive over HTTPS.
# Without this, Starlette generates http:// redirect Location headers (307) which
# browsers block as Mixed Content when the page is served over HTTPS.
try:
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware as _ProxyHeadersMiddleware
    app.add_middleware(_ProxyHeadersMiddleware, trusted_hosts="*")
except ImportError:
    try:
        from starlette.middleware.proxy_headers import ProxyHeadersMiddleware as _ProxyHeadersMiddleware  # type: ignore[no-redef]
        app.add_middleware(_ProxyHeadersMiddleware, trusted_hosts="*")
    except ImportError:
        pass  # Neither middleware available in this env; nginx handles SSL termination

# Register rate limiting (slowapi) — attaches the limiter + 429 handler.
register_rate_limiting(app)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=getattr(
        settings,
        "CORS_ORIGIN_REGEX",
        r"https://(.*\.)?(theforcesecurity|judahsecurity)\.io",
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "An internal server error occurred."})


# Register more-specific handlers AFTER the generic one so Starlette's
# reverse-registration lookup finds these first for their exact types.
@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_error_handler(request: Request, exc: SQLAlchemyError):
    logger.error("Database error on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "A database error occurred."})


# Include routers
app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(users.router, prefix=settings.API_PREFIX)
app.include_router(organizations.router, prefix=settings.API_PREFIX)
app.include_router(assets.router, prefix=settings.API_PREFIX)
app.include_router(vulnerabilities.router, prefix=settings.API_PREFIX)
app.include_router(scans.router, prefix=settings.API_PREFIX)
app.include_router(discovery.router, prefix=settings.API_PREFIX)
app.include_router(nuclei.router, prefix=settings.API_PREFIX)
app.include_router(ports.router, prefix=settings.API_PREFIX)
app.include_router(screenshots.router, prefix=settings.API_PREFIX)
app.include_router(external_discovery.router, prefix=settings.API_PREFIX)
app.include_router(waybackurls.router, prefix=settings.API_PREFIX)
app.include_router(netblocks.router, prefix=settings.API_PREFIX)
app.include_router(labels.router, prefix=settings.API_PREFIX)
app.include_router(scan_schedules.router, prefix=settings.API_PREFIX)
app.include_router(tools.router, prefix=settings.API_PREFIX)
app.include_router(sni_discovery.router, prefix=settings.API_PREFIX)
app.include_router(scan_config.router, prefix=settings.API_PREFIX)
app.include_router(acquisitions.router, prefix=settings.API_PREFIX)
app.include_router(oracle.router, prefix=settings.API_PREFIX)
app.include_router(agent.router, prefix=settings.API_PREFIX)
app.include_router(integrations.router, prefix=settings.API_PREFIX)
app.include_router(scoring_router.router, prefix=settings.API_PREFIX)
app.include_router(threat_intel_router.router, prefix=settings.API_PREFIX)
app.include_router(custom_templates_router.router, prefix=settings.API_PREFIX)
app.include_router(remediation_router.router, prefix=settings.API_PREFIX)
app.include_router(exceptions_router.router, prefix=settings.API_PREFIX)
app.include_router(github_secrets_router.router, prefix=settings.API_PREFIX)
app.include_router(agent_knowledge_router.router, prefix=settings.API_PREFIX)
app.include_router(agent_confirmations_router.router, prefix=settings.API_PREFIX)
app.include_router(agent_skills_router.router, prefix=settings.API_PREFIX)
app.include_router(roe_router.router, prefix=settings.API_PREFIX)
app.include_router(delphi_router.router, prefix=settings.API_PREFIX)
app.include_router(ingestion_router.router, prefix=settings.API_PREFIX)
app.include_router(recon_router.router, prefix=settings.API_PREFIX)
app.include_router(graph_router.router, prefix=settings.API_PREFIX)
app.include_router(reports_router.router, prefix=settings.API_PREFIX)
app.include_router(pentest_router.router, prefix=settings.API_PREFIX)
app.include_router(app_structure_router.router, prefix=settings.API_PREFIX)
app.include_router(mcp_router.router, prefix=settings.API_PREFIX)
app.include_router(mitre_router.router, prefix=settings.API_PREFIX)
app.include_router(llm_red_team_router.router, prefix=settings.API_PREFIX)
app.include_router(detection_feedback_router.router, prefix=settings.API_PREFIX)
app.include_router(detection_suppression_router.router, prefix=settings.API_PREFIX)
app.include_router(workflows_router.router, prefix=settings.API_PREFIX)
app.include_router(attacks_router.router, prefix=settings.API_PREFIX)


# ── Scoring pipeline lifecycle ────────────────────────────────────────────────
# The pipeline must start AFTER all models are imported (Base.metadata.create_all
# runs above) so SQLAlchemy event hooks see the fully-loaded Vulnerability class.

@app.on_event("startup")
def start_scoring_pipeline() -> None:
    """
    Start the universal vulnerability scoring pipeline on application startup.

    Registers SQLAlchemy event hooks so every new Vulnerability is automatically
    scored — regardless of which scanner, API path, or service created it.
    Then starts the worker thread pool to drain the queue.
    """
    try:
        from app.services.scoring_pipeline import register_hooks, get_scoring_pipeline
        # Register hooks first (attaches to SQLAlchemy class-level events)
        register_hooks()
        # Then start workers so the queue is drained as soon as items arrive
        get_scoring_pipeline().start()
        logger.info("Scoring pipeline started and hooks registered")
    except Exception as exc:
        # Pipeline failure must never prevent the API from starting — findings
        # can still be created; scoring will be unavailable until next restart.
        logger.error("Scoring pipeline failed to start: %s", exc, exc_info=True)


@app.on_event("shutdown")
def stop_scoring_pipeline() -> None:
    """Drain the queue and stop worker threads on graceful shutdown."""
    try:
        from app.services.scoring_pipeline import get_scoring_pipeline
        get_scoring_pipeline().stop(timeout=15.0)
    except Exception as exc:
        logger.warning("Scoring pipeline stop error: %s", exc)


@app.get("/")
def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "Attack Surface Management API with Nuclei Integration",
        "docs": "/api/docs"
    }


@app.get("/health")
def health_check():
    """Health check endpoint for container orchestration."""
    return {"status": "healthy"}


@app.get("/api/v1")
def api_info():
    """API information endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "endpoints": {
            "auth": f"{settings.API_PREFIX}/auth",
            "users": f"{settings.API_PREFIX}/users",
            "organizations": f"{settings.API_PREFIX}/organizations",
            "assets": f"{settings.API_PREFIX}/assets",
            "ports": f"{settings.API_PREFIX}/ports",
            "vulnerabilities": f"{settings.API_PREFIX}/vulnerabilities",
            "scans": f"{settings.API_PREFIX}/scans",
            "discovery": f"{settings.API_PREFIX}/discovery",
            "nuclei": f"{settings.API_PREFIX}/nuclei",
            "screenshots": f"{settings.API_PREFIX}/screenshots",
            "external_discovery": f"{settings.API_PREFIX}/external-discovery",
            "oracle": f"{settings.API_PREFIX}/oracle",
        },
    }


@app.on_event("startup")
async def startup_event():
    """Run on application startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("API documentation available at /api/docs")

    # Apply Oracle schema migrations so the Go service's tables exist
    apply_oracle_migrations()

    # Check ProjectDiscovery tools installation
    from app.services.nuclei_service import NucleiService
    from app.services.projectdiscovery_service import ProjectDiscoveryService

    nuclei_svc = NucleiService()
    pd_tools = ProjectDiscoveryService()

    if nuclei_svc.check_installation():
        logger.info("✓ Nuclei is installed")
    else:
        logger.warning("✗ Nuclei is not installed - vulnerability scanning unavailable")

    tools_status = pd_tools.check_tools()
    for tool, installed in tools_status.items():
        if installed:
            logger.info(f"✓ {tool} is installed")
        else:
            logger.warning(f"✗ {tool} is not installed")

    # Check EyeWitness installation
    from app.services.eyewitness_service import get_eyewitness_service
    eyewitness = get_eyewitness_service()
    ew_status = eyewitness.check_installation()
    if ew_status["installed"]:
        logger.info("✓ EyeWitness is installed")
    else:
        logger.warning(f"✗ EyeWitness is not installed: {ew_status.get('error', '')}")

    ensure_default_admin()


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("Shutting down application")


def apply_oracle_migrations():
    """Ensure the oracle schema and its tables exist with the correct structure.

    Uses CREATE TABLE IF NOT EXISTS so it is safe to run on every startup.
    Column names and types exactly match what the Go aegis-oracle service
    reads/writes (see aegis-oracle/internal/store/pg/store.go).
    """
    from sqlalchemy import text

    # Each statement is run independently so one failure does not block others.
    ddl_statements = [
        "CREATE SCHEMA IF NOT EXISTS oracle",

        # Raw ingest tables
        """CREATE TABLE IF NOT EXISTS oracle.raw_cvelistv5 (
            cve_id     text        NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            payload    jsonb       NOT NULL,
            PRIMARY KEY (cve_id, fetched_at)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_nvd (
            cve_id     text        NOT NULL,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            payload    jsonb       NOT NULL,
            PRIMARY KEY (cve_id, fetched_at)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_osv (
            osv_id     text        NOT NULL,
            cve_id     text,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            payload    jsonb       NOT NULL,
            PRIMARY KEY (osv_id, fetched_at)
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_raw_osv_cve_idx ON oracle.raw_osv (cve_id) WHERE cve_id IS NOT NULL",
        """CREATE TABLE IF NOT EXISTS oracle.raw_epss (
            cve_id     text         NOT NULL,
            scored_on  date         NOT NULL,
            score      numeric(5,4) NOT NULL,
            percentile numeric(5,4) NOT NULL,
            PRIMARY KEY (cve_id, scored_on)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_kev (
            cve_id          text PRIMARY KEY,
            added_on        date NOT NULL DEFAULT CURRENT_DATE,
            vendor          text,
            product         text,
            required_action text,
            ransomware_use  boolean,
            fetched_at      timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_pocs (
            cve_id     text        NOT NULL,
            source     text        NOT NULL,
            url        text        NOT NULL,
            title      text,
            stars      int,
            pushed_at  timestamptz,
            fetched_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (cve_id, source, url)
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.raw_hackerone_reports (
            report_id    text PRIMARY KEY,
            cve_id       text,
            url          text NOT NULL,
            title        text,
            cvss_vector  text,
            cvss_score   numeric(3,1),
            severity     text,
            reporter     text,
            team         text,
            disclosed_at timestamptz,
            body_text    text,
            fetched_at   timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_raw_hackerone_cve_idx ON oracle.raw_hackerone_reports (cve_id) WHERE cve_id IS NOT NULL",

        # Canonical CVE table — column names must match store.go SELECT/INSERT
        """CREATE TABLE IF NOT EXISTS oracle.cves (
            cve_id               text PRIMARY KEY,
            published_at         timestamptz NOT NULL DEFAULT now(),
            modified_at          timestamptz NOT NULL DEFAULT now(),
            description          text NOT NULL DEFAULT '',
            cwes                 text[] NOT NULL DEFAULT '{}',
            cpes                 jsonb NOT NULL DEFAULT '[]',
            cvss_vectors         jsonb NOT NULL DEFAULT '[]',
            reference_urls       text[] NOT NULL DEFAULT '{}',
            epss_score           numeric(5,4),
            epss_percentile      numeric(5,4),
            in_kev               boolean NOT NULL DEFAULT false,
            kev_added_on         date,
            nuclei_template      text,
            poc_count            int NOT NULL DEFAULT 0,
            primary_source       text NOT NULL DEFAULT 'cve.org',
            adp_enrichment       jsonb,
            ghsa_id              text,
            osv_ids              text[] NOT NULL DEFAULT '{}',
            source_versions      jsonb NOT NULL DEFAULT '{}',
            intrinsic_input_hash text,
            updated_at           timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_cves_modified_at_idx ON oracle.cves (modified_at DESC)",
        "CREATE INDEX IF NOT EXISTS oracle_cves_kev_idx ON oracle.cves (in_kev) WHERE in_kev",
        "CREATE INDEX IF NOT EXISTS oracle_cves_epss_high_idx ON oracle.cves (epss_score DESC) WHERE epss_score > 0.5",

        """CREATE TABLE IF NOT EXISTS oracle.reference_content (
            url           text PRIMARY KEY,
            cve_ids       text[] NOT NULL DEFAULT '{}',
            source_kind   text NOT NULL DEFAULT '',
            content_text  text,
            content_hash  text NOT NULL DEFAULT '',
            http_status   int,
            fetched_at    timestamptz NOT NULL DEFAULT now(),
            fetch_error   text
        )""",

        """CREATE TABLE IF NOT EXISTS oracle.exploitation_observations (
            cve_id        text NOT NULL,
            source        text NOT NULL,
            first_seen_at timestamptz NOT NULL DEFAULT now(),
            evidence_url  text,
            notes         text,
            PRIMARY KEY (cve_id, source)
        )""",

        # Phase A intrinsic analyses
        """CREATE TABLE IF NOT EXISTS oracle.cve_intrinsic_analyses (
            cve_id                text NOT NULL,
            input_hash            text NOT NULL,
            prompt_version        text NOT NULL,
            llm_provider          text NOT NULL DEFAULT '',
            llm_model             text NOT NULL DEFAULT '',
            remote_triggerability text NOT NULL DEFAULT '',
            exploit_complexity    text NOT NULL DEFAULT '',
            attacker_capability   text NOT NULL DEFAULT '',
            preconditions         jsonb NOT NULL DEFAULT '[]',
            cvss_reconciliation   jsonb NOT NULL DEFAULT '{}',
            attack_chain_summary  text NOT NULL DEFAULT '',
            detection_signals     jsonb NOT NULL DEFAULT '[]',
            rationale             text NOT NULL DEFAULT '',
            confidence            text NOT NULL DEFAULT '',
            token_usage           jsonb,
            cost_usd              numeric(8,4),
            created_at            timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (cve_id, input_hash, prompt_version)
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_cve_intrinsic_latest_idx ON oracle.cve_intrinsic_analyses (cve_id, created_at DESC)",

        # Knowledge base
        """CREATE TABLE IF NOT EXISTS oracle.cwe_profiles (
            cwe_id             text PRIMARY KEY,
            name               text NOT NULL DEFAULT '',
            abstraction        text NOT NULL DEFAULT '',
            parent_cwes        text[] NOT NULL DEFAULT '{}',
            exploit_archetypes jsonb NOT NULL DEFAULT '[]',
            ecosystem_notes    jsonb NOT NULL DEFAULT '{}',
            framework_notes    jsonb NOT NULL DEFAULT '{}',
            detection_signals  jsonb NOT NULL DEFAULT '[]',
            curator_notes      text,
            source_refs        text[] NOT NULL DEFAULT '{}',
            last_reviewed_at   timestamptz,
            reviewed_by        text,
            yaml_hash          text NOT NULL DEFAULT '',
            loaded_at          timestamptz NOT NULL DEFAULT now()
        )""",
        """CREATE TABLE IF NOT EXISTS oracle.dev_patterns (
            pattern_id            text PRIMARY KEY,
            cwe_ids               text[] NOT NULL DEFAULT '{}',
            ecosystem             text NOT NULL DEFAULT '',
            framework             text,
            library               text,
            pattern_name          text NOT NULL DEFAULT '',
            summary               text NOT NULL DEFAULT '',
            exploit_preconditions jsonb NOT NULL DEFAULT '[]',
            code_indicators       text[] NOT NULL DEFAULT '{}',
            config_indicators     text[] NOT NULL DEFAULT '{}',
            runtime_indicators    text[] NOT NULL DEFAULT '{}',
            attacker_capability   text NOT NULL DEFAULT '',
            remote_triggerability text NOT NULL DEFAULT '',
            vulnerable_example    text,
            secure_example        text,
            remediation_summary   text NOT NULL DEFAULT '',
            references_           text[] NOT NULL DEFAULT '{}',
            related_cves          text[] NOT NULL DEFAULT '{}',
            curator               text NOT NULL DEFAULT '',
            reviewed_at           timestamptz NOT NULL DEFAULT now(),
            yaml_hash             text NOT NULL DEFAULT '',
            loaded_at             timestamptz NOT NULL DEFAULT now()
        )""",

        # Assets
        """CREATE TABLE IF NOT EXISTS oracle.assets (
            asset_id     text PRIMARY KEY,
            tenant_id    text,
            hostname     text,
            ip           inet,
            open_ports   int[] NOT NULL DEFAULT '{}',
            signals      jsonb NOT NULL DEFAULT '{}',
            signals_hash text NOT NULL DEFAULT '',
            criticality  text NOT NULL DEFAULT 'unknown',
            exposure     text NOT NULL DEFAULT 'unknown',
            source       text NOT NULL DEFAULT 'asm',
            updated_at   timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_assets_signals_gin ON oracle.assets USING gin (signals jsonb_path_ops)",

        # Findings (Phase B output)
        """CREATE TABLE IF NOT EXISTS oracle.findings (
            finding_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            cve_id                  text NOT NULL,
            asset_id                text NOT NULL,
            intrinsic_input_hash    text NOT NULL DEFAULT '',
            asset_signals_hash      text NOT NULL DEFAULT '',
            evaluator_version       text NOT NULL DEFAULT '',
            preconditions_evaluated jsonb NOT NULL DEFAULT '[]',
            opes_score              numeric(3,1) NOT NULL DEFAULT 0,
            opes_category           text NOT NULL DEFAULT 'informational',
            opes_label              text NOT NULL DEFAULT '',
            opes_components         jsonb NOT NULL DEFAULT '{}',
            opes_top_contributors   jsonb NOT NULL DEFAULT '[]',
            opes_dampener           text,
            opes_override           text,
            confidence              text NOT NULL DEFAULT 'low',
            priority_rationale      text NOT NULL DEFAULT '',
            recommendation_text     text NOT NULL DEFAULT '',
            cvss_reconciliation     jsonb,
            analyst_brief           jsonb,
            status                  text NOT NULL DEFAULT 'open',
            superseded_by           uuid,
            created_at              timestamptz NOT NULL DEFAULT now(),
            updated_at              timestamptz NOT NULL DEFAULT now()
        )""",
        "CREATE INDEX IF NOT EXISTS oracle_findings_open_priority_idx ON oracle.findings (opes_category, created_at DESC) WHERE status = 'open'",
        "CREATE INDEX IF NOT EXISTS oracle_findings_asset_open_idx ON oracle.findings (asset_id) WHERE status = 'open'",
        "CREATE INDEX IF NOT EXISTS oracle_findings_cve_idx ON oracle.findings (cve_id)",

        # Verification tasks
        """CREATE TABLE IF NOT EXISTS oracle.verification_tasks (
            task_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id           uuid NOT NULL,
            precondition_id      text NOT NULL DEFAULT '',
            task_kind            text NOT NULL DEFAULT 'manual',
            command              text,
            expected_signal_path text NOT NULL DEFAULT '',
            expected_match       text,
            external_ref         text,
            status               text NOT NULL DEFAULT 'open',
            resolution_notes     text,
            signal_value         text,
            created_at           timestamptz NOT NULL DEFAULT now(),
            resolved_at          timestamptz
        )""",

        # Module state
        """CREATE TABLE IF NOT EXISTS oracle.module_state (
            module_name text NOT NULL,
            key         text NOT NULL,
            value       jsonb NOT NULL DEFAULT '{}',
            updated_at  timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (module_name, key)
        )""",

        # ── Oracle enrichment columns on the ASM vulnerabilities table ───────
        # Promoted from metadata_["oracle"] JSON for efficient querying/sorting.
        # Each statement uses ADD COLUMN IF NOT EXISTS so it's safe to re-run.
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS detection_confidence   VARCHAR(50) DEFAULT 'unknown'",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_opes_score      FLOAT",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_opes_category   VARCHAR(50)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_opes_label      VARCHAR(100)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_opes_confidence VARCHAR(20)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_attack_path     VARCHAR(100)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_lateral_mvmt    VARCHAR(50)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_mode            VARCHAR(30)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_enriched_at     TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_analysis_status VARCHAR(30)",
        "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS oracle_finding_id      VARCHAR(100)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_oracle_opes_score    ON vulnerabilities (oracle_opes_score)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_oracle_opes_category ON vulnerabilities (oracle_opes_category)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_oracle_mode          ON vulnerabilities (oracle_mode)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_oracle_enriched_at   ON vulnerabilities (oracle_enriched_at)",

        # ── Jira integration schema migrations ────────────────────────────────
        "ALTER TABLE jira_integrations ADD COLUMN IF NOT EXISTS auto_create_enabled       BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE jira_integrations ADD COLUMN IF NOT EXISTS auto_create_min_severity  VARCHAR(20) DEFAULT 'high'",
        "ALTER TABLE jira_integrations ADD COLUMN IF NOT EXISTS open_to_close_transitions JSONB DEFAULT '[]'",
        "ALTER TABLE jira_integrations ADD COLUMN IF NOT EXISTS close_to_open_transitions JSONB DEFAULT '[]'",
        "ALTER TABLE jira_integrations ADD COLUMN IF NOT EXISTS close_custom_fields       JSONB DEFAULT '{}'",
        "ALTER TABLE jira_integrations ADD COLUMN IF NOT EXISTS reopen_custom_fields      JSONB DEFAULT '{}'",
        "ALTER TABLE jira_tickets ADD COLUMN IF NOT EXISTS jira_status      VARCHAR(100)",
        "ALTER TABLE jira_tickets ADD COLUMN IF NOT EXISTS jira_assignee    VARCHAR(255)",
        "ALTER TABLE jira_tickets ADD COLUMN IF NOT EXISTS is_associated    BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE jira_tickets ADD COLUMN IF NOT EXISTS disconnected_at  TIMESTAMP WITH TIME ZONE",

        # ── ServiceNow bidirectional sync + close validation ──────────────────
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS sync_enabled              BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS table_name                VARCHAR(100) NOT NULL DEFAULT 'incident'",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS close_state               VARCHAR(50) NOT NULL DEFAULT '6'",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS reopen_state              VARCHAR(50) NOT NULL DEFAULT '2'",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS remote_closed_states      JSONB DEFAULT '[\"6\", \"7\"]'",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS validate_on_remote_close  BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS accept_close_as           VARCHAR(30) NOT NULL DEFAULT 'resolved'",
        "ALTER TABLE servicenow_integrations ADD COLUMN IF NOT EXISTS last_pull_at              TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE servicenow_deliveries ADD COLUMN IF NOT EXISTS snow_state                     VARCHAR(50)",
        "ALTER TABLE servicenow_deliveries ADD COLUMN IF NOT EXISTS snow_state_label               VARCHAR(100)",
        "ALTER TABLE servicenow_deliveries ADD COLUMN IF NOT EXISTS last_synced_at                 TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE servicenow_deliveries ADD COLUMN IF NOT EXISTS pending_close_validation       BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE servicenow_deliveries ADD COLUMN IF NOT EXISTS pending_close_validation_id    INTEGER",
        "ALTER TABLE servicenow_deliveries ADD COLUMN IF NOT EXISTS last_close_validation_verdict  VARCHAR(50)",

        # ── Censys ASM integration schema migrations ──────────────────────────
        "ALTER TABLE censys_asm_integrations ADD COLUMN IF NOT EXISTS continuous_sync_enabled BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE censys_asm_integrations ADD COLUMN IF NOT EXISTS sync_interval_minutes   INTEGER NOT NULL DEFAULT 360",

        # ── Panorama integration — config export / air-gapped mode ────────────
        "ALTER TABLE panorama_integrations ADD COLUMN IF NOT EXISTS connection_mode     VARCHAR(32) NOT NULL DEFAULT 'api'",
        "ALTER TABLE panorama_integrations ADD COLUMN IF NOT EXISTS export_file_path     TEXT",
        "ALTER TABLE panorama_integrations ADD COLUMN IF NOT EXISTS export_filename      VARCHAR(512)",
        "ALTER TABLE panorama_integrations ADD COLUMN IF NOT EXISTS export_file_size     INTEGER",
        "ALTER TABLE panorama_integrations ADD COLUMN IF NOT EXISTS export_uploaded_at   TIMESTAMP",
        "ALTER TABLE panorama_integrations ALTER COLUMN panorama_host DROP NOT NULL",
        "ALTER TABLE panorama_integrations ALTER COLUMN api_key_encrypted DROP NOT NULL",

        # ── Forced password reset for admin-provisioned accounts ──────────────
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE",

        "ALTER TABLE agent_conversations ADD COLUMN IF NOT EXISTS engagement_replay JSONB DEFAULT '[]'",
        "ALTER TABLE agent_conversations ADD COLUMN IF NOT EXISTS token_usage JSONB",
        "ALTER TABLE agent_conversations ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION",
        "ALTER TABLE pentest_sessions ADD COLUMN IF NOT EXISTS engagement_replay JSONB DEFAULT '[]'",
        "ALTER TABLE pentest_sessions ADD COLUMN IF NOT EXISTS token_usage JSONB",
        "ALTER TABLE pentest_sessions ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION",

        # Vespasian / OpenAPI inventory — create_all will not add these to an
        # existing assets table, so any full Asset load 500s without them.
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS rest_endpoints JSON DEFAULT '[]'::json",
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS api_specs JSON DEFAULT '[]'::json",
    ]

    try:
        with engine.connect() as conn:
            for stmt in ddl_statements:
                try:
                    conn.execute(text(stmt))
                except Exception as e:
                    logger.warning("oracle migration stmt skipped: %s", e)
            conn.commit()
        logger.info("Oracle schema migrations applied.")
    except Exception as exc:
        logger.error("Oracle schema migrations failed (non-fatal): %s", exc)


def ensure_default_admin():
    """Ensure a known-good admin account exists and is usable.

    Fails closed: without an explicit DEFAULT_ADMIN_PASSWORD we do NOT create or
    repair an admin account, so the platform never ships a predictable superuser.
    """
    default_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@judahsecurity.com")
    default_username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    default_password = os.getenv("DEFAULT_ADMIN_PASSWORD")

    _weak_passwords = {"admin123", "admin", "password", "changeme", "change-me"}
    if not default_password or default_password.strip().lower() in _weak_passwords:
        logger.warning(
            "Skipping default admin bootstrap: DEFAULT_ADMIN_PASSWORD is unset or weak. "
            "Set a strong DEFAULT_ADMIN_PASSWORD to auto-provision the admin account."
        )
        return

    db = SessionLocal()
    try:
        user = (
            db.query(User)
            .filter(or_(User.username == default_username, User.email == default_email))
            .first()
        )

        if not user:
            user = User(
                email=default_email,
                username=default_username,
                hashed_password=get_password_hash(default_password),
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_superuser=True,
                is_active=True,
            )
            db.add(user)
            db.commit()
            logger.info("Created default admin user with configured credentials.")
            return

        updated = False
        if not user.username:
            user.username = default_username
            updated = True
        if not user.email:
            user.email = default_email
            updated = True
        if not user.is_superuser:
            user.is_superuser = True
            updated = True
        if not user.is_active:
            user.is_active = True
            updated = True
        if user.role != UserRole.ADMIN:
            user.role = UserRole.ADMIN
            updated = True

        if updated:
            db.add(user)
            db.commit()
            logger.info("Default admin user validated/updated.")
        else:
            logger.info("Default admin user already valid.")
    except Exception as exc:
        logger.error(f"Failed to ensure default admin user: {exc}")
    finally:
        db.close()
