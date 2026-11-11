"""
Project / Organization scan and agent settings (per-org).

Stores 180+ configurable parameters per organization, grouped by module.
Each module's config is a JSON object; workers and the agent read these at runtime.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, UniqueConstraint
from sqlalchemy.orm import relationship

from app.db.database import Base


# Module names for project settings (per-org)
MODULE_TARGET = "target"
MODULE_PORT_SCANNER = "port_scanner"
MODULE_HTTP_PROBER = "http_prober"
MODULE_WAPPALYZER = "wappalyzer"
MODULE_BANNER_GRABBING = "banner_grabbing"
MODULE_KATANA = "katana"
MODULE_PASSIVE_URL = "passive_url"
MODULE_API_DISCOVERY = "api_discovery"
MODULE_NUCLEI = "nuclei"
MODULE_CVE_ENRICHMENT = "cve_enrichment"
MODULE_MITRE_MAPPING = "mitre_mapping"
MODULE_SECURITY_CHECKS = "security_checks"
MODULE_AGENT = "agent"
MODULE_SCAN_TOGGLES = "scan_toggles"
MODULE_RULES_OF_ENGAGEMENT = "rules_of_engagement"
MODULE_COMMONCRAWL = "commoncrawl"
MODULE_SLA_POLICY = "sla_policy"
MODULE_FINDING_RESPONSE = "finding_response"

ALL_MODULES = [
    MODULE_TARGET,
    MODULE_PORT_SCANNER,
    MODULE_HTTP_PROBER,
    MODULE_WAPPALYZER,
    MODULE_BANNER_GRABBING,
    MODULE_KATANA,
    MODULE_PASSIVE_URL,
    MODULE_API_DISCOVERY,
    MODULE_NUCLEI,
    MODULE_CVE_ENRICHMENT,
    MODULE_MITRE_MAPPING,
    MODULE_SECURITY_CHECKS,
    MODULE_AGENT,
    MODULE_SCAN_TOGGLES,
    MODULE_RULES_OF_ENGAGEMENT,
    MODULE_COMMONCRAWL,
    MODULE_SLA_POLICY,
    MODULE_FINDING_RESPONSE,
]


def default_target_config():
    return {
        "target_domain": None,
        "subdomain_list": [],
        "verify_domain_ownership": False,
        "use_tor": False,
        "use_bruteforce": True,
        # Filter subdomains whose only resolutions match the zone's wildcard
        # DNS answer set. Dramatically improves data quality on wildcarded zones.
        "filter_wildcard_dns": True,
        # Prefer the ``puredns`` binary when it is installed; falls back to a
        # pure-Python implementation otherwise.
        "prefer_puredns_binary": True,
    }


def default_port_scanner_config():
    return {
        "scan_type": "c",  # CONNECT (c) vs SYN (s)
        "top_ports": 1000,
        "custom_ports": [],
        "rate_limit": 1000,
        "thread_count": 25,
        "cdn_exclusion": True,
        "passive_shodan": False,
        "skip_host_discovery": False,
    }


def default_http_prober_config():
    return {
        "follow_redirects": True,
        "max_redirects": 5,
        "timeout": 10,
        "rate_limit": 150,
        "status_code_probe": True,
        "tech_detection": True,
        "tls_probe": True,
        "favicon_hash": True,
        "jarm_fingerprint": False,
        "asn_cdn_detection": True,
        "include_response_body": False,
        "custom_headers": {},
    }


def default_wappalyzer_config():
    return {
        "enabled": True,
        "min_confidence_threshold": 0,  # 0-100
        "require_html": False,  # Skip if no HTML body
        "auto_update_npm": False,
        "cache_ttl_seconds": 86400,  # 24h
    }


def default_banner_grabbing_config():
    return {
        "enabled": True,
        "timeout_seconds": 5,
        "thread_count": 10,
        "max_banner_length": 1024,
    }


def default_katana_config():
    return {
        "enabled": True,
        "crawl_depth": 5,
        "max_urls_per_domain": 500,
        "js_rendering": False,
        "scope": "subdomain",  # exact_domain | root_domain | subdomain
        "rate_limit": 150,
        "exclude_patterns": [],  # or use 100+ default patterns
        # Match Katana README pipeline; worker also passes js_crawl, form_extraction, extension_filter_preset
        "extension_filter_preset": "pipeline",  # pipeline | extended
        "known_files": False,
    }


def default_passive_url_config():
    return {
        "enabled": True,
        "providers": ["wayback", "commoncrawl"],
        "max_urls_per_domain": 10000,
        "year_range": None,
        "verify_with_httpx": True,
        "httpx_rate_limit": 150,
        "dead_endpoint_filter": True,
        "file_extension_blacklist": [],
    }


def default_api_discovery_config():
    return {
        "enabled": False,
        "wordlist": "routes-small",
        "rate_limit": 100,
        "connection_count": 5,
        "status_code_whitelist": [200, 201, 204],
        "min_content_length": 0,
        "method_detection": "options",
    }


def default_nuclei_config():
    return {
        "severity": ["critical", "high", "medium", "low", "info"],
        "dast_mode": False,
        "template_include": [],
        "template_exclude": [],
        "exclude_tags": [],
        "rate_limit": 150,
        "concurrency": 25,
        "bulk_size": 25,
        "timeout": 10,
        "interactsh": True,
        "headless": False,
        "follow_redirects": True,
        "template_auto_update": True,
    }


def default_cve_enrichment_config():
    return {
        "enabled": True,
        "data_source": "nvd",  # nvd | vulners
        "max_cves_per_finding": 10,
        "min_cvss_score": 0,
        "api_keys": {},
    }


def default_mitre_mapping_config():
    return {
        "auto_update": True,
        "cwe_inclusion": True,
        "capec_inclusion": True,
        "cache_ttl_seconds": 86400,
    }


def default_security_checks_config():
    return {
        "network_exposure": True,
        "tls_certificate": True,
        "cert_expiry_days": 30,
        "security_headers": True,
        "authentication_checks": True,
        "dns_security": True,
        "exposed_services": True,
        "application_checks": True,
        # asm_scanner_core (shared package): optional CLI checks → same ingest path as agents
        "asm_core_checks": True,
        "asm_core_nerva": False,
        "asm_core_argus": False,
        "asm_core_atlas": False,
        "asm_core_hermes": False,
        "asm_core_janus": False,
        "asm_core_gitleaks": False,
        # Argus (Aegis Vanguard all-seeing secrets scanner, wraps Praetorian titus)
        "argus_scan_path": None,
        "argus_cli_args": None,
        "argus_validate": False,
        "argus_timeout": 900,
        # Atlas (Aegis Vanguard attack-surface cartographer, wraps Praetorian pius)
        "atlas_org": None,
        "atlas_domain": None,
        "atlas_asn": None,
        "atlas_mode": "passive",
        "atlas_plugins": None,
        "atlas_disable": None,
        "atlas_concurrency": 5,
        "atlas_timeout": 900,
        "nerva_extra_args": None,
        "nerva_timeout": 300,
        "nerva_max_targets": 50,
        # Hermes (Aegis Vanguard remote secrets-finder, wraps TruffleHog v3)
        "hermes_source": None,          # git | github | gitlab | s3 | gcs | azure | docker | postman | filesystem | ...
        "hermes_target": None,          # repo URL / org / bucket / image / path
        "hermes_only_verified": False,  # emit only live-validated credentials
        "hermes_cli_args": None,
        "hermes_env": None,             # auth env dict: {GITHUB_TOKEN, AWS_ACCESS_KEY_ID, ...}
        "hermes_timeout": 900,
        # Janus (Aegis Vanguard two-faced DAST gatekeeper, wraps OWASP ZAP)
        "janus_target_url": None,
        "janus_mode": "baseline",       # 'baseline' (passive, safe) or 'full' (active)
        "janus_minutes": None,          # cap ZAP internal timers
        "janus_ajax": False,            # enable ajax-spider for SPAs
        "janus_context_file": None,     # optional .context file for auth/scope
        "janus_cli_args": None,
        "janus_timeout": 1800,
        "gitleaks_repo_path": None,
        "gitleaks_timeout": 600,
    }


def default_agent_config():
    return {
        # ── Single default model ─────────────────────────────────────────
        # This is the ONE model everything uses unless a per-task override is
        # set below. Change these two fields to switch the whole agent to a
        # different model/provider. Providers: anthropic | openai | deepseek | kimi | groq | ollama.
        "llm_provider": "anthropic",
        "llm_model": "claude-sonnet-4-6",
        # ── Optional per-task overrides ──────────────────────────────────
        # Leave empty to use the single default above for every task. To route
        # a specific task to a different model, add a "provider:model" entry,
        # e.g. {"offensive": "anthropic:claude-sonnet-4-6",
        #       "reasoning": "groq:llama-3.3-70b-versatile",
        #       "report": "ollama:qwen2.5:14b"}.
        # A "default" key here overrides llm_provider/llm_model for any task
        # not explicitly listed. Keys come from the encrypted per-org API
        # config store (bring-your-own-key).
        "task_models": {},
        "max_iterations": 100,
        "require_approval_exploitation": True,
        "require_approval_post_exploitation": True,
        "activate_post_exploitation": True,
        "post_exploitation_type": "stateless",  # stateful | stateless
        "lhost": None,
        "lport": 4444,
        "bind_port_on_target": 4444,
        "payload_use_https": False,
        "custom_system_prompts": {},
        "tool_output_max_chars": 8000,
        "execution_trace_memory": 100,
        "brute_force_max_attempts": 3,
        # Per-tool confirmation policy. Patterns support ``*`` suffix wildcards
        # (e.g. ``execute_*``). Values: "auto" (run), "confirm" (pause & ask),
        # "deny" (refuse outright). More specific patterns win.
        "tool_confirmation_policy": {
            # Active/destructive tools need approval; light recon is auto
            # (also enforced in confirmation_service.SAFE_RECON_TOOLS).
            "execute_*": "confirm",
            "execute_httpx": "auto",
            "execute_dnsx": "auto",
            "execute_wafw00f": "auto",
            "execute_wappalyzer": "auto",
            "execute_whatweb": "auto",
            "execute_curl": "auto",
            "execute_katana": "auto",
            "execute_gau": "auto",
            "execute_waybackurls": "auto",
            "execute_crtsh": "auto",
            "execute_crt_name": "auto",
            "execute_subfinder": "auto",
            "execute_subfaster": "auto",
            "execute_deep_crawl": "confirm",
            "execute_llm_red_team": "confirm",
            "execute_metasploit*": "deny",
            "execute_sqlmap*": "confirm",
            "run_intruder_batch": "confirm",
            "create_scan": "confirm",
            "add_asset": "auto",
        },
        # Global override: when true, the gate is active; when false the
        # confirmation layer is bypassed (handy for headless automation).
        "tool_confirmation_enabled": True,
        # Autonomous runs with an analyst present must honor "confirm" policy
        # decisions. Unattended deployments can explicitly opt into bypassing
        # those decisions after establishing separate engagement controls.
        "agent_autonomous_auto_approve": False,
        # Auto-allow *read-only* tools regardless of the pattern above.
        "tool_confirmation_readonly_auto_allow": True,
    }


def default_scan_toggles_config():
    """Module enable/disable with dependency resolution (parent off => children off)."""
    return {
        "domain_discovery": True,
        "port_scan": True,
        "http_probe": True,
        "resource_enum": True,  # Katana, ParamSpider, Wayback
        "js_analysis": True,
        "js_secret_scan": True,
        "js_intruder_planning": True,
        "vuln_scan": True,
    }


def default_rules_of_engagement_config():
    """
    Per-org Rules of Engagement. If ``enabled`` is True, every scan creation
    path calls ``roe_service.check_target(...)`` and hard-refuses work that
    falls outside ``scope_in`` or lands inside ``scope_out``.

    ``scope_in`` / ``scope_out`` entries may be:
        - A hostname ("example.com")
        - A wildcard ("*.example.com")
        - A CIDR ("10.0.0.0/8")

    ``max_rps_global`` caps the aggregate request rate applied by the agent
    across tools. ``allowed_scan_types`` / ``restricted_scan_types`` are
    enforced when creating a scan.
    """
    return {
        "enabled": False,
        "document_name": "",
        "document_hash": "",
        "document_text": "",
        "scope_in": [],
        "scope_out": [],
        "allowed_scan_types": [],
        "restricted_scan_types": [
            "llm_red_team",  # requires explicit opt-in per target
        ],
        "max_rps_global": 10,
        "max_concurrency": 10,
        "requires_agent_confirmation": True,
        "contacts": [],
        "notes": "",
        "accepted_by": "",
        "accepted_at": None,
    }


def default_commoncrawl_config():
    """
    CommonCrawl CDX subdomain enumeration + brand keyword discovery settings.

    Mode 1 — Subdomain enumeration (*.domain queries on known root domains)
    Mode 2 — Brand keyword sweep (*keyword* queries to find unknown domains)

    years options:
      "last1"      – last 1 calendar year (default, fastest)
      "last2"      – last 2 calendar years
      "last3"      – last 3 calendar years
      "lastN"      – last N calendar years
      "all"        – every available release (slowest, most complete)
      "2025"       – a single specific year
      "2025,2024"  – multiple specific years (comma-separated)
    """
    return {
        "enabled": True,
        # How many calendar years of crawl data to query.
        "years": "last1",
        # Datasets queried per year. 1 is the most recent snapshot (fastest).
        "max_per_year": 1,
        # Seconds to wait for a single CDX API response before giving up.
        "timeout": 120,
        # Upper bound on URLs fetched per release per domain.
        "max_results_per_release": 100000,
        # Mode 2: also sweep CC for hostnames containing brand/product keywords.
        # Keywords are sourced from org.commoncrawl_org_name and
        # org.commoncrawl_keywords (set via Discovery Settings).
        "use_keyword_search": True,
    }


def default_sla_policy_config():
    """Remediation windows (days) by SLA tier and exposure.

    Defaults follow the "Proposed remediation windows by severity and
    exposure type" table. ``None`` means no SLA (no deadline, no reminders).
    """
    return {
        "tiers": ["urgent", "critical", "high", "medium", "low", "info"],
        "internet_accessible": {
            "urgent": 2, "critical": 14, "high": 30, "medium": 60, "low": 90, "info": None,
        },
        "non_internet_accessible": {
            "urgent": 10, "critical": 30, "high": 60, "medium": 90, "low": 180, "info": None,
        },
        # Which finding field picks the tier: "severity" (scanner/analyst
        # severity) or "risk_level" (the Likelihood x Impact model, sev_level).
        "tier_source": "severity",
        # Promote to "urgent" automatically when the finding's CVE is in CISA
        # KEV and the tier would otherwise be critical. Analysts can always set
        # urgent by hand at triage.
        "urgent_if_kev_critical": True,
        # Exposure used when nothing says whether the asset is internet-facing.
        "default_exposure": "internet_accessible",
        # When the SLA clock starts: "triage" (analyst approval) or "detected".
        "clock_starts": "triage",
        # Fractions of the window at which reminders fire, then breach.
        "reminder_thresholds": [0.5, 0.9],
    }


def default_finding_response_config():
    """Who carries out each response action, and how findings reach owners.

    Executors: "judah" (Judah sends it itself), "webhook" (Judah emits a signed
    event and an external workflow such as Blink carries it out and reports
    back), or "off". One executor per action keeps every action firing once.
    """
    return {
        # Findings reach owners only after an analyst approves them at triage.
        "executors": {
            "notify_owner": "webhook",
            "open_ticket": "off",
            "sla_reminders": "webhook",
            "close_out": "webhook",
        },
        "webhook_url": "",
        # Encrypted at rest; set through PUT /finding-response/webhook.
        "webhook_secret_encrypted": "",
        "webhook_api_key_header": "",
        "webhook_api_key_encrypted": "",
        "default_owner_email": "",
        # Public base URL of this Judah deployment, used for links in events
        # and notices (e.g. https://judah.example.com). Empty = relative links.
        "judah_base_url": "",
        "notice": {
            "from_name": "Vulnerability Management",
            "subject_template": "[{severity}] {title} - remediate by {deadline}",
            # Banner above the title; {exposure_title} is External or Internal.
            "header_template": "{exposure_title} Exposure",
            # strftime format for dates in the notice (MM/DD/YYYY by default;
            # "%B %d, %Y" gives "September 07, 2023").
            "date_format": "%m/%d/%Y",
            "labels": {
                "severity": "Severity",
                "type": "Type",
                "asset": "Affected Asset",
                "recipient": "To",
                "remediation_date": "Expected Remediation Date",
                "remediation": "Remediation/Recommendation",
            },
            # Paragraph placeholders: {detected_date} {sla_days} {exposure}
            # {severity} {asset} {title} {remediation_date} {ticket_number};
            # {contact} becomes a mailto link to contact_email.
            "intro_template": (
                "On {detected_date}, an {exposure} vulnerability was identified on an asset within "
                "your area of responsibility. This finding should be reviewed, and remediated or "
                "mitigated within {sla_days} days, before a risk is tracked in the organization's "
                "Governance, Risk, and Compliance (GRC) system. Details of this finding can be found below."
            ),
            "intro_no_sla_template": (
                "On {detected_date}, an {exposure} finding was identified on an asset within your "
                "area of responsibility. Details can be found below."
            ),
            "closing_templates": [
                "If you have any questions or believe that this communication is incorrectly "
                "assigned to you, please contact the {contact} team.",
                "If this issue has been remediated, please contact the {contact} team.",
                "If this issue cannot be remediated or mitigated by the required remediation date "
                "above, please document this risk within the risk management system and email the "
                "ticket number or confirmation of risk acceptance to the {contact} team.",
            ],
            "contact_name": "Vulnerability Management",
            "contact_email": "",
            # Display names for finding sources in the "Reporter" line.
            "source_names": {
                "tenable_vm": "Tenable", "tenable_agent": "Tenable", "tenable_credentialed": "Tenable",
                "wiz": "Wiz", "nuclei": "Judah", "port_scanner": "Judah", "censys": "Censys",
                "hackerone": "HackerOne", "praetorian": "Praetorian", "falcon": "CrowdStrike Falcon",
                "manual": "Manual", "bitsight": "BitSight", "securityscorecard": "SecurityScorecard",
            },
            # Title/severity colors; defaults match the finding template .docx.
            "severity_colors": {
                "urgent": "7030A0",
                "critical": "C00000",
                "high": "FF0000",
                "medium": "FFC000",
                "low": "92D050",
                "info": "00B050",
            },
            "footer": "",
        },
    }


def get_default_config(module: str) -> dict:
    """Return default config for a module."""
    defaults = {
        MODULE_TARGET: default_target_config,
        MODULE_PORT_SCANNER: default_port_scanner_config,
        MODULE_HTTP_PROBER: default_http_prober_config,
        MODULE_WAPPALYZER: default_wappalyzer_config,
        MODULE_BANNER_GRABBING: default_banner_grabbing_config,
        MODULE_KATANA: default_katana_config,
        MODULE_PASSIVE_URL: default_passive_url_config,
        MODULE_API_DISCOVERY: default_api_discovery_config,
        MODULE_NUCLEI: default_nuclei_config,
        MODULE_CVE_ENRICHMENT: default_cve_enrichment_config,
        MODULE_MITRE_MAPPING: default_mitre_mapping_config,
        MODULE_SECURITY_CHECKS: default_security_checks_config,
        MODULE_AGENT: default_agent_config,
        MODULE_SCAN_TOGGLES: default_scan_toggles_config,
        MODULE_RULES_OF_ENGAGEMENT: default_rules_of_engagement_config,
        MODULE_COMMONCRAWL: default_commoncrawl_config,
        MODULE_SLA_POLICY: default_sla_policy_config,
        MODULE_FINDING_RESPONSE: default_finding_response_config,
    }
    fn = defaults.get(module)
    return fn() if fn else {}


class ProjectSettings(Base):
    """
    Per-organization project settings (per-org).
    One row per (organization_id, module); config is JSON.
    """

    __tablename__ = "project_settings"
    __table_args__ = (UniqueConstraint("organization_id", "module", name="uq_project_settings_org_module"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    organization = relationship("Organization", backref="project_settings")
    module = Column(String(64), nullable=False, index=True)
    config = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<ProjectSettings org={self.organization_id} module={self.module}>"

    @classmethod
    def get_config(cls, db, organization_id: int, module: str) -> dict:
        """Get config for org+module; merge with defaults."""
        row = db.query(cls).filter(
            cls.organization_id == organization_id,
            cls.module == module,
        ).first()
        default = get_default_config(module)
        if not row or not row.config:
            return default
        merged = dict(default)
        for k, v in row.config.items():
            merged[k] = v
        return merged

    @classmethod
    def set_config(cls, db, organization_id: int, module: str, config: dict) -> "ProjectSettings":
        """Set config for org+module (partial update merged with existing)."""
        row = db.query(cls).filter(
            cls.organization_id == organization_id,
            cls.module == module,
        ).first()
        current = get_default_config(module)
        if row and row.config:
            current.update(row.config)
        current.update(config)
        if not row:
            row = cls(organization_id=organization_id, module=module, config=current)
            db.add(row)
        else:
            row.config = current
        db.flush()
        return row

    @classmethod
    def ensure_defaults(cls, db, organization_id: int) -> None:
        """Ensure all modules have a row for this org (with defaults)."""
        for module in ALL_MODULES:
            existing = db.query(cls).filter(
                cls.organization_id == organization_id,
                cls.module == module,
            ).first()
            if not existing:
                db.add(cls(
                    organization_id=organization_id,
                    module=module,
                    config=get_default_config(module),
                ))
        db.commit()
