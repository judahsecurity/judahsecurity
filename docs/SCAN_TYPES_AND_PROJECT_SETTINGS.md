# Scan Types & Project Settings

This document lists all scanning types in the application, how to ensure they are available, and how project settings (180+ parameters) are structured for per-organization control.

---

## 1. Scan Types in Your Application

Your app already has these **ScanType** values (see `backend/app/models/scan.py`):

| Scan Type | Enum Value | Description | Worker Handler |
|-----------|------------|-------------|----------------|
| Discovery | `DISCOVERY` | Full asset discovery from seed domain | DISCOVERY |
| Subdomain enum | `SUBDOMAIN_ENUM` | Subdomain enumeration (Subfinder, etc.) | SUBDOMAIN_ENUM |
| DNS enum | `DNS_ENUM` | DNS record enumeration | DNS_RESOLUTION |
| DNS resolution | `DNS_RESOLUTION` | Resolve domains to IPs + geo | DNS_RESOLUTION |
| Port scan | `PORT_SCAN` | Port/service scanning (Naabu, masscan) | PORT_SCAN |
| Port verify | `PORT_VERIFY` | Nmap verification of discovered ports | PORT_VERIFY |
| Service detect | `SERVICE_DETECT` | Deep nmap for unknown services | SERVICE_DETECT |
| HTTP probe | `HTTP_PROBE` | HTTP probing for live web assets (httpx) | HTTP_PROBE |
| Technology | `TECHNOLOGY` | Wappalyzer (+ optional WhatRuns) | TECHNOLOGY_SCAN |
| Certificate | `CERTIFICATE` | SSL/TLS certificate analysis | (via discovery/config) |
| Vulnerability | `VULNERABILITY` | Nuclei template-based scanning | NUCLEI_SCAN |
| Login portal | `LOGIN_PORTAL` | Login/admin panel detection | LOGIN_PORTAL |
| Screenshot | `SCREENSHOT` | Web screenshot capture | SCREENSHOT |
| ParamSpider | `PARAMSPIDER` | URL parameter discovery | PARAMSPIDER |
| WaybackURLs | `WAYBACKURLS` | Historical URL discovery (GAU-style) | WAYBACKURLS |
| Katana | `KATANA` | Deep web crawling with JS | KATANA |
| Geo enrich | `GEO_ENRICH` | Geo-location enrichment | GEO_ENRICH |
| Full | `FULL` | Discovery + all scans | DISCOVERY |
| Cleanup | `CLEANUP` | System maintenance | CLEANUP |

### Scan type mapping (reference)

| Module / capability | Your App | Notes |
|--------------------|----------|--------|
| Domain discovery | DISCOVERY, SUBDOMAIN_ENUM, DNS_RESOLUTION | Subdomain list / bruteforce can be driven by project settings |
| Port scanner (Naabu) | PORT_SCAN, PORT_VERIFY, SERVICE_DETECT | Naabu/masscan/nmap in worker |
| HTTP prober (httpx) | HTTP_PROBE | httpx in worker |
| Technology (Wappalyzer) | TECHNOLOGY | Wappalyzer + WhatRuns; config: min_confidence, require_html, cache_ttl |
| Banner grabbing | — | Not a separate scan type; can be added or folded into SERVICE_DETECT |
| Web crawler (Katana) | KATANA | Implemented |
| Passive URL (GAU) | WAYBACKURLS | Wayback + CommonCrawl-style; GAU = getallurls |
| API discovery (Kiterunner) | — | Not implemented; can add scan type + worker |
| Vulnerability (Nuclei) | VULNERABILITY | Nuclei with severity/tags/rate limit in profile |
| CVE enrichment | — | Post-processing / MITRE enrichment service |
| MITRE mapping | MITRE_ENRICHMENT_ENABLED in config | mitre_enrichment_service |
| Security checks | — | Could be a separate scan or part of Nuclei/httpx |

### How to Run Each Scan Type

- **Schedules**: Create a scan schedule (Scans → Schedules) and pick `scan_type` (e.g. `technology`, `port_scan`, `nuclei`, `discovery`, `http_probe`, `katana`, `paramspider`, `waybackurls`, `subdomain_enum`, `dns_resolution`, `screenshot`, `login_portal`, `geo_enrich`).
- **Ad-hoc**: Use the scans API (e.g. `POST /api/v1/scans/adhoc` or by-label) with the desired `scan_type` and targets.
- **Discovery flow**: `POST /api/v1/discovery/full` runs discovery; other scan types are triggered separately or via schedules.

To **ensure all scan types are available** in the UI/API:

1. Expose all `ScanType` enum values in the frontend dropdown for “Scan type” (schedules and ad-hoc).
2. Ensure the worker job_type map in `scanner_worker.py` and `scans.py` includes every `ScanType` you want to run (already done for the list above).
3. Add any **missing** types (e.g. API discovery / Kiterunner, dedicated “security_checks”) as new enum + handler when you need them.

---

## 2. Project Settings

Project settings are stored per **organization** in the `project_settings` table: one row per `(organization_id, module)`, with a JSON `config` column. This gives you 180+ parameters without 180 columns.

### Modules

| Module | Purpose |
|--------|--------|
| `target` | Target domain, subdomain list, verify ownership, Tor, bruteforce |
| `port_scanner` | Naabu: scan type (SYN/CONNECT), top ports, rate limit, CDN exclusion, etc. |
| `http_prober` | httpx: redirects, timeout, tech detection, TLS, JARM, rate limit, etc. |
| `wappalyzer` | **Technology detection**: enabled, min_confidence_threshold (0–100), require_html, auto_update_npm, cache_ttl_seconds |
| `banner_grabbing` | Non-HTTP banner extraction (timeout, threads, max length) |
| `katana` | Crawl depth, max URLs, JS rendering, scope, rate limit, exclude patterns |
| `passive_url` | Wayback/CommonCrawl, max URLs, verify with httpx, year range, etc. |
| `api_discovery` | Kiterunner-style: wordlist, rate limit, status whitelist (for when you add it) |
| `nuclei` | Severity, DAST, template include/exclude, rate limit, concurrency, Interactsh, headless |
| `cve_enrichment` | Enable, data source (NVD/Vulners), max CVEs, min CVSS |
| `mitre_mapping` | Auto-update, CWE/CAPEC inclusion, cache TTL |
| `security_checks` | Network, TLS, headers, auth, DNS, exposed services, application checks |
| `agent` | **AI agent**: LLM provider/model, max iterations, approval toggles, LHOST/LPORT, custom prompts, etc. |
| `scan_toggles` | Enable/disable domain_discovery, port_scan, http_probe, resource_enum, vuln_scan |

### Wappalyzer Implementation

- **Config** (from `project_settings` module `wappalyzer`):
  - `enabled`: if `false`, technology scan job exits early.
  - `min_confidence_threshold`: 0–100; technologies below this are excluded (in `WappalyzerService._analyze_response` and `analyze_url`).
  - `require_html`: if `true`, no HTML body ⇒ return no technologies.
  - `auto_update_npm`: reserved for future (pull Wappalyzer fingerprints from npm).
  - `cache_ttl_seconds`: reserved for future (cache fingerprint or result TTL).
- The **technology scan** worker loads `ProjectSettings.get_config(db, organization_id, MODULE_WAPPALYZER)` and passes it to `run_technology_scan_for_hosts(..., wappalyzer_config=...)`. So Wappalyzer behavior is controlled by project settings.

### Agent (Claude) and Per-Org Overrides

- **Default LLM**: In `backend/app/core/config.py`, `AI_PROVIDER` defaults to `"anthropic"` and `ANTHROPIC_MODEL` to `"claude-sonnet-4-6"`, so the **default agent is Claude**.
- **Per-org overrides**: The `agent` module in `project_settings` stores:
  - `llm_provider`, `llm_model`
  - `max_iterations`, `require_approval_exploitation`, `require_approval_post_exploitation`, `activate_post_exploitation`, `post_exploitation_type`
  - `lhost`, `lport`, `bind_port_on_target`, `payload_use_https`
  - `custom_system_prompts`, `tool_output_max_chars`, `execution_trace_memory`, `brute_force_max_attempts`
- The **orchestrator** currently reads from global `settings` (OPENAI/ANTHROPIC, model, max_iterations, tool output max chars). To fully use per-org agent config, the agent API should pass `organization_id` and the orchestrator should call `ProjectSettings.get_config(db, organization_id, MODULE_AGENT)` and override provider/model and the above fields. Until then, env defaults (Claude) apply.

### Defaults and API

- Defaults for each module are in `backend/app/models/project_settings.py` (`get_default_config(module)`). Reading config merges DB values over defaults.
- **Ensure defaults exist**: When an organization is created or on first use, call `ProjectSettings.ensure_defaults(db, organization_id)` to create one row per module with default JSON.
- **API**: Add routes e.g. `GET /api/v1/organizations/{id}/settings` and `PUT /api/v1/organizations/{id}/settings/{module}` that use `ProjectSettings.get_config` / `set_config` so the webapp can manage project settings.

---

## 3. Database Migration for project_settings

Create the table if it doesn’t exist:

```sql
CREATE TABLE IF NOT EXISTS project_settings (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    module VARCHAR(64) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, module)
);
CREATE INDEX IF NOT EXISTS ix_project_settings_organization_id ON project_settings(organization_id);
CREATE INDEX IF NOT EXISTS ix_project_settings_module ON project_settings(module);
```

---

## 4. Checklist: “All Scan Types” and “Wappalyzer + Claude”

- [ ] **Scan types**: Schedules and ad-hoc UI/API offer all needed types (discovery, subdomain_enum, dns_resolution, port_scan, port_verify, service_detect, http_probe, technology, vulnerability, login_portal, screenshot, paramspider, waybackurls, katana, geo_enrich, full).
- [ ] **Worker map**: Every scan type you offer is mapped to a job type in `scanner_worker.py` and `scans.py` (already done for the list in §1).
- [ ] **Project settings table**: Migration applied; `ProjectSettings.ensure_defaults` run for each org (e.g. on org create or first settings load).
- [ ] **Wappalyzer**: Technology scan reads `wappalyzer` module config; `min_confidence_threshold` and `require_html` are applied; `enabled=false` skips the scan.
- [ ] **Claude**: `AI_PROVIDER=anthropic` and `ANTHROPIC_API_KEY` set; optional per-org overrides via `project_settings.agent` when the agent API/orchestrator is updated to use them.
