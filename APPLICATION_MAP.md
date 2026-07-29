# Application Map

<p align="center">
  <strong>Visual overview of The Force Security ASM Platform</strong>
</p>

---

## 📍 Navigation Map

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                   ASM Platform                                    │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                   │
│  ┌──────────────────┐                                                            │
│  │     SIDEBAR      │     ┌──────────────────────────────────────────────────┐   │
│  │                  │     │                   MAIN CONTENT                    │   │
│  │  ┌────────────┐  │     │                                                   │   │
│  │  │ Dashboard  │──┼────▶│  /dashboard - Metrics, World Map, Charts         │   │
│  │  └────────────┘  │     │                                                   │   │
│  │  ┌────────────┐  │     │  ┌────────────────────────┬─────────────────────┐│   │
│  │  │   Orgs     │──┼────▶│  │  Security Overview     │  Remediation Eff.   ││   │
│  │  └────────────┘  │     │  │  • Critical: X         │  • MTTR: X days     ││   │
│  │  ┌────────────┐  │     │  │  • High: X             │  • Trend: ↑↓        ││   │
│  │  │  Assets    │──┼────▶│  │  • Total Assets: X     │  • Exposure: X%     ││   │
│  │  └────────────┘  │     │  └────────────────────────┴─────────────────────┘│   │
│  │  ┌────────────┐  │     │                                                   │   │
│  │  │ Inventory  │──┼────▶│  /inventory - CIDR Blocks, Domains, M&A          │   │
│  │  └────────────┘  │     │                                                   │   │
│  │  ┌────────────┐  │     │  ┌───────────────────────────────────────────────┐│   │
│  │  │   Graph    │──┼────▶│  │           World Map (Leaflet)                 ││   │
│  │  └────────────┘  │     │  │       • Asset locations by geo                ││   │
│  │  ┌────────────┐  │     │  │       • Click to filter by country            ││   │
│  │  │ Findings   │──┼────▶│  └───────────────────────────────────────────────┘│   │
│  │  └────────────┘  │     │                                                   │   │
│  │  ┌────────────┐  │     └──────────────────────────────────────────────────┘   │
│  │  │ Exceptions │──┼────▶  /exceptions - Accepted risks & false positives       │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │Remediation │──┼────▶  /remediation - Playbooks & CWE guidance              │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │Screenshots │──┼────▶  /screenshots - Visual gallery                        │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │   Scans    │──┼────▶  /scans - Scan history & details                      │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │ Schedules  │──┼────▶  /schedules - Automated scan config                   │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │   Ports    │──┼────▶  /ports - Open port results                           │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │ Discovery  │──┼────▶  /discovery - Subdomain & asset discovery             │
│  │  └────────────┘  │                                                            │
│  │  ┌────────────┐  │                                                            │
│  │  │   Agent    │──┼────▶  /agent - AI security agent chat                      │
│  │  └────────────┘  │                                                            │
│  │                  │     ┌─ Admin Only ──────────────────────────────────────┐   │
│  │  ┌────────────┐  │     │                                                   │   │
│  │  │   Users    │──┼────▶│  /users - User management                        │   │
│  │  └────────────┘  │     │                                                   │   │
│  │  ┌────────────┐  │     │                                                   │   │
│  │  │ Settings   │──┼────▶│  /settings - API keys, org config                │   │
│  │  └────────────┘  │     │                                                   │   │
│  │                  │     └──────────────────────────────────────────────────┘   │
│  └──────────────────┘                                                            │
│                                                                                   │
│  Additional pages (no sidebar link):                                             │
│  • /login          - Authentication page                                         │
│  • /domains        - Domain detail views                                         │
│  • /netblocks/{id} - Netblock detail views                                       │
│  • /wayback        - Historical URL browser                                      │
│  • /detectflow     - Detection flow visualization                                │
│                                                                                   │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Inventory Page Structure

```
/inventory
├── Tab: CIDR Blocks (/inventory?tab=netblocks)
│   ├── Summary Cards (Total IPs, In Scope, Owned)
│   ├── Discover Netblocks Button (WhoisXML API)
│   ├── Netblock Table
│   │   ├── CIDR Notation
│   │   ├── IP Count
│   │   ├── Ownership Status
│   │   ├── In Scope Toggle
│   │   └── Actions (View, Edit)
│   └── Bulk Actions (Set Scope)
│
├── Tab: Domains (/inventory?tab=domains)
│   ├── Summary Cards (Total, Valid, Suspicious, Parked)
│   ├── Validation Status Indicators
│   ├── Enrich DNS Button (WhoisXML API)
│   ├── Domain Table
│   │   ├── Domain Name
│   │   ├── Validation Status (✓ Valid, ⚠ Suspicious, 🅿 Parked)
│   │   ├── DNS Records (A, MX, NS, TXT)
│   │   ├── Mail Providers
│   │   ├── Security Features (SPF, DMARC, DKIM)
│   │   ├── In Scope Toggle
│   │   └── Actions
│   └── Bulk Actions (Validate, Set Scope)
│
└── Tab: M&A (/inventory?tab=acquisitions)
    ├── Summary Cards (Total Acquisitions, Domains Found, Pending Integration)
    ├── Import from Tracxn Button
    ├── Add Manual Acquisition Button
    ├── Acquisition Table
    │   ├── Target Company
    │   ├── Domain
    │   ├── Industry
    │   ├── Acquisition Date
    │   ├── Status (Completed, Pending, Integrating)
    │   ├── Domains Discovered
    │   └── Actions (Discover Domains, View Assets)
    └── Discover Domains Dialog (Whoxy reverse WHOIS)
```

---

## 🔍 Asset Detail Page

```
/assets/{id}
┌──────────────────────────────────────────────────────────────────────────────┐
│  Asset Header: {hostname/IP}                                                  │
│  Asset ID: {uuid}                                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Score Cards                                                         │    │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────┐  ┌───────────────┐  │    │
│  │  │   ARS    │  │   ACS    │  │  Key Drivers   │  │ Vulnerabilities│  │    │
│  │  │  0/100   │  │  5/10    │  │  device_class  │  │      0         │  │    │
│  │  │ Progress │  │ Editable │  │  confidence    │  │                │  │    │
│  │  └──────────┘  └──────────┘  └────────────────┘  └───────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Tabs                                                                │    │
│  │  [Details] [Findings] [Open Ports] [Activity] [Mitigations]         │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  Details Tab:                                                                 │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────┐     │
│  │ Asset Properties         │  │ Network & Location                    │     │
│  │ • System Type            │  │ • Netblock: 131.200.0.0/16           │     │
│  │ • Operating System       │  │ • Country: United States             │     │
│  │ • Device Class           │  │ • City: Milwaukee                    │     │
│  │ • Device Subclass        │  │ • ISP: Rockwell Automation           │     │
│  │ • Public: Yes/No         │  │ • ASN: AS12345                       │     │
│  │ • IPv4 Addresses         │  │                                       │     │
│  └──────────────────────────┘  └──────────────────────────────────────┘     │
│                                                                               │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────┐     │
│  │ Last Seen                │  │ DNS Records                           │     │
│  │ • Scan Name              │  │ • A Records: 1.2.3.4                 │     │
│  │ • Last Scan ID           │  │ • MX Records: mail.domain.com        │     │
│  │ • Last Seen: Jan 12      │  │ • NS Records: ns1.provider.com       │     │
│  │ • First Seen: Oct 27     │  │ • TXT Records: v=spf1...             │     │
│  │ • Last Scan Target       │  │ • Mail Provider: Google Workspace    │     │
│  └──────────────────────────┘  │ • Security: SPF ✓, DMARC ✓          │     │
│                                 └──────────────────────────────────────┘     │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │ Discovery Path                                                       │    │
│  │ ┌────────────┐    ┌────────────┐    ┌────────────┐                  │    │
│  │ │  Source     │───▶│  Method    │───▶│   Asset    │                  │    │
│  │ │ subfinder   │    │ subdomain  │    │ host.com   │                  │    │
│  │ └────────────┘    └────────────┘    └────────────┘                  │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🤖 AI Agent Page

```
/agent
┌──────────────────────────────────────────────────────────────────────────────┐
│  AI Security Agent                                          [Status: Online] │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────────────────────────────┐  ┌──────────────────────────────────┐  │
│  │         Mode Selector           │  │         Playbook Library         │  │
│  │  ○ Assist (approval required)   │  │  • Full Recon                    │  │
│  │  ○ Agent  (autonomous)          │  │  • Subdomain Discovery           │  │
│  └─────────────────────────────────┘  │  • Vulnerability Assessment      │  │
│                                        │  • Port Scan Analysis             │  │
│  ┌─────────────────────────────────┐  │  • Technology Fingerprinting     │  │
│  │      Conversation History       │  │  • Certificate Analysis          │  │
│  │  • Previous sessions list       │  │  • Attack Surface Summary        │  │
│  │  • Click to resume              │  └──────────────────────────────────┘  │
│  └─────────────────────────────────┘                                        │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Chat Interface                                                      │    │
│  │                                                                      │    │
│  │  User: "Run a full recon on example.com"                            │    │
│  │                                                                      │    │
│  │  Agent: [thinking...] Analyzing target...                           │    │
│  │         [tool_start] Running subfinder for subdomains               │    │
│  │         [tool_complete] Found 47 subdomains                         │    │
│  │         [tool_start] Running Nuclei vulnerability scan              │    │
│  │         [tool_complete] Found 3 critical, 8 high findings           │    │
│  │                                                                      │    │
│  │  ┌──────────────────────────────┐  (Assist mode only)               │    │
│  │  │  ⚠ Approval Required        │                                    │    │
│  │  │  Agent wants to run Nuclei   │                                    │    │
│  │  │  on 47 targets               │                                    │    │
│  │  │  [Approve] [Deny]           │                                    │    │
│  │  └──────────────────────────────┘                                    │    │
│  │                                                                      │    │
│  │  ┌────────────────────────────────────────────────────────┐         │    │
│  │  │ Type your security question...              [Send ➤]  │         │    │
│  │  └────────────────────────────────────────────────────────┘         │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  Connection: WebSocket (real-time) with REST fallback                        │
│  URL params: ?target=&playbook=&question= (for prefilled queries)            │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🕸️ Graph Page

```
/graph
┌──────────────────────────────────────────────────────────────────────────────┐
│  Attack Surface Graph                              [Sync Data] [Org Select] │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Tabs: [Attack Surface] [Relationships] [Attack Paths] [Vuln Impact]        │
│                                                                               │
│  Attack Surface Tab (PostgreSQL fallback - always available):                │
│  ┌────────────────────┐  ┌────────────────────┐  ┌─────────────────────┐    │
│  │ Risk Distribution  │  │ Discovery Sources  │  │ Entry Points        │    │
│  │ • Critical: X      │  │ • crt.sh: X        │  │ • Open ports: X     │    │
│  │ • High: X          │  │ • subfinder: X     │  │ • Web services: X   │    │
│  │ • Medium: X        │  │ • virustotal: X    │  │ • Login portals: X  │    │
│  │ • Low: X           │  │ • manual: X        │  │                     │    │
│  └────────────────────┘  └────────────────────┘  └─────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────┐  ┌──────────────────────────────────┐    │
│  │ Technologies                   │  │ Top Ports                        │    │
│  │ • Nginx: X assets             │  │ • 443 (HTTPS): X assets         │    │
│  │ • Apache: X assets            │  │ • 80 (HTTP): X assets           │    │
│  │ • WordPress: X assets         │  │ • 22 (SSH): X assets            │    │
│  └────────────────────────────────┘  └──────────────────────────────────┘    │
│                                                                               │
│  Relationships Tab (Neo4j required):                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  Asset selector dropdown → Interactive graph visualization           │    │
│  │                                                                      │    │
│  │  Domain ──▶ Subdomain ──▶ IP ──▶ Port ──▶ Service ──▶ Technology    │    │
│  │                                              │                       │    │
│  │                                              ▼                       │    │
│  │                                        Vulnerability ──▶ CVE        │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Data Flow Diagram

```
                                    ┌──────────────────┐
                                    │       User       │
                                    │    (Browser)     │
                                    └────────┬─────────┘
                                             │
                                             ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              Frontend (Next.js 14)                            │
│                                                                               │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐  │
│  │ Dashboard │ │  Assets   │ │ Inventory │ │  Findings │ │    Agent     │  │
│  │   Page    │ │   Page    │ │   Page    │ │   Page    │ │    Page      │  │
│  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ └──────┬───────┘  │
│        └──────────────┴─────────────┴─────────────┴──────────────┘          │
│                                     │                                        │
│                             ┌───────┴────────┐                               │
│                             │   API Client   │                               │
│                             │  (lib/api.ts)  │                               │
│                             │  Axios + JWT   │                               │
│                             └───────┬────────┘                               │
└─────────────────────────────────────┼────────────────────────────────────────┘
                                      │ HTTP/REST + WebSocket
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              Backend (FastAPI)                                │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                       API Routes (/api/v1/)                          │    │
│  │                                                                      │    │
│  │  ┌──────┐ ┌──────┐ ┌────────┐ ┌───────┐ ┌──────┐ ┌──────────────┐  │    │
│  │  │ auth │ │assets│ │ scans  │ │ vulns │ │ agent│ │   graph      │  │    │
│  │  └──────┘ └──────┘ └────────┘ └───────┘ └──────┘ └──────────────┘  │    │
│  │  ┌──────────────┐ ┌──────────┐ ┌────────┐ ┌──────┐ ┌────────────┐  │    │
│  │  │  discovery   │ │netblocks │ │  ports │ │ mcp  │ │remediation │  │    │
│  │  └──────────────┘ └──────────┘ └────────┘ └──────┘ └────────────┘  │    │
│  │  + 19 more route modules (labels, screenshots, reports, etc.)       │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                     │                                        │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                          Services Layer (55+)                        │    │
│  │                                                                      │    │
│  │  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────┐  │    │
│  │  │ discovery_svc   │  │ nuclei_service   │  │ agent/orchestrator │  │    │
│  │  │ subdomain_svc   │  │ port_scanner_svc │  │ agent/tools        │  │    │
│  │  │ dns_service     │  │ eyewitness_svc   │  │ agent/knowledge    │  │    │
│  │  │ whoxy_service   │  │ katana_service   │  │ mcp/server         │  │    │
│  │  │ tracxn_service  │  │ waybackurls_svc  │  │ graph_service      │  │    │
│  │  │ geolocation_svc │  │ paramspider_svc  │  │ report_service     │  │    │
│  │  │ technology_svc  │  │ ffuf_service     │  │ remediation_svc    │  │    │
│  │  └─────────────────┘  └──────────────────┘  └────────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                     │                                        │
└─────────────────────────────────────┼────────────────────────────────────────┘
                                      │
                   ┌──────────────────┼──────────────────┐
                   │                  │                   │
                   ▼                  ▼                   ▼
          ┌──────────────┐  ┌──────────────┐   ┌──────────────┐
          │  PostgreSQL  │  │    Redis     │   │   Neo4j      │
          │   Database   │  │  Cache/Queue │   │  (optional)  │
          │              │  │              │   │              │
          │  • Assets    │  │  • Sessions  │   │  • Graph     │
          │  • Vulns     │  │  • Job Queue │   │  • Relations │
          │  • Scans     │  │  • Rate Limit│   │  • Attack    │
          │  • Orgs      │  │              │   │    Paths     │
          │  • Agent     │  │              │   │              │
          │    Convos    │  │              │   │              │
          └──────────────┘  └──────────────┘   └──────────────┘
                                                      │
          ┌───────────────────────────────────────────┘
          │
          ▼
   ┌──────────────┐        ┌──────────────────────────────────┐
   │   Workers    │        │       Security Tools Suite       │
   │              │        │                                   │
   │  • Scanner   │───────▶│  Nuclei, Subfinder, HTTPX, DNSX, │
   │  • Scheduler │        │  Naabu, Masscan, Nmap, Katana,   │
   │              │        │  EyeWitness, WaybackURLs,         │
   └──────────────┘        │  ParamSpider, FFUF, TLDFinder     │
                           └──────────────────────────────────┘

   ┌──────────────────────────────────────────────────────────┐
   │                    AI Agent Stack                         │
   │                                                           │
   │  ┌──────────────┐   ┌───────────────┐   ┌────────────┐  │
   │  │  LangGraph   │──▶│  MCP Server   │──▶│  Security  │  │
   │  │ Orchestrator │   │  (tool proxy) │   │   Tools    │  │
   │  └──────┬───────┘   └───────────────┘   └────────────┘  │
   │         │                                                 │
   │         ▼                                                 │
   │  ┌──────────────────────────────────┐                    │
   │  │  LLM Provider                    │                    │
   │  │  • Anthropic Claude (default)    │                    │
   │  │  • OpenAI GPT (alternative)      │                    │
   │  └──────────────────────────────────┘                    │
   └──────────────────────────────────────────────────────────┘

   ┌──────────────────────────────────────────────────────────┐
   │              Aegis Vanguard (external agent)              │
   │                                                           │
   │  aegis-vanguard/  — autonomous ReACT pentest agent        │
   │                                                           │
   │  Orchestrator → Recon → Vuln → Exploit → Report           │
   │         │                                                 │
   │         ▼                                                 │
   │  asm_bridge.py ──POST /api/v1/ingest/findings──▶ ASM DB   │
   │                                                           │
   │  On-demand validation:                                    │
   │  Findings UI → /vulnerabilities/{id}/validate             │
   │            → scanner worker → validate_finding.py         │
   │            → FindingValidation + verdict on Vulnerability │
   │                                                           │
   │  Deploy: standalone Python or Docker (aegis-vanguard:latest)│
   │  Docs:   aegis-vanguard/README.md + DEPLOYMENT.md         │
   └──────────────────────────────────────────────────────────┘
```

---

## 🗄️ Database Schema Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                             PostgreSQL Database                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  CORE TABLES                                                                 │
│  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐             │
│  │ organizations│◀──────│    users     │       │  api_configs │             │
│  │              │       │              │       │              │             │
│  │ • id         │       │ • id         │       │ • service    │             │
│  │ • name       │       │ • email      │       │ • api_key    │             │
│  │ • domain     │       │ • role       │       │ • org_id     │             │
│  └──────┬───────┘       │ • (admin/    │       └──────────────┘             │
│         │               │   analyst/   │                                     │
│         │               │   viewer)    │                                     │
│         │               └──────────────┘                                     │
│         │ 1:N                                                                │
│         ▼                                                                    │
│  ASSET MANAGEMENT                                                            │
│  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐             │
│  │    assets    │◀──────│vulnerabilities│      │   netblocks  │             │
│  │              │       │              │       │              │             │
│  │ • hostname   │       │ • severity   │       │ • cidr       │             │
│  │ • ip_address │       │ • template   │       │ • start_ip   │             │
│  │ • ars_score  │       │ • cvss       │       │ • end_ip     │             │
│  │ • acs_score  │       │ • first_seen │       │ • in_scope   │             │
│  │ • is_live    │       │ • last_seen  │       │ • is_owned   │             │
│  │ • live_url   │       │ • cwe_id     │       │              │             │
│  │ • geo_*      │       │ • is_manual  │       │              │             │
│  │ • metadata   │       │ • asset_id   │       │              │             │
│  └──────┬───────┘       └──────────────┘       └──────────────┘             │
│         │                                                                    │
│         │ M:N / 1:N                                                         │
│         ▼                                                                    │
│  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐             │
│  │    labels    │       │ port_services│       │ technologies │             │
│  │              │       │              │       │              │             │
│  │ • name       │       │ • port       │       │ • name       │             │
│  │ • color      │       │ • protocol   │       │ • version    │             │
│  │ • org_id     │       │ • service    │       │ • category   │             │
│  │              │       │ • asset_id   │       │ (via M:N     │             │
│  └──────────────┘       └──────────────┘       │  join table) │             │
│                                                 └──────────────┘             │
│  SCANNING & SCHEDULING                                                       │
│  ┌──────────────┐       ┌──────────────┐       ┌──────────────┐             │
│  │    scans     │       │scan_schedules│       │ scan_configs │             │
│  │              │       │              │       │              │             │
│  │ • scan_type  │       │ • frequency  │       │ • name       │             │
│  │ • status     │       │ • scan_type  │       │ • settings   │             │
│  │ • targets    │       │ • next_run   │       │ • org_id     │             │
│  │ • results    │       │ • is_active  │       │              │             │
│  │ • org_id     │       │ • org_id     │       │              │             │
│  └──────────────┘       └──────────────┘       └──────────────┘             │
│                                                                               │
│  ┌──────────────┐       ┌──────────────┐                                    │
│  │scan_profiles │       │ screenshots  │                                    │
│  │              │       │              │                                    │
│  │ • name       │       │ • url        │                                    │
│  │ • settings   │       │ • image_path │                                    │
│  └──────────────┘       │ • asset_id   │                                    │
│                          └──────────────┘                                    │
│                                                                               │
│  M&A / ACQUISITIONS                                                          │
│  ┌──────────────┐       ┌──────────────────┐                                │
│  │ acquisitions │       │finding_exceptions│                                │
│  │              │       │                  │                                │
│  │ • target_name│       │ • vuln_id        │                                │
│  │ • domain     │       │ • justification  │                                │
│  │ • status     │       │ • status         │                                │
│  │ • tracxn_id  │       │ • org_id         │                                │
│  │ • org_id     │       │                  │                                │
│  └──────────────┘       └──────────────────┘                                │
│                                                                               │
│  AI AGENT                                                                    │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐           │
│  │agent_conversations│  │  agent_notes    │  │agent_knowledge  │           │
│  │                  │  │                  │  │                  │           │
│  │ • session_id    │  │ • title          │  │ • title          │           │
│  │ • messages      │  │ • content        │  │ • content        │           │
│  │ • mode          │  │ • conversation_id│  │ • org_id         │           │
│  │ • org_id        │  │                  │  │                  │           │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘           │
│                                                                               │
│  SETTINGS                                                                    │
│  ┌──────────────────┐                                                       │
│  │project_settings  │                                                       │
│  │                  │                                                       │
│  │ • module         │                                                       │
│  │ • settings (JSON)│                                                       │
│  │ • org_id         │                                                       │
│  └──────────────────┘                                                       │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔌 External API Integrations

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          External API Integrations                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  FREE SOURCES (No API Key Required)                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────┐  │    │
│  │  │   crt.sh   │ │  Wayback   │ │  RapidDNS  │ │      M365      │  │    │
│  │  │ Cert Trans │ │  Machine   │ │  DNS Enum  │ │   Fed Auth     │  │    │
│  │  │            │ │            │ │            │ │                │  │    │
│  │  │ Subdomains │ │ Historical │ │ Subdomains │ │ Domains        │  │    │
│  │  │ from SSL   │ │ URLs       │ │            │ │                │  │    │
│  │  └────────────┘ └────────────┘ └────────────┘ └──────────────────┘  │    │
│  │                                                                      │    │
│  │  ┌────────────┐                                                      │    │
│  │  │Common Crawl│                                                      │    │
│  │  │ Web Archive│ (optional S3 index for ~100ms lookups)               │    │
│  │  └────────────┘                                                      │    │
│  │                                                                      │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  PAID SOURCES (API Key Required - Configure in Settings)                     │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │    │
│  │  │ VirusTotal │ │  WhoisXML  │ │   Whoxy    │ │   Tracxn   │       │    │
│  │  │            │ │    API     │ │            │ │            │       │    │
│  │  │ Subdomains │ │ • Netblocks│ │ • Reverse  │ │ • M&A Data │       │    │
│  │  │  database  │ │   by org   │ │   WHOIS    │ │ • Company  │       │    │
│  │  │            │ │ • DNS data │ │ • Domain   │ │   domains  │       │    │
│  │  │            │ │ • A/MX/NS  │ │   discovery│ │            │       │    │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘       │    │
│  │                                                                      │    │
│  │  ┌────────────┐ ┌────────────┐                                      │    │
│  │  │AlienVault  │ │   Tavily   │                                      │    │
│  │  │   OTX      │ │            │                                      │    │
│  │  │            │ │ Agent web  │                                      │    │
│  │  │ Threat     │ │ search for │                                      │    │
│  │  │ intel,     │ │ CVE/exploit│                                      │    │
│  │  │ Passive DNS│ │ research   │                                      │    │
│  │  └────────────┘ └────────────┘                                      │    │
│  │                                                                      │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  AI PROVIDERS (for Agent - configure in .env)                                │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  ┌──────────────────┐  ┌──────────────────┐                         │    │
│  │  │    Anthropic     │  │     OpenAI       │                         │    │
│  │  │   Claude (def)   │  │    GPT (alt)     │                         │    │
│  │  │                  │  │                  │                         │    │
│  │  │ ANTHROPIC_API_KEY│  │ OPENAI_API_KEY   │                         │    │
│  │  └──────────────────┘  └──────────────────┘                         │    │
│  │                                                                      │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Scan Types & Workflows

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                             Scan Type Workflows                               │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  FULL RECON PIPELINE (scan_type: "full")                                     │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  ┌────────────┐  ┌───────────┐  ┌──────────┐  ┌─────────────────┐  │    │
│  │  │  Domain    │─▶│ Port Scan │─▶│  HTTP    │─▶│   Resource      │  │    │
│  │  │ Discovery  │  │ Naabu/    │  │  Probe   │  │ Enumeration     │  │    │
│  │  │ (Phase 1)  │  │ Masscan   │  │ (Phase 3)│  │ Katana/Wayback  │  │    │
│  │  └────────────┘  │ (Phase 2) │  └──────────┘  │ ParamSpider     │  │    │
│  │                  └───────────┘                 │ (Phase 4)       │  │    │
│  │                                                └────────┬────────┘  │    │
│  │                                                         ▼           │    │
│  │                                                ┌─────────────────┐  │    │
│  │                                                │  Vuln Scan      │  │    │
│  │                                                │  Nuclei 8000+   │  │    │
│  │                                                │  (Phase 5)      │  │    │
│  │                                                └────────┬────────┘  │    │
│  │                                                         ▼           │    │
│  │                                                ┌─────────────────┐  │    │
│  │                                                │  Graph Sync     │  │    │
│  │                                                │  (Neo4j)        │  │    │
│  │                                                └─────────────────┘  │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  INDIVIDUAL SCAN TYPES                                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  Discovery Scan                                                      │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │    │
│  │  │ Domain   │─▶│Subfinder │─▶│  HTTPX   │─▶│ Store as Assets  │    │    │
│  │  │ Input    │  │ Amass    │  │  Probe   │  │ with technologies│    │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    │    │
│  │                                                                      │    │
│  │  Vulnerability Scan                                                  │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │    │
│  │  │ Targets  │─▶│  Nuclei  │─▶│  Parse   │─▶│ Store Findings   │    │    │
│  │  │ (Assets) │  │  8000+   │  │ Results  │  │ with severity    │    │    │
│  │  │          │  │ templates│  │          │  │ + CVE/CWE        │    │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    │    │
│  │                                                                      │    │
│  │  Port Scan                                                           │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │    │
│  │  │ IP/CIDR  │─▶│ Masscan  │─▶│  Nmap    │─▶│ Store Port/Svc   │    │    │
│  │  │ Targets  │  │ Fast scan│  │ Service  │  │ on Assets        │    │    │
│  │  │          │  │          │  │ detect   │  │                  │    │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    │    │
│  │                                                                      │    │
│  │  Screenshot Capture                                                  │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐    │    │
│  │  │  Web     │─▶│EyeWitness│─▶│  Save    │─▶│ Link to Assets   │    │    │
│  │  │ Assets   │  │ Chromium │  │ Images   │  │                  │    │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘    │    │
│  │                                                                      │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Docker Compose Services

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Docker Compose Stack                                │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  CORE SERVICES (always running)                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   frontend   │  │   backend    │  │      db      │  │    redis     │    │
│  │   Next.js    │  │   FastAPI    │  │  PostgreSQL  │  │  Cache/Queue │    │
│  │   :80→3000   │  │   :8000      │  │   :5432      │  │   :6379      │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                               │
│  WORKER SERVICES (always running)                                            │
│  ┌──────────────┐  ┌──────────────┐                                         │
│  │   scanner    │  │  scheduler   │                                         │
│  │  Scan worker │  │ Cron worker  │                                         │
│  │ (root user)  │  │              │                                         │
│  └──────────────┘  └──────────────┘                                         │
│                                                                               │
│  OPTIONAL SERVICES (profiles)                                                │
│  ┌──────────────┐  ┌──────────────┐                                         │
│  │   adminer    │  │    neo4j     │                                         │
│  │   DB Admin   │  │   Graph DB   │                                         │
│  │   :8080      │  │ :7474, :7687 │                                         │
│  │ profile: dev │  │ profile:graph│                                         │
│  └──────────────┘  └──────────────┘                                         │
│                                                                               │
│  SHARED VOLUMES                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ postgres_data │ redis_data │ nuclei_templates │ scan_outputs │         │  │
│  │ screenshots_data │ neo4j_data │ neo4j_logs                            │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Authentication & Authorization Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          Auth Flow                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─────────┐   POST /auth/login    ┌──────────┐   Verify pwd   ┌─────────┐ │
│  │  User   │──────────────────────▶│ Backend  │───────────────▶│   DB    │ │
│  │ Browser │   (email + password)  │ FastAPI  │   (bcrypt)     │  Users  │ │
│  └────┬────┘                       └────┬─────┘               └─────────┘ │
│       │                                 │                                   │
│       │◀────────────────────────────────┘                                   │
│       │   JWT access token (30 min)                                         │
│       │   JWT refresh token (7 days)                                        │
│       │                                                                     │
│       │   Store in Zustand (auth store)                                     │
│       │                                                                     │
│       │   All subsequent requests:                                          │
│       │   Authorization: Bearer <access_token>                              │
│       │                                                                     │
│  RBAC Roles:                                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                                 │
│  │  admin   │  │ analyst  │  │  viewer  │                                 │
│  │ Full     │  │ Read +   │  │ Read     │                                 │
│  │ access   │  │ Write    │  │ only     │                                 │
│  └──────────┘  └──────────┘  └──────────┘                                 │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 📅 Scheduled Scan Frequencies

| Frequency | Interval | Best For |
|-----------|----------|----------|
| Every 15 minutes | 15 min | Critical port monitoring (SSH, RDP) |
| Every 30 minutes | 30 min | High-priority asset checks |
| Hourly | 1 hour | Active vulnerability detection |
| Every 2 hours | 2 hours | Regular service monitoring |
| Every 4 hours | 4 hours | Standard security checks |
| Every 6 hours | 6 hours | Comprehensive port scans |
| Every 12 hours | 12 hours | Full discovery sweeps |
| Daily | 24 hours | Complete vulnerability scans |
| Weekly | 7 days | Deep reconnaissance |
| Monthly | 30 days | Full attack surface review |

---

## 🔄 Recon Pipeline (Full Scan)

| Phase | Name | Tools | Output |
|-------|------|-------|--------|
| 1 | Domain Discovery | Subfinder, crt.sh, Whoxy, TLDFinder | Assets (domains, subdomains, IPs) |
| 2 | Port Scan | Naabu, Masscan, Nmap | PortService records |
| 3 | HTTP Probe | HTTPX | is_live, live_url, http_status |
| 4 | Resource Enumeration | Katana, WaybackURLs, ParamSpider | Endpoints, parameters, JS files |
| 5 | Vulnerability Scan | Nuclei (8000+ templates) | Vulnerability records with CVE/CWE |

After all phases: **Graph Sync** pushes data to Neo4j for relationship modeling.

See [docs/RECON_WORKFLOW.md](docs/RECON_WORKFLOW.md) for detailed phase descriptions.

---

## 🕸️ Neo4j Graph Schema

```
Domain ──HAS_SUBDOMAIN──▶ Subdomain ──RESOLVES_TO──▶ IP ──HAS_PORT──▶ Port
                                │                                        │
                                │ SAME_IP_AS                    RUNS_SERVICE
                                │ (co-hosted)                            │
                                ▼                                        ▼
                           Subdomain                                  Service
                                                                        │
                                                               USES_TECHNOLOGY
                                                                        │
                                                                        ▼
                                                                   Technology
                                                                        │
                                                              HAS_VULNERABILITY
                                                                        │
                                                                        ▼
                                                                  Vulnerability
                                                                   │         │
                                                            REFERENCES   MAPS_TO
                                                                   │         │
                                                                   ▼         ▼
                                                                 CVE      MITRE
```

See [docs/GRAPH_SCHEMA.md](docs/GRAPH_SCHEMA.md) for full schema, Cypher queries, and troubleshooting.

---

## ⚔️ Aegis Vanguard

Autonomous external pentest agent that lives in `aegis-vanguard/` (not inside the Docker Compose stack). It runs recon → vuln → exploit → report via a ReACT multi-agent loop and submits findings to the ASM platform.

| Piece | Role |
|-------|------|
| `run_pentest.py` | Full-target pentest entrypoint |
| `validate_finding.py` | Re-tests one existing finding (true/false positive) |
| `asm_bridge.py` | Batches findings to `POST /api/v1/ingest/findings` |
| `agent/` | Orchestrator, specialized agents, guardrails, tracing |
| Praetorium | Shared Lictor/Censor/Augur guard layer with the platform agent |

**Auth:** create an agent API key (`tfasm_…`) with `agent_type: aegis_vanguard`.  
**Image:** `docker build -f aegis-vanguard/Dockerfile -t aegis-vanguard:latest .`  
**Env (validator worker):** `AEGIS_VALIDATOR_MODE`, `AEGIS_VANGUARD_IMAGE`, `AEGIS_VANGUARD_PATH`, `AEGIS_VALIDATE_MAX_TURNS`, `AEGIS_VALIDATE_TIMEOUT`.

See [aegis-vanguard/README.md](aegis-vanguard/README.md) and [aegis-vanguard/DEPLOYMENT.md](aegis-vanguard/DEPLOYMENT.md).

---

<p align="center">
  <strong>Made with ❤️ by The Force Security</strong>
</p>
