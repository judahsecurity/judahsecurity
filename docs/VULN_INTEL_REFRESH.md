# Vulnerability Intelligence — Freshness Gap Analysis & Remediation Plan

This document records the current state of vulnerability-intelligence ingestion,
the gaps that keep it from being continuously updated, and the concrete changes
needed to close them.

**Status:** Phase 1 implemented (§4). Phase 2 (delta-driven rescore) and
phase 3 still pending — **G4 remains open**, so displayed priorities do not yet
move on their own.
**Scope:** `backend/app/services/delphi_enrichment_service.py`,
`backend/app/services/vuln_intel_feeds.py`,
`backend/app/workers/schedule_worker.py`,
`backend/app/services/scoring_pipeline.py`,
`aegis-oracle/internal/modules/enrichers/`, `docker-compose.yml`.

---

## 1. Current state

### 1.1 How feeds refresh today

There is **no scheduled refresh anywhere in the stack**. Three mechanisms exist,
none of them continuous:

| Mechanism | Trigger | Cadence | Location |
|-----------|---------|---------|----------|
| Lazy in-process reload | An API request or a finding enrichment | `DELPHI_REFRESH_HOURS`, default **24h** | `delphi_enrichment_service.py:414` (`ensure_loaded`) |
| `refresh_vuln_intel` CLI | A human typing the command | Manual only | `backend/app/scripts/refresh_vuln_intel.py`, invoked via `aws/ec2-single/manage.sh:180` |
| Schedule worker | 60s loop (`SCHEDULE_CHECK_INTERVAL`) | Runs continuously — but **does not touch vuln intel** | `backend/app/workers/schedule_worker.py:856` |

`ensure_loaded()` is called from only three places: `enrich()`
(`delphi_enrichment_service.py:518`), `status()` (`:1014`), and the manual
`POST /delphi/refresh` (`:1049`). Per-file staleness is `mtime`-based
(`vuln_intel_feeds.py:81`), also defaulting to 24h.

**Consequence:** feeds refresh only when someone hits the API, and at most once
per day. During a quiet period the cache simply ages.

### 1.2 Feeds we ingest

Delphi (Python, `vuln_intel_feeds.py`):

| Feed | URL | Gate |
|------|-----|------|
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` (+ `cisagov/kev-data` GitHub mirror fallback) | always |
| EPSS | `epss.cyentia.com/epss_scores-current.csv.gz` | always — **display only, never affects priority** |
| VulnCheck KEV (community) | `api.vulncheck.com/v3/index/vulncheck-kev` (+ `/v3/backup/`) | needs `VULNCHECK_API_TOKEN`; silently skipped without it |
| CIRCL / Shadowserver honeypot | `vulnerability.circl.lu/api` | `DELPHI_EXTENDED_KEV_ENABLED` |
| CIRCL KEVIntel | `kevintel.com/api/v1/kevs` | `DELPHI_EXTENDED_KEV_ENABLED` |
| ENISA EUKEV | `euvdservices.enisa.europa.eu` | always |

Aegis Oracle (Go, `internal/modules/enrichers/`): Exploit-DB, CXSecurity,
`nomi-sec/PoC-in-GitHub`, `trickest/cve`, AttackerKB, AlienVault OTX,
VulnCheck XDB, CISA Vulnrichment/SSVC, VCDB (Verizon DBIR), Tenable plugin
search, JVN, MITRE ATT&CK mappings.

### 1.3 Feeds that are stubs

| Dataset | State | Location |
|---------|-------|----------|
| **FIRE** | Empty in Go **and** Python **and** the JSON overlay | `fire_ice.go:47`, `delphi_enrichment_service.py:221`, `backend/data/breach_intel/fire_cves.json` |
| **ICE** | **Does not exist.** No list, lookup, or feed — only the filename and a schema comment | `fire_ice.go`, `pkg/schema/exploitation.go:125` |
| Mandiant M-Trends | 14 hardcoded CVEs, last updated M-Trends 2025 | `fire_ice.go:57`, `delphi_enrichment_service.py:187` |
| CrowdStrike GTR | 8 hardcoded CVEs, with a `placeholder: add CVEs from the 2026 report` comment | `fire_ice.go:83`, `delphi_enrichment_service.py:205` |
| Mandiant/CrowdStrike JSON overlays | Both `"cves": []` | `backend/data/breach_intel/` |

`LookupFIRE()` always returns `Found: false`. The `fire_linked` schema field,
the `fire_insurance_loss` signal, the `fire` tag, and the breach-intel score
floor at `delphi_enrichment_service.py:771` are live code paths that **never
execute**.

FIRE's source (`cvedata.com/fire.html`) is described in our comments as Zywave
insurance-carrier loss data. That characterisation is **unverified** — it was
written from the source page, which we have not since been able to reach to
confirm. Verify before building against it.

---

## 2. Gaps

### G1 — No scheduled refresh
Feed freshness depends on user traffic. Fix: move refresh into the schedule
worker, which already runs a continuous loop.

### G2 — The scheduler cannot write the cache
`delphi_cache` is mounted **only on the `backend` service**
(`docker-compose.yml:159`). The `scheduler` container has no such mount, so a
refresh added there today would write to a throwaway container layer and be
invisible to the API.

### G3 — One global cadence for feeds that move at different speeds
`DELPHI_REFRESH_HOURS` applies uniformly. But CISA KEV publishes on weekdays,
EPSS drops once daily around 00:00 UTC, and the CIRCL/Shadowserver honeypot
sightings move continuously. A single 24h knob is simultaneously too slow for
the fast feeds and wasteful for the slow ones.

### G4 — Findings never re-prioritise *(highest impact)*
`scoring_pipeline.py` is a SQLAlchemy `after_insert` hook: it scores a
`Vulnerability` the moment it is created and never again. When a CVE is added
to KEV tomorrow, every finding for it already in the database keeps yesterday's
priority until a human calls `POST /scoring/rescore-all/{organization_id}`
(`app/api/routes/scoring.py:171`). Nothing calls that automatically.

**Fresh feeds plus stale scores produce no visible improvement.** G4 must land
for G1–G3 to be worth anything.

### G5 — Oracle's exploit lookups are per-CVE GitHub code-search calls
Metasploit, Nuclei, VCDB and Vulnrichment are queried through
`api.github.com/search/code?q=<CVE>+repo:...` (see `external.go`). GitHub code
search is rate-limited to roughly 10–30 requests/minute, so these calls do not
scale to bulk re-enrichment and cannot support a delta-driven rescore across a
large finding set.

### G6 — Oracle's curated lists require a redeploy
FIRE / M-Trends / GTR live as compiled-in Go map literals. Updating them is a
code change plus a rebuild, not a data refresh. Python already supports JSON
overlays (`load_breach_overlay`); Go does not.

### G7 — CXSecurity is scraped HTML
`cxsecurity.go` parses `cxsecurity.com/cveshow/<CVE>` HTML with regexes
(`_CX_WLB_HREF_RE`, `_CX_TITLE_RE`). There is no open feed, so this breaks
silently whenever the page markup changes.

---

## 3. Prior art — `kevinmhorvath/exploit-availability-check`

A standalone tool answering "how ready-made is the tooling to exploit this
today?" Worth noting because of two design choices, not its source list.

**Its sources are a subset of ours:** CISA KEV, EPSS, Metasploit, Nuclei
Templates, Exploit-DB, `nomi-sec/PoC-in-GitHub`, `trickest/cve`. We already
ingest all seven, plus VulnCheck, CIRCL/Shadowserver, KEVIntel, ENISA, VCDB,
Project Zero, AttackerKB, OTX and SSVC. It deliberately excludes Packet Storm,
CXSecurity and 0day.today for lack of open feeds — which is a direct comment on
**G7**, since we scrape CXSecurity anyway.

**Two ideas worth adopting:**

1. **Bulk-download-and-cache instead of per-CVE API calls.** It pulls roughly
   35 MB once, caches for 24h, and then answers sub-second offline. This is
   strictly better than our GitHub code-search-per-CVE approach for Metasploit
   and Nuclei (**G5**) and is a prerequisite for bulk rescore.
2. **A normalised exploit-maturity tier**: `weaponized` → `public working
   exploit` → `PoC only` → `none`, reported separately from in-the-wild status.
   We expose the raw signals (`MetasploitAvailable`, `PublicPOCCount`,
   `ExploitDBFound`, `VulnCheckMaxMaturity`) but never fuse the free sources
   into a single tier. `AttackerDiscoverabilityTier` answers a different
   question — "can an attacker detect this remotely?" — not "how good is the
   available exploit code?"

Its 24h cache TTL matches ours, so it offers no freshness advantage.

---

## 4. Remediation plan

Ordered by dependency. Phase 1 and 2 are the committed scope; phase 3 is
follow-on.

### Phase 1 — Continuous refresh ✅ *implemented*

1. **Mount the cache on the scheduler.** `delphi_cache:/app/data/delphi_cache`
   plus `DELPHI_CACHE_DIR`, `VULN_INTEL_REFRESH_ENABLED` and
   `VULNCHECK_API_TOKEN` added to the `scheduler` service in
   `docker-compose.yml`, so worker and backend share one directory.
   *(G2 — blocked everything else.)*
2. **`run_vuln_intel_refresh()` added to `schedule_worker.run()`**, gated by
   `VULN_INTEL_REFRESH_ENABLED`. Blocking `urllib` fetchers run via
   `asyncio.to_thread` so the 60s loop stays responsive; each feed's timestamp
   is recorded *before* the await so a slow or failing feed is not retried every
   tick. *(G1)*
3. **Per-feed cadences** in `DEFAULT_FEED_INTERVAL_MINUTES`
   (`vuln_intel_feeds.py`), each overridable via `VULN_INTEL_INTERVAL_<FEED>`
   in minutes, with `DELPHI_REFRESH_HOURS` demoted to a fallback default:

   | Feed | Proposed interval | Rationale |
   |------|------------------|-----------|
   | CIRCL/Shadowserver, KEVIntel | 15–30 min | Continuously updated; closest thing to real-time we have |
   | CISA KEV | 1h | Weekday publication, no fixed hour |
   | EPSS | 6h | Single daily drop ~00:00 UTC |
   | VulnCheck KEV backup | 24h | Large download, token-gated |
   | ENISA EUKEV | 6h | Low churn |

   *(G3)*

4. **Cross-process cache reload.** `ensure_loaded()` now compares the on-disk
   KEV/EPSS mtimes against its last in-memory load and re-reads from disk when
   the worker has refreshed them. Without this the API process would keep
   serving its in-memory copy for up to `DELPHI_REFRESH_HOURS`, making the whole
   of phase 1 invisible. Reloading is network-free, and if the worker stops
   touching files the service falls back to its own timer-driven network fetch.

**Not yet closed by phase 1:** G4 below. Feeds are now fresh, but no displayed
priority changes until something re-scores existing findings.

### Phase 2 — Delta-driven rescore

4. **Diff each refresh against the previous cache** and enqueue *only* findings
   whose CVE newly gained an exploitation signal into the existing scoring
   pipeline. Scoped to the delta, this is far cheaper than `rescore-all` and is
   what actually makes priorities move without human intervention. *(G4)*

### Phase 3 — Follow-on

5. Replace GitHub code-search lookups with cached bulk mirrors of the Metasploit
   module list and the Nuclei template index. *(G5)*
6. Extend the Go enrichers to read the same JSON overlays Python already
   supports, so curated lists update without a redeploy. *(G6)*
7. Refresh Mandiant M-Trends and CrowdStrike GTR to the 2026 reports.
8. Add a fused exploit-maturity tier over the free sources (see §3).
9. Decide FIRE/ICE: either populate FIRE from a verified export, or rename
   `fire_ice.go` and drop the dead signals so the schema stops implying a
   capability we do not have.

---

## 5. Expectation setting: "real time" has an upstream ceiling

CISA KEV is a daily-ish JSON drop; EPSS is a once-daily CSV. No amount of
polling makes those stream. The achievable target is **minutes behind
publication**, not live. The only genuinely fast-moving sources available to us
are the CIRCL/Shadowserver honeypot sightings and VulnCheck — and VulnCheck
requires `VULNCHECK_API_TOKEN`, which is currently unset in the default
configuration, causing that path to be skipped entirely
(`refresh_vuln_intel.py`, "skipping VulnCheck (no token)").
