# Aegis Vanguard — Capability Scope (draft)

Candidate capabilities to add to the agent, **built natively in our stack** rather
than by shelling out to third-party binaries. Each one follows the existing shape:

- a pure-Python `run_*` wrapper in `scanners.py` that reuses `_run` / the internal
  HTTP primitives, `ASMBridge`, and `Finding`;
- an agent-facing tool name wired into the relevant hunter tool list in
  `agent/owasp_hunters.py` (or `api_framework_hunters.py` / `enterprise_hunters.py`);
- coverage recorded through `agent/coverage.py` (keyed by endpoint / method /
  parameter / identity / vuln-class) so gaps stay visible;
- shared state (payload queues, notes, exhausted markers) through `agent/brain.py`.

Pattern/wordlist data lives alongside `data/techniques.json`, not hard-coded.

Status legend: **BUILD** (net-new, additive) · **EXTEND** (grow an existing tool) ·
**COVERED** (already present — do not rebuild).

---

## 1. URL-corpus sink classifier  — BUILD · priority: high

**What.** A native pass over the URL/parameter corpus we already collect
(`run_katana`, `run_gau`, `run_waybackurls`) that tags candidate sinks — open-redirect,
SSRF, SQLi, path/LFI, and leaked-secret params — using our own pattern sets. Replaces
the `gf`-pattern idea with an in-house classifier.

**Why.** We gather the corpus but don't *prioritize* it. This feeds hunter target
selection and seeds the coverage ledger with pending rows per (endpoint, param, class)
instead of leaving the fireteam to rediscover sinks.

**Integration.**
- `scanners.py`: `run_corpus_triage(urls, bridge)` → structured `{endpoint, param, classes[], confidence}`.
- Patterns in `data/sink_patterns.json` (our file, versioned).
- Agent tool `triage_url_corpus`, consumed in the recon phase and pushed to
  `brain_add_payload` / coverage `pending` rows.

**Done when.** A recon run emits a ranked sink list, coverage shows those rows as
pending, and at least the injection / open-redirect / SSRF hunters read it for targeting.

---

## 2. Native cloud-storage asset discovery  — BUILD · priority: medium-high

**What.** Pure-Python derivation of likely bucket/container names from the target's
names (org, domains, subdomains) and HTTP probing of S3 / GCS / Azure Blob endpoints.
No AWS CLI, no `s3scanner`.

**Why.** Cloud storage is a real ASM asset class with no counterpart in `scanners.py`
today. Fits the product: discovered buckets become assets/findings via `ASMBridge`.

**Integration.**
- `scanners.py`: `run_cloud_storage_discovery(scope, bridge)` → `Finding` per exposed/listable bucket.
- New coverage asset class `cloud_storage`.
- Recon-phase tool `discover_cloud_storage`; optional `supply_chain_hunter` consumer.

**Constraint.** Read-only probing of in-scope names only. Never enumerate or touch
objects outside the authorized scope.

---

## 3. Secret-surface sweep (consolidation + expansion)  — EXTEND · priority: medium

**What.** Fold our scattered exposure checks (`dump_exposed_vcs`, `run_js_url_secret_scan`,
`run_swagger_spec_discovery`, actuator/`.env`/`.git` probes) into one native sweep that
reports exposed config/secret surfaces as a single finding class.

**Why.** We already do pieces; the agent lacks one coherent "what secrets are reachable
from the outside" capability. This is the **external** surface — distinct from local
`gitleaks` / `run_sast_secrets`, which stay as-is.

**Integration.**
- `scanners.py`: `run_secret_surface(target, bridge)` orchestrating existing probes + a
  small native path list in `data/`.
- Agent tool `sweep_secret_surface`; wired into `auth_hunter` and recon.

---

## 4. Native DNS brute/resolve layer  — BUILD · priority: medium

**What.** Async-DNS subdomain brute + resolution in Python, feeding the validation we
already do (`run_dnsx`, `run_httpx`). Replaces the puredns/massdns/shuffledns idea with
our own resolver pool.

**Why.** Current discovery (`run_subfinder`, `run_amass`, `run_subcat`) is mostly passive.
A controlled active layer widens the surface the hunters see.

**Integration.**
- `scanners.py`: `run_dns_brute(domain, wordlist, resolvers, bridge)` → candidates handed
  to existing `run_dnsx` / `run_httpx`.
- Wordlist + resolver list in `data/` (size-capped, rate-limited).

**Constraint.** Rate-limit and honor scope; this is the noisiest item here.

---

## 5. Archived-parameter expansion  — COVERED

`run_waybackurls` + `run_gau` + `run_arjun` already cover ParamSpider-style discovery.
Don't build a separate tool — fold any gaps into **#1** (the corpus classifier).

## 6. Deep JS analysis  — COVERED

`run_jsluice` + `run_js_url_secret_scan` cover LinkFinder / SecretFinder / Mantra. Any
new secret patterns go into **#3**, not a new tool.

---

## Suggested order

1. **#1 corpus sink classifier** — highest leverage, pure in-house, sharpens every hunter.
2. **#2 cloud-storage discovery** — new asset class, clear ASM/product fit.
3. **#3 secret-surface sweep** — consolidation, mostly reuse.
4. **#4 DNS brute layer** — most infra/rate-limit care; do last.

Cross-cutting for all: register the new tool names in the hunter tool lists, add the
coverage class, and keep every probe behind scope + authorization checks (see the
"Only authorized targets" rule in `CLAUDE.md`).
