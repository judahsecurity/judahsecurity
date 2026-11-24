# Vanguard → Prowl capability parity

Status: audit of 2026-11-24. Nothing in Vanguard has been deleted. Use this
as the checklist before removing any Vanguard module: a row may only be
deleted once its gap is ported (with tests) or explicitly dropped.

Legend: **MISSING** = no Prowl equivalent; **PARTIAL** = narrower in Prowl;
"pc" = `aegis-vanguard/prowl_client.py`.

## Hard blockers (deleting breaks something today)

| Module | Live caller | Effect of deletion |
|---|---|---|
| `aegis-vanguard/validate_finding.py` | `backend/app/workers/scanner_worker.py` `handle_validate_finding._run_vanguard` (modes `auto`/`docker`/`subprocess`; compose default `AEGIS_VALIDATOR_MODE=auto`) | Agent, LLM red-team and manual findings can no longer be re-confirmed; native validator refuses them by design (`finding_revalidation_service.py`) |
| `aegis-vanguard/agent/finding_lifecycle.py` | `run_pentest.py` Phase 2b, `coverage.apply_findings` | ImportError in the autonomous CLI |
| `aegis-vanguard/agent/session_ops.py` | `agent/core.py`, `run_pentest.py` | Not identity code: compaction, spend cap, `--load` for the CLI |
| `agent/identities.py`, `identity_sessions.py`, `oob.py` | `agents.py`, `owasp_hunters.py`, `hunt_patterns.py`, `run_pentest.py` | CLI hunters lose tools |

## Finding verification

Gaps (Vanguard `validate_finding.py` / `finding_lifecycle.py` vs Prowl
`independent_verify.py`, `proof_policy.py`, `finding_gate.py`,
`external_candidates.py`):

1. Deterministic service/port logical-sanity auto-FP (`_logical_sanity_check`, `sanity_flags`) — **MISSING**.
2. `template_yaml` → `template_logic_issue` diagnosis that drives `NUCLEI_AUTO_REFINE_ON_FP` and detection feedback in `scanner_worker` — **MISSING**.
3. Verification of non-HTTP findings (host:port services, secrets, manual steps) and nuclei re-runs — **MISSING** (pc rejects non-HTTP targets).
4. `still_open` (remediated vs never real), `confidence`, verifier `recommended_severity`/downgrade — **MISSING** (Prowl only caps severity).
5. Read-only verification — Prowl intake mutates the session and may publish.
6. Batch decisions and `candidate/validated/rejected` states used by `run_pentest.py`.
7. Operator knobs: model, max turns, max risk, stdin finding, `--output`; exit-code contract.
8. Works with only an LLM key; Prowl needs platform, JWT, a session with a run snapshot, target in seed scope, <25 external candidates.

Prowl is stronger at: per-class proof kinds, independent verifier, root-cause
dedup, publication gate.

Tests to write before deletion: logical sanity, verdict extraction, field
normalisation, exit codes, `scanner_worker` auto-escalation without the
validator. Port `tests/test_finding_lifecycle.py`.

## OOB and identities

Closed: pc now hands named identities to Prowl (`identities`,
`start --identity-file`, `har`, `capture-token`). Logins run locally with
`agent/identity_sessions.py`; only session material reaches
`POST /agent/sessions/{sid}/identities`. `identity_sessions.py` therefore stays.

Still open on the Prowl side:

Identity gaps inside a Prowl run: `{{csrf}}` substitution/refresh;
auto re-login on 401/403 (session expiry means re-running `identities`); non-GET and fuzzy-similarity authz diff with an
anonymous leg.

OOB gaps: generic webhook/self-hosted collector (`AEGIS_OOB_DOMAIN`,
`AEGIS_OOB_POLL_URL`, `AEGIS_OOB_POLL_KEY`) and multi-schema parsing
(Prowl is interactsh-only); operator default server/token; Log4Shell JNDI and
curl-RCE payloads. Prowl is stronger at: persistent interactsh sessions,
in-request callback placement, SQLi OOB across 4 DB families, SMTP sink, XXE.

Also missing in pc: `--load` (prior session), `execute_interactsh` access.

## Hunters, coverage, brain, probes

Hunters with no Prowl specialist: grpc, nodejs (server-side prototype
pollution), deserialization, m365_entra, okta, sharepoint, enterprise_vpn,
vcenter. Playbook text only: spring, laravel, nextjs. Thin: websocket CSWSH,
aspnet ViewState/axd/NTLM, supply-chain GHA, cloud_iam. Their surface-signal
tables (`owasp_hunters.py`) have no Prowl counterpart.

Coverage ledger (`coverage.py` vs `coverage_cells.py`): monotonic transition
guard (Prowl lets `finding` be overwritten to `tested_clean`); `candidate` and
`rejected` states; `auth` class; broader crlf/csrf/xxe planning; auto-ingest of
free-form probe output. Do not port the Vanguard bug where `pending()` skips
`inconclusive`.

Request ledger: response auto-classification, adaptive hints, filter by
class, diff of stored request ids.

Brain: WAF profile, exhausted techniques per endpoint, effective payloads,
cross-run memory keyed by target. Fan-out: `cross_validated` agreement flag.

Probes: ad-hoc probing of an arbitrary URL/location (every Prowl scoped probe
needs a leased cell); header/cookie/JSON locations for SSTI/cmdi/traversal/
CRLF/redirect; server-side prototype pollution; GraphQL introspection/
suggestions/batching; `.git` dump with credential extraction.

Other: local-checkout SAST (grep/read source, three SAST agents),
`techniques.json` prior art, CWE remediation `advise`, VulnCheck, offline
mode (`netmode.py`), `fingerprint_gitlab`, mail security, third-party vendors.

pc also cannot choose specialists, seed an input surface/coverage plan,
export coverage cells, or call non-recon tools.

Prowl is stronger at: leased coverage cells, deterministic scoped probes,
JWT lanes, smuggling, isolated custom-probe runner, content shield.

## Scanner wrappers (step 2)

The two sides do different jobs: Vanguard `run_*` build fixed argv, parse and
submit through `ASMBridge`; backend MCP `_execute_*` pass free-form args
through Lictor/Augur and return raw output, with parsing in worker services.
Unifying means a core of typed builders + parsers returning a `Result`, with
MCP and the bridge as adapters.

Only in Vanguard: parsers for nikto, wafw00f, cmseek, wpscan findings; tlsx
grading; security headers/CORS; third-party vendor intel; mail intel (BIMI,
MTA-STS, DANE); smart sqlmap wrapper and `_augment_form_body`; arjun
inconclusive semantics; input-surface discovery (forms, JS fetch templates);
GitLab hash fingerprint; katana `-fx`; xsstrike `--blind`.

Decisions needed: argv vs free-form args; return shape; timeout semantics and
defaults; sync vs async; where scope is enforced; secret redaction (Vanguard
sends raw secrets to ingest — adopt backend redaction); severity mapping;
binary resolution (Vanguard can hit the Python `httpx` CLI).

Consolidate the backend's own duplicates first: trufflehog
(`trufflehog_service` vs core hermes); ProjectDiscovery tools
(`projectdiscovery_service` vs per-tool services); gitleaks.

Known bugs found during the audit:

- Fixed: shell injection in Vanguard `run_waybackurls`, `run_gau`, `run_cmseek`.
- Open: `run_swagger_spec_discovery` / `run_autoswagger` build `Finding(tool=…)` (TypeError); `run_sast_secrets` calls `submit_finding` with kwargs; lossy argus/atlas/hermes/janus re-submission drops url/cwe/tags/raw_data and atlas IPs; `check_gitleaks` requires `.git` but passes `--no-git` and reads stdout; Vanguard JS secret scan and jsluice submit raw secrets; `asm_bridge.py` has a fallback copy of `Finding` that can drift; takeover emits a `safe` finding per host.

Most parsers on both sides are untested: add golden-output tests per tool
before moving it.
