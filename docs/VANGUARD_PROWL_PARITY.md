# Vanguard → Prowl capability parity

Status: audit of 2026-11-24. Nothing in Vanguard has been deleted. Use this
as the checklist before removing any Vanguard module: a row may only be
deleted once its gap is ported (with tests) or explicitly dropped.

Legend: **MISSING** = no Prowl equivalent; **PARTIAL** = narrower in Prowl;
"pc" = `aegis-vanguard/prowl_client.py`.

## Hard blockers (deleting breaks something today)

| Module | Live caller | Effect of deletion |
|---|---|---|
| `aegis-vanguard/validate_finding.py` | `backend/app/workers/scanner_worker.py` `route_finding_validation` (modes `auto`/`docker`/`subprocess`). In `auto`, Prowl now re-tests inconclusive HTTP(S) findings in a provable class first (`app/services/agent/prowl_revalidation.py`); Vanguard is the fallback only for findings Prowl cannot take | Non-HTTP, no-proof-class and no-requesting-user findings lose their LLM re-test. Mode `prowl` already runs without Vanguard |
| `aegis-vanguard/agent/finding_lifecycle.py` | `run_pentest.py` Phase 2b, `coverage.apply_findings` | ImportError in the autonomous CLI |
| `aegis-vanguard/agent/session_ops.py` | `agent/core.py`, `run_pentest.py` | Not identity code: compaction, spend cap, `--load` for the CLI |
| `agent/identities.py`, `identity_sessions.py`, `oob.py` | `agents.py`, `owasp_hunters.py`, `hunt_patterns.py`, `run_pentest.py` | CLI hunters lose tools |

## Finding verification

Gaps (Vanguard `validate_finding.py` / `finding_lifecycle.py` vs Prowl
`independent_verify.py`, `proof_policy.py`, `finding_gate.py`,
`external_candidates.py`):

1. Deterministic service/port logical-sanity auto-FP — **closed**: moved to
   `asm_scanner_core/finding_sanity.py`, used by the native validator
   (`finding_revalidation_service`, template detections only) and by
   `validate_finding.py`. It also yields `template_logic_issue` for the
   protocol-mismatch case, which now reaches detection feedback and
   `NUCLEI_AUTO_REFINE_ON_FP` without Vanguard.
2. LLM `template_logic_issue` diagnosis for other template flaws (weak banner or
   version matchers) — **closed**: `native_verifiers.diagnose_template_logic`
   (backend LLM via `custom_template_ai.call_llm`; only with template YAML and a
   false_positive / needs_more_evidence verdict; LLM errors give no diagnosis).
3. Verification of non-HTTP findings — **closed** in the native validator
   (`backend/app/services/native_verifiers.py`): `verify_network_service` (nmap
   `-sV`: the claimed protocol must answer, not just TCP open),
   `verify_secret` (re-fetch the exposing URL, compare the secret fingerprint;
   the secret is never used), `verify_manual` (replay documented curl / raw HTTP
   requests, compare the documented result). Nuclei re-runs were already native.
4. `still_open` (remediated vs never real), `confidence`, `recommended_severity`
   — **closed**: every native verdict carries `remediation_state`
   (`open|remediated|never_real|unknown`); remediated verdicts are not counted as
   detection false positives. `auto` mode escalates to Vanguard only when no
   native verifier owns the finding (`native_verifier` unset) and Prowl cannot
   take it. The former fallbacks are now closed natively or by Prowl, so with
   no Vanguard backend every finding kind ends in a native or Prowl verdict
   (`test_validation_gaps.py::test_every_finding_kind_ends_native_or_prowl_without_vanguard`):
   - Application findings with no proof kind (agent / LLM red-team / manual,
     or endpoints the native validator hands over with `prowl_retest`):
     `prowl_revalidation` retest mode. The candidate enters under
     `external_candidates.RETEST_CLASS` (or `known_cve` / `account_enumeration`),
     which no proof kind confirms; intake accepts it only with
     `allow_retest_class` (never from the public route) and caps it at low.
     Outcomes: refuted with counterevidence (`false_positive`, `remediated`
     when it held before), inconclusive; never `confirmed`.
   - Prose manual findings / steps with no stated result:
     `native_verifiers.verify_manual_extracted` (bounded LLM extraction, at most
     3 same-host GET/HEAD/OPTIONS/POST requests, credential headers dropped,
     every field validated; LLM failure means no extraction). No observable, or a
     derived observable that no longer appears, goes to the Prowl retest.
   - Mixed endpoint probes: `finding_revalidation_service.resolve_mixed_endpoints`
     decides per endpoint (`gone` / `open` / `retest`). Exposure claims are
     confirmed where an endpoint still answers; application claims hand their
     reachable routes to the Prowl retest.
   - Missing nuclei / nmap: needs_more_evidence with
     `error="tool_unavailable:<tool>"` (a crashed nuclei run is
     `tool_failed:nuclei`). Never counted as owned by `route_finding_validation`;
     the scanner worker logs missing tools once at start-up.
5. Read-only verification — **closed for worker re-tests**: `prowl_revalidation`
   runs in a throwaway session with `revalidation_only` set, and `create_finding`,
   `scoped_assessment_publish` and LLM red-team auto-filing refuse to publish while
   it is. Operator `prowl_client verify` still runs in the operator's session.
6. Batch decisions and `candidate/validated/rejected` states used by `run_pentest.py`.
7. Operator knobs: model, max turns, max risk, stdin finding, `--output`; exit-code contract.
8. Works with only an LLM key; Prowl needs platform, JWT, a session with a run snapshot, target in seed scope, <25 external candidates.

Prowl is stronger at: per-class proof kinds, independent verifier, root-cause
dedup, publication gate.

Done: logical sanity (`backend/tests/test_finding_sanity.py`), worker routing
(`test_validation_routing.py`), Prowl re-test mapping and publish refusal
(`test_prowl_revalidation.py`), retest mode, prose extraction, mixed endpoints,
missing tools and the kinds × availability outcome (`test_validation_gaps.py`).
Still to port: `tests/test_finding_lifecycle.py`.

## OOB and identities

Closed: pc now hands named identities to Prowl (`identities`,
`start --identity-file`, `har`, `capture-token`). Logins run locally with
`agent/identity_sessions.py`; only session material reaches
`POST /agent/sessions/{sid}/identities`. `identity_sessions.py` therefore stays.

Still open on the Prowl side:

Identity gaps inside a Prowl run: `{{csrf}}` substitution/refresh;
auto re-login on 401/403 (session expiry means re-running `identities`); non-GET and fuzzy-similarity authz diff with an
anonymous leg.

OOB: closed for `run_oob_callback_workflow`. Collector provider is operator
config (`AEGIS_OOB_PROVIDER=interactsh|http_poll`, `backend/app/services/oob_collectors.py`);
`http_poll` uses `AEGIS_OOB_DOMAIN` / `AEGIS_OOB_POLL_URL` / `AEGIS_OOB_POLL_KEY`
with Vanguard's lenient multi-schema parsing and per-probe token correlation.
Operator default Interactsh server/token: `AEGIS_INTERACTSH_SERVER` /
`AEGIS_INTERACTSH_TOKEN`. JNDI (`jndi_variant`) and curl/wget (`cmdi_command`)
templates: `agent/oob_payload_templates.py`. Still open: manual
`execute_interactsh` register/poll stays Interactsh-only. Prowl is stronger at: persistent interactsh sessions,
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
Ported to `brain_memory.py`: `defense_profile` (fed from every `_http_exchange`
response, plus `record_defense_profile`), `exhausted_techniques` /
`effective_payloads` (via `log_engagement_approach(category=, payload=)`),
cross-run memory in `AEGIS_TARGET_MEMORY_DIR/<org_id>/<sha256(origin)>.json`
(0600, atomic replace, org id and origin re-checked on load, redacted and
bounded, loaded as `prior_target_memory`: context, never proof), and
`FindingCandidate.corroborated_by` for same-root-cause agreement (triage only).

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

Parser registry (ported): `asm_scanner_core.parsers` holds pure parsers for
nikto, wafw00f, cmseek, wpscan, testssl, tlsx, httpx (security headers + CORS),
sqlmap, arjun, xsstrike and katana (`-fx` forms), each returning a
`ParsedResult` (status ok | partial | inconclusive | unavailable, typed
observations, counts). Golden tests: `backend/packages/asm_scanner_core/tests`
(run in the backend suite via `backend/tests/test_scanner_parsers_golden.py`).
Prowl's `MCPServer.call_tool` attaches `result["parsed"]` before Augur; the
agent tool layer prefixes a short summary to the model-facing output and
records each observation as a `parser` attack-graph fact (planning state, not
proof). Vanguard bugs fixed in the port are listed in each parser's docstring;
Vanguard's own `run_*` still parse independently until they switch over.
