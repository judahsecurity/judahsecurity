# The proof gate (`agent/finding_oracle.py`)

Every finding reported as **CONFIRMED** must carry a machine-checkable *proof
token* produced by a tool during the run. Anything else is downgraded to
**NEEDS_EVIDENCE** — reported for triage, never as confirmed — no matter how
confident the agent's prose is. This is the generalization of the flag oracle
to all findings, and it is what makes "confirmed" mean the same thing to the
harness and to a human.

## Proof-token kinds and producers

| Kind | Producer | Verified when |
|---|---|---|
| `flag` | `agent.flag_oracle` | the expected/benchmark flag appeared in a real tool response |
| `response_diff` | `replay_request` | an identity change (strip_auth / set_headers) still returned the same 2xx body — the broken-access-control signature |
| `browser_exec` | `test_dom_xss` | a payload actually executed JS in a real Chromium (dialog fired / `window.__vanguard_xss` set) |
| `oob` | `oob_probe` + `oob_check` (`agent.oob_oracle`) | a correlated out-of-band callback fired to a host we control — proof for blind SSRF/RCE/XXE/SSTI. See `docs/oob-oracle.md`. |

A token counts only when `verified=True`; producers set that flag only when the
evidence meets the bar, so registering a token *is* the proof assertion.

## How a finding is confirmed

`grade_finding` confirms a finding when a verified token:

1. is cited by id in `finding["proof_token_id"]`, **or**
2. has a `subject` (normalized host+path) that correlates with the finding's
   `endpoint`/`url`, **or**
3. is a `flag` token whose flag string appears in the finding.

Otherwise → `NEEDS_EVIDENCE` with the reason "run the matching oracle to earn
CONFIRMED".

## In the pipeline

`run_pentest.py` grades `merged_findings` after validation, writes
`proof_gate_<session>.json`, prints a `PROOF GATE: N/M` banner, and leads the
run summary with a deterministic `## Proof Gate` table (generated, not LLM
prose). On the hallucinated-report failure mode — findings with no tool-produced
evidence — every row is `NEEDS_EVIDENCE`, which is the point.

## Documenting findings

The run writes two documentation artifacts (the names from CLAUDE.md) into the
output dir, each finding carrying its gate verdict:

- `findings_<session>.json` — structured: every finding + `verification`
  (status, proof token ids, reason).
- `VULN-FINDINGS_<session>.md` — human-readable, grouped by severity, with a
  ✅ CONFIRMED / ⚠️ NEEDS_EVIDENCE badge and the proof tokens per finding.

`build_findings_document(findings, target=...)` and `findings_markdown(doc)`
build these; both are deterministic (no LLM prose).

## Submission governance

At `ASMBridge.flush()`, every `type == "vulnerability"` finding is stamped with
its gate verdict before it is sinked or submitted:

- a `proof:confirmed` / `proof:needs_evidence` tag and the verdict in
  `raw_data.verification`;
- a finding that *claims* `confidence: "confirmed"` but has no proof token is
  demoted to `confidence: "needs_evidence"` (tagged `downgraded:no_proof`) —
  **impact/severity is left intact; only the trust axis is corrected**, so an
  unproven finding can never leave the harness labelled confirmed.

Inventory findings (subdomain/port/url/…) are untouched. Disable with
`AEGIS_PROOF_GATE_SUBMISSION=false`.

## Object-id IDOR caveat

`set_query` object-id swaps are recorded but **not** auto-verified: same-vs-
different body under another id needs two-account reasoning, so that stays with
the analyst. Identity-change BAC (strip_auth / set_headers) is auto-verified.
