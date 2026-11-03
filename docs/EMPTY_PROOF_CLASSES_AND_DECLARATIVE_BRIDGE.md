# Closing the empty proof classes + a declarative operation bridge

This note covers two improvements to PROWL's in-product assessment agent, both
drawn from a comparison with breadth-first tools (e.g. CyberStrikeAI) that
*flag* command injection, traversal, and similar classes but never prove them:

1. **Deterministic validators for classes that previously stayed inconclusive
   forever** — `command_injection` and `path_traversal` (shipped here).
2. **A declarative, signed operation catalog** for the scoped-assessment bridge
   (design only).

The design center stays the same as the rest of the proof policy: a finding is
published only when a hunter proposes a candidate and a **fresh-context
verifier** independently re-derives a *deterministic* proof. Breadth without
that gate is what we are explicitly not copying.

---

## 1. Deterministic validators for the empty classes

### Why they were empty

`backend/app/services/agent/proof_policy.py` maps each vulnerability class to
the set of proof recipes that can confirm it (`PROOFS_BY_CLASS`). Three classes
shipped with an **empty** set:

```python
"command_injection": frozenset(),
"path_traversal": frozenset(),
"csrf": frozenset(),
```

An empty set means `proof_kind_allowed()` rejects every proof kind for that
class, so a candidate can never pass `validate_proof()` and is held
`inconclusive` indefinitely. The agent could *observe* a likely OS-command or
traversal sink but had no sanctioned way to turn that lead into a confirmed
finding. This is exactly the gap that breadth-first scanners fill with
*unverified* output — we close it with verifiable, non-destructive proofs.

`csrf` is intentionally left for a follow-on: a deterministic CSRF proof needs a
same-site cookie + cross-origin state-change differential that reuses the
authz/state-change machinery, and is a larger design than these two.

### command_injection

Two recipes are now allowed:

```python
"command_injection": frozenset({"oob_callback", "command_timing"}),
```

**`oob_callback` (blind / gold standard).** Reuses the existing
out-of-band collaborator infrastructure (`oob_register` → planted
`http_exchange` → `oob_poll`) already used for SSRF and XXE. A blind command
injection that triggers a DNS/HTTP callback (e.g. the canary host planted in an
injectable parameter) produces the same register/plant/poll evidence the
generic `oob_callback` branch already validates — the planted canary domain
must appear in the candidate endpoint request and a matching interaction must
fire from a freshly registered session. No new probe code was required; the
class was simply added to `PROOFS_BY_CLASS`, and the existing XXE special-case
in the `oob_callback` branch is untouched.

**`command_timing` (self-contained, no collaborator).** New probe
`backend/app/services/agent/scoped_assessment/command_injection.py`. It proves a
server is executing an injected shell command by inducing a *bounded, repeatable
sleep* and measuring the response-time separation — modelled directly on
`race_probe.py` / `response_probe.py`:

- The injection template is **operator policy**, not model-generated: an
  in-scope URL carrying a `__PROWL_DELAY__` token where the sleep interval is
  substituted (mirrors `race_probe`'s `__PROWL_NONCE__` cleanup template).
- A **zero-delay control** and a **bounded-delay probe** (`2–8 s`) are each run
  `N` times (`2–5` trials).
- Confirmed only when `min(probe_samples) − max(control_samples) ≥ 0.6 × delay`
  — a repeatable separation that ordinary jitter or a uniformly slow endpoint
  cannot satisfy.
- The payload **only sleeps**; it writes and reads nothing.

`command_timing_proof_valid(result)` is a pure function that re-checks all of
the above from the stored evidence, so the verifier gate never trusts a
hunter-set boolean.

### path_traversal

```python
"path_traversal": frozenset({"path_canary"}),
```

New probe `backend/app/services/agent/scoped_assessment/path_traversal.py`. It
proves directory traversal / LFI by reading an **out-of-root operator
sentinel**:

- `control_url` is a benign in-tree resource; `traversal_url` resolves via
  `../` segments to an operator-nominated file *outside* the served root whose
  `sentinel_marker` is known not to appear in a normal response. Both are
  operator policy.
- Confirmation requires the marker **only** in the traversal response, with
  `2xx`, non-truncated bodies for both. Reuses `http_observe.observe_get`'s
  `reflection_marker` → `reflection_detected` path, so **only booleans and the
  marker's SHA-256 are retained — never file contents.**
- Non-destructive: it is a read differential.

`path_canary_proof_valid(result)` enforces the structural invariants.

### The independent-verification gate (both classes)

Both kinds flow through the existing scoped-evidence branch in
`validate_proof()`, which already requires **distinct, time-ordered hunter and
verifier execution records** of the expected kind against the same candidate
target. The per-class branches add:

| Class | Expected evidence kind | Cross-actor invariants |
|-------|------------------------|------------------------|
| `command_timing` | `scoped_command_timing` | same `parameter`, same `delay_seconds`, **distinct nonces**, same identity, both `proof_confirmed`, both structurally valid |
| `path_canary` | `scoped_path_canary` | same `marker_sha256`, same `traversal_template` + `control_template`, **distinct nonces**, same identity, both confirmed + valid |

`evidence_store.py`'s accepted scoped-proof-kind allowlist was extended with the
two new kinds; their `proven` check is the generic `proof_confirmed is True`.

### What is shipped

**Proof core** (`backend/tests/test_empty_class_proofs.py`, plus an updated
assertion in `test_scoped_proof_policy.py` that previously pinned the *absence*
of a command-injection proof):

- Both probe modules and their pure `*_proof_valid` checkers.
- `PROOFS_BY_CLASS`, `validate_proof` branches + `expected_kind` entries.
- `evidence_store` kind allowlist.

**Live-agent wiring** (so the fireteam actually selects these — the funnel
already emits `command_injection` and `path_traversal` cells via
`vulnerability_catalog.py`, routed to the `injection` specialist, which
previously dead-ended at `unsupported_input`):

1. `scoped_command_timing_assigned` / `scoped_path_canary_assigned` tool methods
   in `tools.py`, registered in the tool map, modelled on `scoped_race_assigned`
   — the model proposes the injection/traversal attempt, but it only fires when
   the path is in an operator allowlist.
2. `set_scoped_assessment_policy` now accepts `command_injection_paths` (approved
   paths for the timing probe) and `path_traversal_sentinels`
   (`[{path, marker}]`, the out-of-root marker is **operator policy**, never
   model-supplied, so the verifier can re-read it and only the marker hash is
   retained in evidence).
3. `_verify_scoped_command_candidate` / `_verify_scoped_path_candidate` replay
   functions in `independent_verify.py`, registered in the verifier dispatch,
   re-run the probe with a fresh nonce in the verifier session.
   `verifier_mission()` surfaces the new proof options automatically.
4. Directive text (`operation_directive.py`) and tool docs (`prompts.py`) point
   the injection specialist at the two recipes and their operator-approval
   requirements.

**Safety posture:** no OS-command gadget catalog or LFI payload list is shipped.
Like `race_probe`, the model forms the exact attempt but the probe refuses any
path the operator has not allowlisted, and the command-timing payload only
induces a bounded sleep while the path-canary read is non-destructive.

### Still open

- `csrf` (the third empty class) — needs a same-site-cookie + cross-origin
  state-change differential reusing the authz/state-change machinery.
- POST-body variants of both recipes (v1 covers the GET/query surface).

---

## 2. A declarative, signed operation bridge (design)

### Problem

`backend/app/services/agent/prowl_service_bridge.py` exposes a **fixed**
`_OPERATIONS` dict (~20 entries). Every new probe means editing that module,
re-threading the allowlist, and re-deploying the bridge. Breadth-first tools
grow their tool surface from declarative YAML recipes + MCP discovery at
runtime; we can borrow that ergonomics **without** weakening the credential and
scope boundary that keeps the model from ever holding admin/hunter/verifier
keys.

### Design

Keep the allowlist; make it **data, signed and loaded**, not code.

```
operations/
  http_sqli_boolean.recipe.json
  scoped_command_timing.recipe.json
  scoped_path_canary.recipe.json
  ...
```

Each recipe declares exactly what the current `_OPERATIONS` entry encodes plus
the guardrails that today live implicitly in the handler:

```jsonc
{
  "name": "scoped_command_timing",
  "version": 3,
  "method": "POST",
  "path": "http/command-timing",
  "class": "probe",                 // observe | probe | submit | memory | coverage
  "produces_evidence_kind": "scoped_command_timing",
  "input_schema": { /* JSON Schema the bridge validates before dispatch */ },
  "bounds": { "max_delay_seconds": 8, "max_trials": 5, "timeout_seconds": 20 },
  "scope": "candidate_origin_only",
  "signature": "ed25519:…"          // signed by the platform release key
}
```

Loading rules (the boundary stays intact):

- The bridge loads a recipe **only if** its `signature` verifies against a
  platform release public key pinned in config. Unsigned or MCP-discovered
  recipes are advertised but never dispatched until signed — this is the
  equivalent of CyberStrikeAI's dry-run / allowlist gate, made cryptographic.
- `class` maps to the existing `OBSERVE_OPERATIONS` / `PROBE_OPERATIONS` sets,
  so per-class policy (e.g. probes require a coverage cell) is preserved.
- `input_schema` is validated in the bridge before the call leaves the session;
  the model still never sees service credentials — only the allowlisted
  operation name and its schema-checked body.
- `produces_evidence_kind` must already be present in both
  `proof_policy.PROOFS_BY_CLASS` consumers and the `evidence_store` kind
  allowlist, so a recipe can never introduce an *unverifiable* evidence kind.

### Migration

1. Generate recipes from the current `_OPERATIONS` dict (one-to-one), sign them,
   and have `prowl_service_bridge` build `_OPERATIONS` by loading + verifying
   the recipe directory at startup. Behaviour is identical; the dict is now
   derived.
2. New probes (including `scoped_command_timing` and `scoped_path_canary` above)
   ship as a signed recipe file + the probe module + the proof-policy entry —
   no edit to the bridge module itself.
3. Optional later step: allow MCP-federated recipe *discovery* for visibility,
   still gated by signature before dispatch.

This keeps the one property that distinguishes PROWL from breadth-first tools —
**every operation the model can invoke is an allowlisted, scope-bounded,
evidence-producing step** — while removing the code edit from the critical path
of adding coverage.
