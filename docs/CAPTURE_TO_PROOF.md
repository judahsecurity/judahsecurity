# Capture-to-proof authorization testing

Stage 1 connects successful, execution-observed REST requests to disposable
authorization proofs. It supports cross-user and cross-tenant reads, string
mutations, boolean/numeric property changes, and deletion. A confirmed hunter
receipt still requires a fresh independent verifier run before publication.

## Operator workflow

1. Register dedicated owner and attacker accounts with `register_test_identity`.
   Supply role/tenant metadata and verify a stable unique principal with
   `check_test_identity`. Role labels alone do not establish access policy.
2. Exercise a legitimate operation as owner using `browse_as_identity` or
   `replay_http_request(..., identity="owner")`. HTTP results expose `capture`;
   browser results expose `captures`. `list_proof_captures` lists supported
   execution-owned templates. The older `list_captured_requests` remains the
   capability-map index for generic request mutation.
3. Generate an authorization matrix using the capture's `operation_id`, with
   explicit deny expectations for each attacker and selected body property.
4. Call `prepare_captured_authorization_proof` with `hypothesis_id`, `capture_id`,
   `owner_identity`, the original captured `object_id`, and `configuration`.
   Preparation sends no requests. Example configuration for a captured PATCH:

```json
{
  "strategy": "captured_property",
  "value_path": "/enabled",
  "attack_value": true,
  "canary_path": "/marker",
  "object_path": "/id",
  "setup": {
    "method": "POST",
    "url": "https://staging.example.test/objects",
    "body": {"enabled": false}
  },
  "verify": {"url": "https://staging.example.test/objects/{{object_id}}"},
  "cleanup": {"url": "https://staging.example.test/objects/{{object_id}}"}
}
```

The captured body must contain `enabled`; its matrix parameter is `body:enabled`.
Setup must accept and persist a string `marker` property, populated with a fresh
canary by the engine. The original captured object is never the proof victim:
its complete URL path segment is replaced with the ID returned by setup.
Recipes must describe operator-controlled disposable fixtures. The engine
cannot infer whether a customer object is safe to modify or delete.

5. Call `run_authorization_proof(hypothesis_id)`. Every run creates fresh objects
   and canaries, including independent reruns. Registered plans cannot be edited
   or downgraded within the same assessment.
6. Submit confirmed candidates through the existing candidate workflow. The
   independent verifier reruns the recipe and submits its own ordered
   `evidence_ids` with `proof={"kind":"workflow","run_id":"<fresh run ID>"}`.
   Hunter receipts, model verdicts and imported traffic cannot replace this step.
7. Inspect `get_assessment_coverage`, including cleanup status and artifacts.

## Verdicts

| Strategy | Required evidence |
|---|---|
| `captured_read` | Owner creates and reads a fresh canary; attacker creates and reads a distinct control; attacker reads the owner's canary and ID; owner reads the victim again. |
| `captured_mutation` | Owner baseline, attacker writes a fresh generated string, owner reads the exact change from the same fresh object. |
| `captured_property` | Baseline differs from attack value; owner readback matches its exact JSON type and value and retains the object canary. Boolean true and numeric 1 differ. |
| `captured_delete` | Stable owner inventory contains a fresh victim and survivor before replay; afterward only the victim is missing and the survivor canary remains. |

Registered identities are checked before execution and again after readback.
Attack status and echoed bodies do not prove mutations. A 404 or empty inventory
does not prove deletion. Read denial stays inconclusive; refuted mutations apply
only to the exact test, never the whole application's security.

Delete recipes use a stable owner inventory URL in `verify`; `inventory_path`
(default `/items`) selects its array. Incomplete pagination and eventual
consistency may make results inconclusive and need dedicated recipes.

## Boundaries and cleanup

- Templates live in a private organization/session store: 200 records maximum,
  64 KiB JSON bodies. Imported maps cannot mint captures. Public descriptors omit
  body values. Successful redirect chains are excluded from HTTP templates.
- Only Accept and Content-Type carry into replay. Cookies, authorization and API
  keys come exclusively from the selected registry identity. Other application
  headers need a reviewed adapter; owner credentials are never inherited.
- Fresh proof receipts link capture provenance separately from verifier artifacts.
- Cleanup runs in `finally` for identified fresh objects. `attempted` means the
  cleanup endpoint accepted the request or reported absence, not independently
  verified deletion. Failed cleanup, or setup that may have created an unidentified
  object, produces `needs_follow_up`. Cleanup artifacts remain separate from
  evidence establishing the vulnerability.
- Transport failure after an action leaves an inconclusive result. Mutations are
  not automatically retried; follow-up must resolve uncertain external effects.

## Limits and validation

This slice supports REST JSON, whole-segment object IDs and top-level properties.
Query-bearing requests, credential-like body fields, multipart/binary bodies,
GraphQL and other protocols are unsupported replay templates. Read proofs need
an authenticated attacker able to create a control. Unavailable fixtures, missing
identity/policy and unsupported surfaces cannot count as tested. Templates/plans
remain in memory; durable restoration belongs to Stage 4.

`backend/tests/test_capture_to_proof.py` uses a real local HTTP application with
three principals in two tenants. Five recipes, two identity relationships and
vulnerable/patched variants form 20 detection cases. Each vulnerable case also
passes the existing independent publication gate. Further controls cover misleading
successes, expired identities, cleanup failure, actionful timeouts, altered plans,
capture isolation and patching between discovery and verification.

`backend/tests/test_assessment_browser_capture.py` exercises Chromium capture
through preparation and proof. The existing CI runs backend/harness tests and a
separate browser job. These tests establish deterministic workflow behavior,
not an LLM's autonomous discovery recall.

For live agent measurement, `harness/local_harness/product_agent.py` requires a
dedicated assessment database, organization/user context and configured LLM
credentials. Keep defect ground truth outside the agent prompt; score verified
findings separately from candidates and incomplete coverage. Judah already accepts
per-task `provider:model` selections, but a model's availability in Codex does
not itself configure the product's API credentials or assessment database.
