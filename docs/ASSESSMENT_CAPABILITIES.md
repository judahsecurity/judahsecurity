# Application assessment capabilities

For execution-owned REST capture, typed mutation/delete recipes, and their
vulnerable/patched fixtures, see [Capture-to-proof testing](CAPTURE_TO_PROOF.md).

This phase extends Judah's in-product tool manager, engagement brain, task graph,
identity registry and execution evidence store. It does not launch Hadrian,
Vespasian or Titus as external scanners. Their design concepts informed the
identity matrix, passive operation inventory and candidate-first JS pipeline.

## Architecture and guarantees

| Component | Responsibility |
|---|---|
| `assessment_sessions.py` | Sessions keyed by identity name and exact origin; role/tenant metadata, explicit anonymous context, URL-aware cookies and isolated browser state |
| `authorization_engine.py` | Explicit allow/deny/unknown expectations, matrix expansion, per-cell verdict/evidence and coverage |
| `runtime_mapper.py` | Bounded request normalization, stable operation IDs, protocol fidelity, provenance and graph hypotheses |
| `js_intelligence.py` | Same-origin bounded script/import/map collection, static leads and redacted provider candidates |
| `proof_engine.py` | Trusted `ProofStrategy` evaluators, fresh canaries, ordered execution artifacts and immutable workflow receipts |
| `assessment_capabilities.py` | Thin agent-tool adapters that reuse `_http_exchange`, the browser service and engagement state |

All mutable engines, credentials, plans and receipts are scoped by organization
and assessment session through `SessionValue`. Registering `user_a` on host B
does not replace its session on host A. Registry inputs are copied, and named
requests cannot override registered credential headers, Cookie, Authorization
or Host. Cookie rotation is retained per entry. An HTTP 403 does not imply the
whole identity session has expired; an explicit identity check establishes the
principal, and proof runs recheck accounts before testing.

Browser identity contexts start fresh, receive only the selected origin's
storage/cookies, block cross-origin HTTP and WebSocket requests, and disable
service workers. This requires Playwright >=1.48. Browser state export alone
never marks an identity authenticated. Cross-origin SSO/application dependencies
require separately configured contexts; they are not silently credentialed.

Evidence records expose read-only snapshots of execution-owned data, retain
redacted bodies beyond the agent preview, and optionally persist through the
existing `AEGIS_EVIDENCE_DIR`. Proof receipts are frozen and bind ordered artifact
IDs to hypothesis, operation, parameter, attacker identity, candidate revision and
verifier run. The receipt binds the claimed operation URL to the actual controlled
object URL used by that run, so fresh fixtures can have new IDs without accepting
evidence from unrelated endpoints. A hunter proof cannot issue a publication receipt. Matrix candidates
require a fresh workflow receipt in the independent verifier. Later inconclusive
or refuted verification revokes publication and reopens the cell.

## Operator workflow

1. Register the supplied user A, user B, admin and tenant sessions with
   `register_test_identity(name, target, cookies, headers, storage_state, role, tenant)`.
   Use `check_test_identity(identity, url, field, expected)` against a known
   identity endpoint. Account principals must be distinct for cross-user proofs.
2. Use `browse_as_identity(identity, url, actions)` to observe legitimate actions.
   Existing HTTP replay and crawl samples also feed the mapper. For externally
   captured request dictionaries, call `map_application_traffic(requests, identity)`.
3. Read operation IDs from the returned `engagement_brain.application_operations`.
   Call `generate_authorization_matrix` with explicit expectations, for example:

   ```json
   {
     "operation_ids": ["<observed PATCH operation ID>"],
     "identity_names": ["user_b", "anonymous"],
     "expectations": [
       {"operation_id": "<observed PATCH operation ID>", "identity": "user_b", "expected": "deny"}
     ]
   }
   ```

   Roles and tenant labels do not invent an access policy. Unspecified expectations
   are blocked. There is one operation-level cell and one for each observed input
   (`query:name`, `body:name`, `variable:name`). Input expectations are independent.
4. Run a controlled REST JSON proof with the returned hypothesis ID. Example:

   ```json
   {
     "hypothesis_id": "<matrix hypothesis ID>",
     "plan": {
       "strategy": "authorization_mutation",
       "controlled_resource": true,
       "target": "https://app.example.test/objects/1",
       "owner_identity": "user_a",
       "object_path": "/id",
       "value_path": "/marker",
       "setup": {
         "method": "POST", "url": "https://app.example.test/objects",
         "body": {"marker": "before"}
       },
       "attack": {
         "method": "PATCH", "url": "https://app.example.test/objects/{{object_id}}",
         "body": {"marker": "{{nonce}}"}
       },
       "verify": {"method": "GET", "url": "https://app.example.test/objects/{{object_id}}"}
     }
   }
   ```

   The engine generates the nonce. Confirmation requires that the distinct owner's
   later read of the same object contains the fresh attacker-written value. An
   unchanged value refutes that mutation attempt. Unexpected state or failed
   controls remain inconclusive. Numeric role changes need a dedicated strategy;
   this string-canary recipe must not be used to claim privilege escalation merely
   because a marker field was writable.

   `authorization_read` instead requires setup to persist and return `{{nonce}}`,
   a GET attack, a distinct attacker-owned GET `control`, and owner GET `verify`.
   The canary cannot be supplied in the attack/control/readback requests, preventing
   reflection from masquerading as disclosure. Both object ID and fresh canary
   must be observed in the attacker response. An absent canary is inconclusive.

   Use disposable, operator-owned fixtures. This proof tool does not delete setup
   objects automatically; the existing `run_assessment_workflow` supports explicit
   cleanup requests and resumable sequences. Scope cleanup to the created fixture.
5. Submit a finding candidate referencing this hypothesis and its actual impact.
   An independent verifier can call `run_authorization_proof(hypothesis_id)` without
   resupplying the registered plan. It must submit the new receipt's exact
   `evidence_ids` and `proof={"kind":"workflow","run_id":"<fresh receipt run_id>"}`
   to `record_verify_verdict`. Normal publication gates still apply.
6. `get_assessment_coverage` returns counts and rows by hypothesis, identity,
   tenant, input and operation. `get_coverage` includes it alongside legacy
   inventory coverage. Tested describes an executed proof, not completeness of
   the whole application. Omitted cells remain untested or blocked.

## Runtime and JS discovery

The runtime mapper distinguishes REST, GraphQL queries/batches, WebSocket
handshakes, gRPC-Web method paths and SOAP envelope/actions. It preserves exact
paths rather than guessing that numeric segments are interchangeable. GraphQL
operation identity includes the query fingerprint, avoiding collapse of distinct
operations at `/graphql`. Query values, body values and credentials are excluded
from the inventory. Recorded parameter names are retained.

Browser request hooks run before login and application actions. Capture is bounded
at 200 HTTP requests per browser call; the merged inventory is bounded at 1000
operations. Each operation seeds a task-graph hypothesis. Source JS hints are
explicitly marked as discovery; they do not establish a request method or runtime
reachability even when a provisional GET operation is used for scheduling.

`collect_js_intelligence(url, identity, max_files=20)` uses the existing HTTP
transport, disables redirects and permits only the initial origin. It collects
inline/external scripts, literal JS imports/chunks and linked source maps with
`sourcesContent`. Each response is capped at 1 MiB during streaming and the file
budget is capped at 50. It extracts endpoint hints, GraphQL operation names,
WebSocket URLs, feature flags, internal hostnames, local/session storage names,
cloud storage references and secret candidates. Missing maps, blocked dependencies
and exhausted budgets appear in `gaps`.

Secret values stay in the session's JS engine, are excluded from candidate output,
and are redacted in execution artifacts. Current provider recognizers cover
GitHub, Stripe and AWS access-key identifiers, plus generic assignment candidates.
An AWS access-key ID is not sufficient to authenticate and is never a finding.

Provider validation is disabled by default. Trusted application code can configure
`manager._secret_validation_policy = {"enabled": True, "providers": [...]}` and
register an async callback in `manager._js_intelligence.validators[provider]` after
initializing the engines. Callbacks must use fixed provider endpoints, a read-only
identity/metadata action, and execution evidence; never construct a destination
from untrusted JavaScript. The wrapper enforces a 10-second timeout and requires
an evidence ID for valid/invalid results. The agent's
`validate_js_secret_candidate(candidate_id)` cannot enable this policy. Even a
valid credential result remains a candidate requiring impact assessment and
independent confirmation. No bundled live provider calls are enabled here.

## Validation and remaining slices

Regression tests cover the pure engines and the real product tool manager through
HTTP fixtures, including stale verifier runs, account aliases, reflected canaries,
HTTP-200 patched controls, matrix isolation, immutable evidence and secret
redaction. An opt-in Chromium test checks real browser requests, distinct identity
cookies, GraphQL discovery and cross-origin blocking:

```sh
export PYTHONPATH=backend:harness:backend/packages/aegis_praetorium:backend/packages/asm_scanner_core
pytest backend/tests/test_assessment_*.py
RUN_ASSESSMENT_BROWSER_TESTS=1 pytest backend/tests/test_assessment_browser_capture.py
pytest harness/tests
```

Remaining work is explicit: AST-based and computed webpack-chunk discovery;
GraphQL authorization proofs and schema-aware parameter mutation; gRPC descriptors
and frame decoding; WebSocket message semantics; SOAP mutation proofs;
business-workflow strategies; preconfigured provider validation adapters; durable
workflow-plan restoration and a frontend matrix view. REST JSON now supports captured
read, string, numeric, boolean and deletion proofs. Persistent snapshots retain the
task graph, bounded hypothesis leases and historical evidence references, but omit
credentials and executable receipt authority. Old receipts therefore cannot authorize
publication, and expired leases require reconciliation before another action.

The recommended next slice is a held-out two-tenant CRUD fixture pack with read,
update, delete and property-authorization variants, plus patched counterparts.
Use it to add typed property/delete strategies, cleanup and durable workflow
resumption, and measure verified recall and per-identity coverage through the
product-agent harness before expanding protocol breadth.

Design references: [Hadrian](https://github.com/praetorian-inc/hadrian),
[Vespasian](https://github.com/praetorian-inc/vespasian),
[Titus](https://github.com/praetorian-inc/titus), and
[Playwright WebSocket routing](https://playwright.dev/python/docs/api/class-websocketroute).
No source code from these Praetorian tools was copied.
