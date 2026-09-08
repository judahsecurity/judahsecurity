# Evidence-backed assessments

The product agent now requires execution-owned evidence before publishing medium-or-higher findings. These checks apply to both direct orchestration and fireteam discovery. `skip_judge_gate` and the old verification-disable environment flag do not bypass publication.

## Execution and verification

`replay_http_request` and `compare_requests` return an `evidence_id` for each HTTP exchange. Browser XSS checks and Interactsh registration/polling return `evidence_ids`. `read_evidence(evidence_id, offset, limit)` retrieves observations beyond the specialist's preview.

Evidence is isolated by organization and assessment session. Records include verifier run, candidate revision, identity, target, time, and a digest. Secret header values and structured JSON secret fields are redacted. Avoid putting real secrets in free-form explanatory text: arbitrary prose is not guaranteed to be fully scrubbed.

Set `AEGIS_EVIDENCE_DIR` to persist redacted artifacts in a private directory. The in-memory window retains up to 512 records or 64 MiB per session. Artifacts larger than 2 MiB retain a preview and cannot confirm a finding; use a bounded follow-up. Receipts expire after one hour and fail closed if their evidence is unavailable. Restarting a worker requires fresh verification. The files support audit/retrieval outside the agent; they are not automatically trusted as restored publication receipts.

The verifier must execute its own requests and call `record_verify_verdict` with the candidate ID, explanation, evidence IDs, and a supported structured proof:

| Proof kind | Required observation |
|---|---|
| `response_match` | A substantial literal response observation for an exposure; unavailable for authorization, mass assignment, XSS, and blind SSRF claims |
| `authorization` | Same private object/action, distinct verified principals, and the owner's principal ID in the same response field |
| `state_change` | A unique `aegis-verify-` value written and subsequently returned by a readback |
| `browser_xss` | Browser dialog executing the fresh verifier canary; source reflection alone is insufficient |
| `oob_callback` | Fresh collaborator registration, an observed request planting that payload, and a matching subsequent callback |

These are minimum proof requirements, not a universal vulnerability oracle. The verifier still has to establish intended access policy, context, and impact. A public object accessible to two users is not an IDOR. A legitimate authorized write is not an authorization flaw. Unsupported proof types stay inconclusive rather than falling back to a prose confirmation.

Confirmed receipts bind to the current candidate revision. Refutation invalidates the receipt. Changing the candidate's description, severity, or evidence requires reverification. Publication must use the verified target, description, and severity. Risk assessment remains a separate step.

## Configure two test identities

Register sessions supplied for the engagement using the tool API:

```python
register_test_identity(
    name="user_a", target="https://app.example.test",
    cookies=[{"name": "session", "value": "TEST_SESSION_A", "domain": "app.example.test",
              "path": "/", "secure": True}],
    role="member", tenant="tenant_a",
)
check_test_identity(
    identity="user_a", url="https://app.example.test/api/me",
    field="id", expected="user-a-id",
)
```

Repeat with a distinct principal as `user_b`. Use an engagement-provided administrator or another tenant where appropriate. `anonymous` is built in. Tokens may be registered through `headers` for HTTP replay. Identity verification expects a top-level JSON principal field; applications with another login representation need an adapter.

Named identities are restricted to their registered origin and cannot be mixed with credential overrides. The transport respects cookie host/domain, path, Secure, and expiry rules. Session checks run again before the authorization helper, so expired credentials produce a blocked test.

```python
test_authorization_boundary(
    url="https://app.example.test/api/objects/TEST_OBJECT_A",
    owner_identity="user_a", other_identity="user_b",
    object_field="owner_id", hypothesis_id="object-ownership-check",
)
```

First establish that the object is private and belongs to user A. This helper discovers a candidate; independent verification is required before publication.

For browser/crawl sessions, pass `identity` in JSON arguments to `execute_browser` or `execute_deep_crawl`. Cookies and browser storage are seeded from that identity. HTTP-only bearer headers are not injected globally into browser subresource requests; use browser storage/cookies or the HTTP tools for those applications. `list_captured_requests(identity="user_a")` and `mutate_captured_request(identity="user_a", ...)` retain access to that identity's crawl samples.

## Replay a legitimate workflow

Use captured requests from an authorized normal-user walkthrough, not invented endpoints. `run_assessment_workflow` supports explicit identities, top-level JSON extraction, `{{variable}}` references, expected statuses, cleanup, and a resumable workflow ID.

```json
[
  {
    "id": "create_test_object",
    "request": {
      "method": "POST", "url": "https://app.example.test/api/objects",
      "identity": "user_a", "body": {"name": "aegis-verify-object"}
    },
    "expect_status": [201], "extract": {"object_id": "id"}
  },
  {
    "id": "read_as_other_user",
    "hypothesis_id": "object-ownership-check",
    "request": {
      "url": "https://app.example.test/api/objects/{{object_id}}",
      "identity": "user_b"
    },
    "expect_status": [403, 404]
  },
  {
    "id": "remove_test_object", "cleanup": true,
    "request": {
      "method": "DELETE", "url": "https://app.example.test/api/objects/{{object_id}}",
      "identity": "user_a"
    },
    "expect_status": [204]
  }
]
```

An unexpected response remains evidence and makes the workflow inconclusive; it does not itself confirm a vulnerability. Cleanup steps run after failed prerequisites, and failed cleanup stays visible. Resume a returned `workflow_id` without repeating completed mutations. Workflow checkpoints currently live within the worker's assessment session, not across worker restarts.

Specialists return `hypothesis_results`, one entry per hypothesis, citing HTTP evidence IDs captured with that hypothesis ID. A lane summary cannot close all its cards. Missing results remain open; tool errors do not kill a hypothesis. Only independent verification marks a discovery proven.

## Evaluate the in-product execution path

The harness still supports Vanguard. To use the product orchestrator, run from the repository root with the backend installed and a dedicated initialized assessment database/org/user:

```bash
export PYTHONPATH="$PWD/backend:$PWD/harness:$PWD/backend/packages/aegis_praetorium"
export AEGIS_HARNESS_SCANNER_CMD="python -m local_harness.product_agent"
export AEGIS_HARNESS_SCANNER_CWD="$PWD"
export AEGIS_HARNESS_SCANNER_ARGS="--organization-id 123 --user-id 456 --identities /secure/assessment-identities.json"
# Set AEGIS_ASSESSMENT_DATABASE_URL and the normal backend LLM credentials securely.
python -m local_harness.benchmark.run --ground-truth /path/to/controlled-ground-truth.json \
  --min-verified-recall 0.8 --fail-on-scan-error
```

The `0.8` threshold above is an example, not a measured result or established release threshold. Identity configuration is a JSON array of registration arguments; each entry can include a `check` object with `url`, `field`, and `expected`. Keep real credentials out of source control.

The adapter invokes the normal product orchestration path, preserves publication gates, writes the standard finding sink, and stops on completion, error, required input, or its turn budget. It does not pass benchmark ground truth to the agent. Real database/model execution requires those configured services; offline tests exercise the adapter contract and the actual specialist/transport/verifier path with controlled responses.

Scoring uses one-to-one category/endpoint matching. Paths preserve case and segment boundaries; explicit `{id}` placeholders match one segment. Optional identity, tenant, and method constraints must match finding metadata. Invalid or duplicate LLM judge matches are discarded and misses are derived from validated matches.

Existing `recall`/`precision` describe candidate findings for compatibility. `verified_recall`/`verified_precision` count findings marked confirmed by the engine; use `--min-verified-recall` for a verified-result gate. For third-party scanners, the harness trusts the engine's confirmed flag; only the product engine binds that flag to its execution receipt.

Run vulnerable and patched counterparts and hold out variants when measuring detection quality. Regression test counts and scripted verifier results are not live-agent precision/recall measurements.

## Regression checks

```bash
python -m pip install -r backend/requirements-assessment-tests.txt
export PYTHONPATH="$PWD/backend:$PWD/harness:$PWD/backend/packages/aegis_praetorium"
export SECRET_KEY="test-only-secret-with-at-least-32-characters"
python -m pytest backend/tests harness/tests -o addopts= -q
ruff check --select F821,F822,F823 backend/app/services/agent harness/local_harness
```

The assessment CI workflow runs both suites on backend/harness changes. No model credentials or live assessment targets are required for these tests.
