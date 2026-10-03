# Agent consolidation: Aegis runtime, PROWL assessment capabilities

## Direction

The existing Aegis ReAct/LangGraph runtime is the canonical agent. Its task
model router supports Anthropic, OpenAI, and other configured providers. The
separate PROWL assessment service supplies exact-origin browser and HTTP
execution, evidence, candidate review, and proof gates. The service is an
executor; it does not choose the agent model or own the main planning loop.

The product may later be renamed PROWL. Rename code, URLs, data directories,
and deployment identifiers only after the agent and assessment workflows are
joined and compared on the same controlled targets.

## First connected slice

An authenticated operator calls `POST /api/v1/agent/scoped-assessments` with an
in-scope `asset_id`, an exact `origin`, and optional named test identities,
body replay paths, and owner-only resource declarations. The API creates or
reuses an agent session and provisions one service run. It returns `session_id`,
`run_id`, `asset_id`, and `allowed_origin`; bearer capabilities stay encrypted
in the backend database. A URL asset with a non-root path cannot authorize an
origin-wide run.

Use the returned `session_id` with the usual `/api/v1/agent/query` or WebSocket
agent endpoint. The agent can call allowlisted `scoped_assessment_observe`,
`scoped_assessment_probe`, `scoped_assessment_probe_assigned`,
`scoped_assessment_candidate`,
`scoped_assessment_plan`, `scoped_assessment_memory`, and
`scoped_assessment_status` tools. Planning covers the service threat model,
coverage checks, and completion gate. Memory recall is limited to the same
organization and asset and cannot serve as fresh finding proof. The bridge
forwards only the hunter capability. The service enforces exact origins, named identities, per-run
limits, and its evidence rules. Aegis records tool receipts and the service
keeps the full private artifacts.

For browser XSS and public directory index candidates, Aegis can run a fresh
deterministic verifier action with the separate verifier capability. Numeric
SQLi and owner-only authorization candidates require an operator-scoped browser
page that issues the relevant GET. Aegis independently captures that request
under the verifier identity, repeats the bounded proof, and asks the service to
confirm and publish. If the fresh capture is missing or ambiguous, the
candidate stays pending. The model never gets the verifier capability. This
repeat action provides independent evidence; it is not yet a separate
adversarial reasoning agent.

## Parameter handoff to specialists

Aegis now normalizes observed query keys, form controls, API sample bodies,
and scoped browser traffic into a value-free parameter inventory. Each row
identifies the HTTP method, host, path, input location, parameter name,
identity, and capture reference where available. Request values and session
secrets do not enter the inventory. The `get_parameter_inventory` tool pages
through the worklist; XSS and SQLi specialists receive an exact parameter
coverage lease in each fireteam wave.

The coverage ledger creates separate XSS and SQLi cells for every eligible
observed input. A completed cell survives a later map refresh, while other
inputs stay open. Dispatch can continue these cells after a broad XSS or SQLi
hypothesis is closed. A negative result needs cited HTTP evidence; a signal
still requires independent verification before it becomes a finding. CSRF,
session, and token fields are recorded but excluded from automatic injection
work. Browser and crawl capture limits still bound what Aegis can discover;
the ledger cannot claim coverage for inputs that were never observed.

For a leased input backed by a PROWL private browser capture, XSS and SQLi
specialists can call `scoped_assessment_probe_assigned`. Aegis selects the
service operation from the cell's method, location, value type, and identity;
the specialist cannot substitute another capture or parameter. A GET query
can receive a bounded quote differential; a positive integer GET query can
receive the service's Boolean SQLi proof; a configured POST JSON/form capture
can receive a body probe. GET query XSS can receive a nonce browser check.
Differentials remain leads. A service proof signal remains subject to the
fresh verifier and publication gate above. Unsupported input shapes remain
open rather than being marked tested.

## JavaScript and API handoff

Browser requests and `browser_inspect_js` supply first-party script URLs. Aegis
creates one durable `js_secret_review` coverage cell per observed script and
assigns it to the JS specialist. `scan_assigned_js` fetches only that scoped
URL, refuses redirects, runs Gitleaks plus regex and structural client-signing
checks, and records a redacted evidence receipt. A failed, truncated, or
incomplete scan stays inconclusive; when PROWL supplied a source hash, a
different fetched bundle also stays inconclusive. A candidate remains in focus for review;
the agent can then inspect endpoints, sinks, source maps, and lazy chunks using
the existing JShero tools. Authenticated scripts that cannot be fetched again
are currently inconclusive, even when PROWL has a private browser source
artifact. The service does not expose that private source to the agent.

Observed first-party fetch/XHR operations and static JS API leads enter the
central `application_operations` ledger with method, path, parameter names,
identity, provenance, response metadata, and private capture IDs when present.
`get_api_operation_inventory` pages this value-free ledger for API specialists.
`fingerprint_api` performs passive, Caido-style classification from the
observed metadata and existing captured samples. A path alone is only a
discovery lead, not a verified framework or security finding.

For a scoped engagement, Aegis also saves the observed paths, parameter
names, first-party JS URLs, API rows, and a compact passive API fingerprint on
the run's bound asset. It updates the asset's Application Structure sitemap and
REST catalog. A JS scan writes a redacted status/count receipt under asset
metadata; it never stores the recovered secret value there. Independently
verified findings continue to become asset-linked Vulnerability records. The
bound asset and observed origin must match before any of these writes occur.
The asset detail page shows the passive API fingerprint and JS review receipts
in App Structure alongside the saved paths, parameters, scripts, and REST APIs.

Confirmed service publications enter the ordinary Aegis Findings table through
`POST /api/v1/prowl/findings`. This intake requires a service key, distinct
hunter and verifier evidence, a supported proof recipe, asset matching, and
idempotency by candidate ID. For runs provisioned by Aegis, it also checks the
bound organization, asset, and exact origin.

## Configuration

Build the separate assessment image from the PROWL service checkout and make
it available as `PROWL_ASSESSMENT_IMAGE` (default `prowl-browser:latest`). In
the Aegis deployment set `PROWL_ASSESSMENT_URL` to
`http://prowl-assessment:8833`, set a strong `PROWL_ADMIN_TOKEN`, and share a
separate strong `PROWL_INGEST_KEY` with the service. Start the Compose
`scoped-assessment` profile. The service has a private persistent data volume
and no published port.

To use OpenAI models for the main agent, configure `AI_PROVIDER=openai`,
`OPENAI_API_KEY`, and `OPENAI_MODEL`. Per-organization `task_models` settings
can override this for reasoning, offensive work, reports, or recon, so check
those settings during a model switch. The assessment service itself does not
require a Claude model for browser and HTTP execution.

## Remaining gates before making this the default

1. Run the four proof recipes against controlled fixtures, including a browser
   page that produces the SQLi and owner-only GET requests. Add an adversarial
   reasoning pass if the product needs independent judgment beyond the current
   deterministic replay.
2. Add a UI flow for selecting an in-scope asset, exact origin, test identities,
   and rules of engagement before starting an agent session.
3. Run the Aegis agent with an OpenAI model and an Anthropic model against the
   same controlled fixture, identity set, time limit, and spend limit. Measure
   reachable surfaces, correct findings, false positives, independent proof,
   tool calls, token cost, and recovery after restart.
4. Deploy the scoped service in the controlled test organization and repeat the
   proof and publication flow there. Local syntax checks and Compose validation
   do not establish runtime parity.

Until these gates pass, the existing agent and the separate service remain
available, and the new bridge is opt-in through configuration and run binding.
