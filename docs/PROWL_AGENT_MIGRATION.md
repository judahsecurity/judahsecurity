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
`scoped_assessment_probe`, `scoped_assessment_candidate`, and
`scoped_assessment_status` tools. The bridge forwards only the hunter
capability. The service enforces exact origins, named identities, per-run
limits, and its evidence rules. Aegis records tool receipts and the service
keeps the full private artifacts.

For browser XSS and public directory index candidates, Aegis can run a fresh
deterministic verifier action with the separate verifier capability and ask the
service to confirm and publish. The model never gets that capability. Other
candidate types remain pending until an independent verifier handles them.
This repeat action provides independent evidence; it is not yet a separate
adversarial reasoning agent.

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

1. Extend the Aegis-driven verifier to numeric SQLi and owner-only authorization
   proofs. Those require a fresh browser capture by the verifier before the
   service will accept an independent proof. Keep the verifier capability out
   of the hunter tool registry and prompts.
   Add an adversarial reasoning pass if the product needs independent judgment
   beyond the current deterministic replay.
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
