# Prowl capability roadmap

Status: agreed plan, not started.

This plan closes the gaps found when Prowl was compared with PentAGI and
CyberStrikeAI. Prowl already leads on scope enforcement, verification of
findings before they are reported, and ASM integration. It trails on
isolation, MCP, memory, published benchmark results and code structure.

The order follows dependencies. Benchmarks come first so every later change
can be measured. Isolation has to exist before any broader tooling. Pulling
the command runner out of the large modules is the first step of both the
isolation and the maintainability work.

## Phase 0: baseline and quick fixes

### 0.0 Update model defaults (before the baseline)

The defaults are dated: `claude-sonnet-4-6`, `gpt-4o` and `gemini-2.5-pro` in
`backend/app/services/agent/llm_factory.py:43-50`, and `ANTHROPIC_MODEL` and
`OPENAI_MODEL` in `backend/app/core/config.py:97,102`. A baseline run on
these would understate Prowl and have to be redone, so update them before
0.1. Check the `model_router.py` task defaults at the same time.

### 0.1 Benchmark baseline (no public numbers today)

The harness already exists. Run it with a fixed model, budget and scope, and
record the results in a doc:

1. The 15-class lab: `harness/local_harness/product_class_benchmark.py`.
2. The XBEN smoke set.
3. The full XBEN import (104 challenges).

From then on, compare every change in this plan against the baseline with
`python -m local_harness.ledger_compare`.

Still to decide: which model to benchmark with and the budget per run.

### 0.2 Browser sandbox default

The code and the docs disagree:

- `backend/app/services/agent/scoped_assessment/browser_runtime.py:13-16`
  turns the Chromium sandbox on only when `AEGIS_BROWSER_ENABLE_SANDBOX` is
  set.
- `docs/ASSESSMENT_RELIABILITY.md:188`, and the second launcher in
  `backend/app/services/browser_automation_service.py:212`, treat the sandbox
  as on unless `AEGIS_BROWSER_DISABLE_SANDBOX=true`.

Make the code match the docs: on by default, off only through
`AEGIS_BROWSER_DISABLE_SANDBOX=true`. Chromium's sandbox often fails inside
Docker without a seccomp profile, so smoke-test the backend and
`prowl-browser` images, and add a seccomp profile to compose if one is
needed. Do not ship it as a blind change of the default.

### 0.3 Persistent graph checkpoints

`backend/app/services/agent/orchestrator.py:107` keeps LangGraph checkpoints
in memory (`MemorySaver`); the comment above it already says production
should use a persistent store. A backend restart in the middle of a turn
loses graph state, and memory grows with every session. The Postgres run
snapshots (`run_snapshot.py`) cover only part of this. Switch to
`PostgresSaver` from `langgraph-checkpoint-postgres`, and test that a run
resumes after a backend restart.

## Phase 1: real isolation

Today the scanner CLI tools run as plain subprocesses inside the backend and
scanner containers. There is also a bigger problem: the `scanner` service in
`docker-compose.yml` runs as root (`user: "0:0"`) and mounts
`/var/run/docker.sock`. Control of that container is effectively root on the
host. The socket is there for `AEGIS_VALIDATOR_MODE=docker`
(`backend/app/workers/scanner_worker.py:1198`), which already starts a
throwaway container for each validation. So the per-run container pattern
exists in the codebase; it just isn't safe yet.

1. **Separate the runner from the tools.** Put a `SandboxRunner` interface
   in front of `MCPServer._run_command` (`backend/app/services/mcp/server.py:1675`),
   with a `native` implementation (today's behaviour) and a `container` one.
2. **Run tools in a container per engagement.** Use a minimal tools image
   with:
   - a read-only root filesystem;
   - all capabilities dropped, except `NET_RAW` where a tool needs it;
   - CPU, memory and process limits;
   - no host mounts.
3. **Lock outbound traffic to the scope.** The sandbox's only network route
   goes through an egress proxy that applies the same rules-of-engagement and
   host checks as `aegis_praetorium`. A CLI tool then can't reach
   out-of-scope hosts even with bad arguments. This also covers a limit the
   docs already admit to: tool-start limits don't bound the requests made
   inside a single CLI call.
4. **Take the Docker socket away from the scanner.** Replace the socket mount
   with a small dedicated runner service (or rootless Docker or gVisor) that
   only accepts "launch an approved image with these limits".
5. **Make spending and request limits hard.** `docs/PROWL_AUTONOMY.md:58-66`
   admits that a model call can go past the dollar cap before usage is
   reported, and that one CLI call can send many requests.
   - Enforce a hard request count per engagement at the egress proxy from
     step 3.
   - Check the cost cap before each model call, using an estimated cost, as
     well as after usage is reported.

## Phase 2: real MCP server

The platform's "MCP server" (`backend/app/api/routes/mcp.py`) is a REST
wrapper around the tool registry; no MCP SDK is used.

1. Add the official `mcp` Python SDK as a dependency.
2. Serve the existing tool registry over streamable HTTP, mounted in FastAPI.
3. Authenticate with per-organisation API keys, and keep the Praetorium
   checks and the rules of engagement around every call.
4. Add stdio support later, for local clients.
5. Keep the existing REST endpoints unchanged for current callers.
6. Add a conformance test that uses an MCP client before calling this done.
7. Make outbound MCP client sessions (`backend/app/services/agent/mcp_client.py`)
   survive a process restart. Today they are process-local.

## Phase 3: memory

Embeddings are stored in JSON columns, and search falls back to a hashed
bag-of-words when no OpenAI key is set.

1. Switch the database image from `postgres:15-alpine` to
   `pgvector/pgvector:pg15`.
2. Add a migration that gives the knowledge and palace tables a `vector`
   column with an HNSW index, then backfill the existing JSON embeddings.
3. Replace the hash fallback with local embeddings, for example
   `nomic-embed-text` on the existing Ollama service. Orgs without an OpenAI
   key then still get real semantic search.
4. Hold off on Graphiti. Neo4j is already in place through `evograph.py`.
   Check whether pgvector changes the benchmark results before adding
   another graph layer.

## Ongoing: maintainability

There is no dedicated refactor phase. Split the large modules as the work
above touches them:

- `backend/app/services/agent/tools.py` (about 12.8k lines)
- `engagement_brain.py` (about 4.3k lines)
- `orchestrator.py` (about 4.1k lines)

The Phase 1 runner, the Phase 2 MCP layer and the Phase 3 memory module each
move out of `tools.py` and `mcp/server.py` as part of that work.

One decision is due now: should `aegis-vanguard/` move onto Prowl's shared
packages, or be frozen as the research harness? The two parallel agent stacks
duplicate the fireteam, the coverage ledger and identities, and they will
keep diverging.

## Breadth: decide after Phase 1

Prowl has no shells, exploit frameworks, or Active Directory or
internal-network tooling. For an external-ASM product that is mostly
deliberate.

- These tools are only safe to add once the Phase 1 sandbox exists.
- Recommended limit: one scoped "sandboxed shell" tool, available only in
  supervised pilot mode with operator approval.
- Full kill-chain or internal-network testing is a separate product
  decision, not a feature to match CyberStrikeAI on.

## After the baseline: coverage gaps the docs admit to

Schedule these once the Phase 0 benchmark shows how much each one matters:

- XSS in URL or CSS contexts has no execution recipe.
- The verifier on the legacy path isn't an independent adversarial agent.
- Coverage only reaches inputs that were actually observed.

## Open decisions

- **Benchmark settings:** which model and which budget per run to use for
  0.1.
- **Vanguard:** move `aegis-vanguard/` onto Prowl's shared packages, or
  freeze it as the research harness.
- **`aegis-claude-sdk/`:** it runs on a Pro/Max subscription OAuth token,
  and there is a `make` target for it in `Makefile:174-181`. Its own README
  says that using it for client or commercial scans breaks Anthropic's
  consumer terms and puts the account at risk. Recommended: move it out of
  this repo, or at least make sure no deployment or customer workflow can
  reach it. Commercial runs should use API keys.

## First PRs

1. Updated model defaults (0.0).
2. The browser sandbox default fix (0.2), with a smoke test.
3. Persistent graph checkpoints (0.3).
4. The baseline benchmark results doc (0.1), after PR 1.
5. A `SandboxRunner` interface with only the `native` implementation (1.1),
   so behaviour doesn't change yet.
