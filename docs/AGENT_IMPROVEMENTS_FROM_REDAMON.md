# Agent & Platform Improvements Inspired by RedAmon

This document outlines improvements we can adopt from [RedAmon](https://github.com/samugit83/redamon) (AI-powered agentic red team framework) that fit our **defensive ASM** scope. RedAmon focuses on offensive automation; we focus on attack surface discovery, vulnerability management, and remediation—so we adapt ideas that improve agent UX, reliability, and intelligence without adding exploitation features.

**Shipped since this note:** the in-product **tester process** (engagement brain, fireteam, `compare_requests`, chain cards) is documented in [TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](./TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md). Batch/detection measurement is in [HARNESS.md](./HARNESS.md) / [harness/README.md](../harness/README.md).

---

## 1. **Streaming / Long-Running Requests (High impact)**

**RedAmon:** Agent chat uses **WebSocket** for real-time updates; long tool runs (e.g. Nuclei, Hydra) stream progress every 5 seconds so the user sees activity and the connection doesn’t time out.

**Our current state:** The frontend uses **REST** `POST /api/v1/agent/query` and waits for the full response. Long vuln scans exceed proxy timeouts (60–300s) and produce **504 Gateway Timeout**.

**Improvements:**

- **Option A (recommended):** Use the existing **WebSocket** agent endpoint from the frontend for the main chat. Stream partial responses (e.g. “Agent is thinking…”, “Running Nuclei…”, tool output chunks) so the client stays connected and the proxy doesn’t kill the request.
- **Option B:** Add **Server-Sent Events (SSE)** for a single long-lived response: one request, multiple events (thinking → tool_start → tool_output → answer). Simpler than WebSocket if we only need server→client streaming.
- **Option C:** Run the agent as a **background job** (e.g. Celery/Redis or DB-backed task). Frontend polls or uses SSE for status and final result. Avoids HTTP timeout entirely but requires job queue and UI for “running” state.

**References:** RedAmon uses WebSocket for agent and SSE for recon logs ([README](https://github.com/samugit83/redamon)).

---

## 2. **Structured Execution Context in the ReAct Prompt (Medium impact)**

**RedAmon:** “EvoGraph” injects **structured sections** into the agent prompt: **Findings** (by severity), **Failed Attempts** (with lessons learned), **Decisions** (phase transitions, rationale), **Recent Steps** (last N steps). They report ~25% efficiency gain vs. a flat execution trace.

**Our current state:** We inject a single **flat execution trace** (last 10 steps: thought, tool, success, short analysis) via `format_execution_trace()` in `state.py`.

**Improvements:**

- **Structured trace:** Build prompt sections from the same `execution_trace` list:
  - **Findings:** Steps that produced actionable findings (e.g. from `output_analysis` or tool result), sorted by severity/relevance.
  - **Failed steps:** Steps where `success is False` with a one-line “lesson” (e.g. “Nuclei timed out on X”).
  - **Decisions:** Phase transitions and approval outcomes.
  - **Recent steps:** Last 5 steps in compact form (as today).
- Keep the same data source; only change how we **format** it for the system prompt so the LLM gets clearer, prioritized context.

**References:** RedAmon [README – EvoGraph](https://github.com/samugit83/redamon#evograph--attack-chain-evolution), “Structured Chain Context in the ReAct Prompt”.

---

## 3. **Real-Time Progress for Long Tool Runs (Medium impact)**

**RedAmon:** For long-running MCP tools (e.g. Hydra, Metasploit), the agent streams progress updates every 5 seconds over the WebSocket so the user sees “Agent is working” instead of a spinning state.

**Our current state:** While a tool runs (e.g. `execute_nuclei`), the frontend only shows “Agent is thinking and may run tools…” until the full response returns (or 504).

**Improvements:**

- When the orchestrator **starts** a long-running tool (e.g. Nuclei, Naabu, Katana), push a **progress event** over WebSocket (or SSE): e.g. `{ "type": "tool_start", "tool": "execute_nuclei", "args": {...} }`.
- If the MCP layer can report progress (e.g. “Nuclei: 30%”), stream **progress events** periodically: `{ "type": "tool_progress", "tool": "execute_nuclei", "message": "..." }`.
- Frontend shows a live status line: “Running Nuclei on 5 targets…” and keeps the connection alive, reducing perceived timeouts and 504s.

---

## 4. **Multi-Session / Session List (Lower priority)**

**RedAmon:** Multiple concurrent agent sessions per project; each has its own attack chain in Neo4j. User can switch sessions and resume from the session list.

**Our current state:** One active conversation per tab; session is in memory (MemorySaver). No UI to list or resume past sessions.

**Improvements:**

- **Persist sessions:** Store session metadata (and optionally full state) in DB or Neo4j so sessions survive restarts.
- **Session list in UI:** Show recent sessions for the current org/project; “Resume” loads that session’s history and state.
- Enables “run vuln scan in session A, ask questions in session B” without losing context.

---

## 5. **Dynamic Model List (Nice to have)**

**RedAmon:** Model selector is **dynamic**: it fetches available models from each configured provider (OpenAI, Anthropic, OpenRouter, Bedrock, etc.) and shows them in one searchable dropdown. New models appear without code changes.

**Our current state:** We use a single model from config (`ANTHROPIC_MODEL` / `OPENAI_MODEL`). No UI to switch models.

**Improvements:**

- Add an optional **GET /api/v1/agent/models** (or similar) that returns `{ "anthropic": [...], "openai": [...] }` from provider APIs (with API key server-side).
- In the Agent UI, add a **model dropdown** (e.g. for analysts) so they can pick Claude vs GPT or a different model without editing env.
- Keep default from env; override only when user selects another model (e.g. stored in session or per-org settings).

---

## 6. **Recon / Scan Log Streaming (Already partially there)**

**RedAmon:** Recon pipeline streams logs to the frontend via **SSE**, so users see live progress of each phase (domain discovery, port scan, vuln scan, etc.).

**Our current state:** Scans run in the scanner worker; we have scan detail and results. Need to confirm if any scan-type already streams logs via SSE or WebSocket.

**Improvements:**

- If not already in place: add **SSE or WebSocket** for “scan log stream” by scan ID so the scan detail page shows live logs (e.g. “Running Nuclei…”, “Found 3 issues”) instead of only final results.
- Aligns with RedAmon’s “watch real-time logs in the drawer” UX.

---

## 7. **What We Intentionally Don’t Copy**

- **Offensive exploitation (Metasploit, Hydra, phishing):** RedAmon’s exploitation and post-exploitation phases are out of scope for our defensive ASM product.
- **CypherFix / CodeFix agent:** Automated code fixes and GitHub PRs are a large feature set; we already have remediation playbooks and finding management. We could later consider a lighter “suggest patch” or “link to playbook” step.
- **GVM/OpenVAS:** We use Nuclei and custom scans; adding a full GVM stack is a separate product decision.
- **Full EvoGraph persistence:** RedAmon persists entire attack chains in Neo4j for cross-session intelligence. We can adopt “structured trace for prompt” without committing to the same graph schema.

---

## Summary Table

| Improvement                    | Impact   | Effort | Notes                                      |
|------------------------------|----------|--------|--------------------------------------------|
| Streaming (WebSocket/SSE)     | High     | Medium | Fixes 504; better UX for long agent runs   |
| Structured execution context | Medium   | Low    | Prompt-only change; better agent decisions|
| Progress events for tools     | Medium   | Medium | Depends on streaming + MCP progress       |
| Multi-session / session list  | Low–Med  | Medium | Requires session persistence + UI          |
| Dynamic model list            | Nice to have | Low | Optional endpoint + dropdown              |
| Scan log streaming            | Medium   | Low–Med| If not already present                     |

Implementing **streaming (1)** and **structured execution context (2)** gives the largest benefit for 504s and agent quality with manageable effort. Progress events (3) build on streaming and improve perceived performance for vuln scans and discovery.
