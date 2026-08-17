# Aegis Vanguard — Claude Agent SDK harness (Pro/Max subscription)

This is an **alternative front-end** to the Aegis Vanguard offensive agent
(`../aegis-vanguard`). It runs the pentest loop inside the **Claude Agent SDK**
(which wraps the Claude Code CLI) so it can bill against a Claude **Pro/Max
subscription** via `CLAUDE_CODE_OAUTH_TOKEN`, instead of the standard
`ANTHROPIC_API_KEY` per-token API billing.

It does **not** reimplement any offensive logic. Every registered Vanguard
`@security_tool` is exposed to Claude as an in-process MCP tool, and every call
is gated by Vanguard's existing `GuardrailEngine` (scope enforcement, risk
ceiling, blocked-command patterns). Only the model-call substrate changes.

---

## ⚠️ Read this before you use it

Anthropic's consumer Terms state that OAuth tokens from **Free/Pro/Max** plans
are *"intended exclusively for Claude Code and Claude.ai"* and that using them
*"in any other product, tool, or service — including the Agent SDK — is not
permitted."* Anthropic has also (as of ~2026) started **actively blocking**
third-party harnesses that bridge subscription auth.

**Implications:**

- Use this for **personal / research** work on **your own** account only.
- Do **not** ship it to end users, host it as a service, or run customer-facing
  scans on it. That is a Terms violation and risks your account.
- The path can break at any time if Anthropic tightens enforcement.
- A leaked token drains your subscription until you rotate it — treat it like a
  password (store it as a secret, never commit it).
- Rate limits apply. A wide scan makes many model calls and can exhaust a
  subscription's rolling/weekly limits quickly.

For anything shared or production, run with `--api-billing` (Console API key) or
point Vanguard at a cloud provider (Bedrock/Vertex). The SDK itself is
production-grade; **you swap the auth method, not the SDK.**

---

## Setup

```bash
# 1. Install the Claude Code CLI (the SDK spawns it as a child process)
npm install -g @anthropic-ai/claude-code

# 2. Generate a ~1-year subscription OAuth token (opens a browser once)
claude setup-token          # prints: sk-ant-oat01-...
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...

# 3. IMPORTANT: make sure ANTHROPIC_API_KEY is NOT set, or it shadows the token
#    and you get billed for API credits. (This harness also unsets it in-process
#    as a safety net.)
unset ANTHROPIC_API_KEY

# 4. Python deps: the SDK + the Vanguard tooling
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r ../aegis-vanguard/requirements.txt
```

The offensive scanners (subfinder, httpx, nuclei, sqlmap, …) must be on `$PATH`
for full coverage — same requirement as Vanguard. Missing tools degrade
gracefully (the agent skips them). The prebuilt `../aegis-vanguard/Dockerfile`
image already contains them.

---

## Usage

```bash
# List the Vanguard tools this harness exposes to Claude (offline, no auth needed)
python3 pentest_subscription.py --list-tools

# Run an authorized assessment on your subscription
python3 pentest_subscription.py --target https://example.com --scope example.com

# Cap risk and turns
python3 pentest_subscription.py --target https://example.com --max-risk medium --max-turns 120

# Stop when the API-equivalent cost estimate hits a ceiling
python3 pentest_subscription.py --target https://example.com --max-budget 5.00

# Fall back to per-token API billing (compliant path for shared/hosted use)
python3 pentest_subscription.py --target https://example.com --api-billing
```

Findings flow to your ASM platform automatically if `ASM_API_URL` / `ASM_API_KEY`
are set (the Vanguard `submit_findings_to_platform` tool is reused); otherwise
they stay in the run output.

### Key flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--target, -u` | — | Target URL (required unless `--list-tools`) |
| `--scope, -s` | target host | Root domain scope for guardrail enforcement |
| `--model, -m` | subscription default / `$AEGIS_MODEL` | Model alias or name |
| `--max-risk` | `high` | Tool risk ceiling (`safe`…`critical`) |
| `--max-turns` | `200` | Max agentic tool-use round trips |
| `--max-budget` | none | Stop at an API-equivalent USD estimate |
| `--no-guardrails` | off | Disable the guardrail engine (not recommended) |
| `--api-billing` | off | Use `ANTHROPIC_API_KEY` instead of the subscription |

---

## How it works

```
pentest_subscription.py
  ├─ preflight: require CLAUDE_CODE_OAUTH_TOKEN, unset ANTHROPIC_API_KEY
  ├─ import aegis-vanguard  ──▶ every @security_tool registers in ToolRegistry
  ├─ wrap each ToolDef as an in-process SDK MCP tool
  │     handler = guardrail check → registry.execute() in a worker thread
  ├─ create_sdk_mcp_server(name="vanguard", tools=[...])
  └─ ClaudeSDKClient(options)             ← Claude Code owns the ReAct loop
        system_prompt = Vanguard pentester ROE
        allowed_tools = mcp__vanguard__*  + read-only built-ins
        disallowed    = Bash / Write / Edit  (agent can't touch a raw shell/FS)
        env           = CLAUDE_CODE_OAUTH_TOKEN  → bills the subscription
```

Safety is preserved because each Vanguard tool re-checks the `GuardrailEngine`
(scope + risk + blocked commands) inside its handler before executing, and the
unguarded built-in shell/file tools are removed from Claude's context.

---

## Deploying on AWS

Because subscription OAuth is **personal-use** and rate-limited, treat this as a
single-operator research rig, not a fleet service:

- Simplest: an **EC2 instance** with the CLI installed and
  `CLAUDE_CODE_OAUTH_TOKEN` stored via **SSM Parameter Store / Secrets Manager**
  (never a plaintext env file). Reuse `../aegis-vanguard/Dockerfile` for the
  scanner toolchain and run this harness inside it (Node + the `claude` CLI must
  be present in the image).
- For a compliant, scalable AWS deployment instead, drop the subscription path
  and run Vanguard (or the backend platform agent) with **Claude via Bedrock**
  (`AEGIS_MODEL=bedrock/...`) on ECS Fargate — no personal token, no rate cap,
  within Terms.
