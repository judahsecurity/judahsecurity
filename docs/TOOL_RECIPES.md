# YAML tool recipes

A recipe exposes a command-line tool to the Prowl agent without Python changes.
Add one file to `backend/app/services/tool_recipes/recipes/` and restart the
backend.

```yaml
name: execute_tlsx            # must start with execute_
binary: tlsx                  # bare executable name on PATH
description: >-
  What the tool tells the agent and when to use it (shown in the tool list).
example: execute_tlsx(args="-u app.example.com -san -cn")
phases: [informational, exploitation, post_exploitation]   # default: all
timeout_seconds: 120          # default 300, max 1800
fixed_args: [-silent]         # always prepended
help_args: [-h]               # registers tlsx_help; null to disable
success_exit_codes: [0]
deny_flags: []                # Lictor refuses calls containing these
safe_defaults: []             # Lictor appends these when absent
auto_approve: true            # passive recon only: skip the confirmation prompt
shareable: true               # identical concurrent calls share one run
```

One file registers the tool in the MCP server, the agent tool registry,
`TOOL_PHASE_MAP`, the phase tool list in the system prompt, Lictor's flag
policy, confirmation auto-approval and single-flight sharing.

## Rules

- Every recipe call goes through the same guard layer as built-in tools:
  Censor, the never-touch denylist, Lictor (SSRF, scope, destructive flags,
  rate limit) and Augur.
- The agent only sees a recipe in its tool list when the binary is installed.
  A missing binary is listed as unavailable and fails fast.
- A recipe cannot replace a built-in tool. Name collisions are skipped with a
  warning.
- Invalid files are skipped with a logged reason; the rest still load.
  Unknown keys are rejected so typos fail loudly.
- Use `auto_approve` only for tools that send little or no traffic to the
  target. Active tools should leave it off so the org's confirmation policy
  applies.
- Recipes run with no stdin and take arguments as one CLI string. Tools that
  need stdin, files or structured output parsing still need a Python handler.

## Bundled recipes

| Recipe | Why it helps the agent pivot |
|---|---|
| `execute_tlsx` | Certificate SANs and CNs reveal sibling, staging and internal hosts |
| `execute_assetfinder` | Passive subdomains with no traffic to the target |
| `execute_dig` | TXT/MX/NS/CNAME records name SaaS vendors and dangling takeover targets |

Tests: `backend/tests/test_tool_recipes.py` loads every bundled recipe and
fails on validation errors or a collision with a built-in tool.
