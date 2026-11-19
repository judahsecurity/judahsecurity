# Prowl run discipline

Eight controls that make Prowl test more thoroughly, waste less budget, and
report gaps honestly. Each lives in its own module under
`backend/app/services/agent/`. Per-org switches are in the agent settings
(`MODULE_AGENT`, defaults in `app/models/project_settings.py`).

| Control | Module | What it does | Switch |
|---|---|---|---|
| Sealed output | `content_shield.py` | Every tool result except a short trusted list is wrapped in markers carrying a random seal id per call. Marker-shaped text inside the data is defanged, so target content cannot close its own frame. JSON stays parseable with an `_untrusted_content` notice. Unknown and MCP tools are sealed by default. | None (always on) |
| Argument rules | `argument_rules.py` | Approval rules that match a call's arguments, not just the tool name. `auto` rules must list every flag they allow; `deny`/`confirm` rules match anywhere. Calls that cannot be parsed (bad quoting, `$(…)`, chaining) go to an analyst, and autonomous auto-approve cannot pass them. | `tool_argument_rules` (list, default empty) |
| Full Pursuit | `full_pursuit.py` | Prompt guidance: keep testing after the first finding, prove the full impact, render the app, approach business logic as state machines. Completion is blocked until the app has been rendered in a real browser (an HTTP-only Katana crawl does not count). | `full_pursuit_enabled` (default `true`) |
| Hindsight notes | `hindsight.py` | Agent findings an analyst marked false positive (status or an active false-positive exception) become per-org notes: "do not re-report this root cause without a new mechanism". Computed on read, so reopening a finding removes its note. Capped at 8 notes / 1,800 characters and sealed. | `hindsight_mode`: `shadow` (default, log only), `inject`, `off` |
| Cold trails | `cold_trails.py` | A direction (tool family + normalized endpoint + coverage cell or hypothesis) tried 3+ times in a run with nothing actionable is listed to the planner as cold. | None (prompt steer only) |
| Last light | `last_light.py` | Agent and pilot final reports always end with a deterministic "Not covered in this run" list: open coverage cells by class, open hypotheses, unconfirmed candidates, tester-loop steps that never ran. | None |
| Provider cooldown | `provider_cooldown.py` | A billing, quota or bad-key failure puts that provider (per org) in cooldown: 1 min, then 5, then 30. Cooling providers move to the back of the fallback chain; a success clears it. | None |
| Run purse | `run_purse.py` | One spend account per run for every model call, including fireteam specialists. A specialist starts only if its spend cap can be reserved; 5% of the limit is kept for the final report. | Uses the existing `price_limit_usd` |

## Measuring them

Compare runs with a switch on and off on the class lab
(`harness/local_harness/benchmark/class_lab_manifest.py`), holding the planner
model fixed. Useful measures: false-positive rate, confirmed findings per
dollar, and injection cases that got through. Run `hindsight_mode` in `shadow`
first; its log line (`hindsight: org=… notes=…`) shows what would have been
injected.

## Limits

- The run purse uses estimated token prices (`observability.MODEL_PRICING`);
  models without a price entry are charged at a default of $3 / $15 per
  million input / output tokens, which overstates local open models.
  Specialist spend from earlier runs of the same session is not carried into a
  new run.
- Cold trails and Full Pursuit guidance are prompt steers. The render
  requirement and Last light are enforced in code.
