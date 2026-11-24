# Prowl efficiency benchmark runbook

Measures whether the ARTEX-inspired changes raise verified findings without
raising false positives or cost. Every arm uses the same model, targets,
scope, identities and budget; only the settings below change.

## Arms

| Arm | Code | Settings |
|---|---|---|
| A. Baseline | `beb276e` (the branch point on `main`) | defaults |
| B. Changes, default settings | `claude/great-maxwell-17cln5` | defaults (caching, shell unlock, retest, goals, thin-negative re-check, script sandbox, candidate signal, compaction, prior engagement) |
| C. B + rolling dispatch | same branch | `FIRETEAM_ROLLING_DISPATCH=true` |
| D. C + bigger budgets | same branch | `FIRETEAM_ROLLING_DISPATCH=true AGENT_SPECIALIST_TURN_MULTIPLIER=2.5` |

Run arm D with matching schedule caps if you use scheduled runs
(`max_specialist_tool_calls`, `max_specialist_seconds`).

Use a fresh organization (or delete the earlier runs' snapshots under
`~/.aegis/sessions`) for each arm. Otherwise arm B onwards picks up the
previous arm's run through the previous-engagement summary, which is not a
fair comparison.

## Targets

```bash
docker run -d --rm --name juice -p 3000:3000 bkimminich/juice-shop
```

```bash
docker run -d --rm --name vampi -p 5000:5000 -e vulnerable=1 erev0s/vampi
```

Plus the 15-class lab in `harness/README.md` (it has known positives and
negatives, so it measures false positives directly).

## One run

From `harness/`, once per arm and target, with a fresh sink folder each time:

```bash
ARM=C TARGET=http://127.0.0.1:3000 NAME=juice
OUT="$PWD/runs/efficiency/$ARM-$NAME"; mkdir -p "$OUT"
FIRETEAM_ROLLING_DISPATCH=true \
AEGIS_FINDINGS_SINK="$OUT/findings.jsonl" \
AEGIS_ASSESSMENT_DATABASE_URL="$DEDICATED_ASSESSMENT_DATABASE_URL" \
  python -m local_harness.product_agent --target "$TARGET" --scope "$TARGET" \
    --organization-id "$BENCH_ORG_ID" --user-id "$BENCH_USER_ID" \
    --max-turns 4 --max-iterations 30 --price-limit-usd 5
```

Check out `beb276e` for arm A (a separate worktree keeps it simple:
`git worktree add ../prowl-baseline beb276e`).

## Compare

```bash
python -m local_harness.ledger_compare runs/efficiency/A-juice runs/efficiency/C-juice
```

This reports actions, test actions, repeated calls, timeouts, published
findings, duration and `model_refusals`, plus `refusals_by_role` for each arm.
Cost is in each `product_assessment.json` (`cost_usd`, `token_usage`,
including `cache_read_tokens`).

For finding quality, score each `findings.jsonl` against the target's known
issues (the class lab does this with `product_class_benchmark`; for Juice Shop
and VAmPI, review each verified finding by hand or with the harness judge).
Keep a change only if verified findings go up, false positives stay flat, and
cost per verified finding does not rise.

## What to read from the results

- **C vs B:** does starting work mid-round find more in the same budget?
- **D vs C:** is specialist budget what limits recall? If findings rise with
  little cost, raise the default multiplier.
- **`refusals_by_role`:** a role losing more than a few percent of its calls
  to refusals is a candidate for a different model. Compare one open model
  on that role only, with the verifier and report writer unchanged.
- **Run Ledger:** `unverified_candidate` and `candidate_verdict` entries show
  how long candidates wait for verification.
