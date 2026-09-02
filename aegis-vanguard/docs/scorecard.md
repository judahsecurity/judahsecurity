# Performance scorecard (`scorecard.py` / `agent/scorecard.py`)

Turns the artifacts a run emits into an objective performance number you can
track across iterations — and fails loudly when a change makes the agent worse.
This is the measurement half of the verification stack: the oracles produce
evidence, the scorecard scores it.

## Inputs

Per run, in the output dir:
- `findings_<sid>.json` — the proof-gated findings document (`build_findings_document`)
- `grade_<sid>.json` — the flag verdict (from the flag oracle), when a benchmark
  had an expected flag

## Metrics

| Metric | Meaning |
|---|---|
| `flag_pass_rate` | of benchmarks with an expected flag, how many were captured |
| `overall_confirmed_rate` | confirmed / total findings — the **precision of "confirmed"** |
| `needs_evidence` (+ share) | findings that could not earn a proof token — the false-positive pressure the gate absorbs |
| `proof_tokens` by kind | where evidence came from (flag / response_diff / browser_exec / oob) → coverage across vuln classes |

## Usage

```bash
# Score a suite of runs and save the scorecard
python3 scorecard.py --runs results/ --out scorecard.json

# Gate a change: exit 1 if any metric regressed vs the last scorecard
python3 scorecard.py --runs results/ --baseline scorecard.json --tolerance 0.02
```

Wire the baseline form into CI so a hunter/prompt change that drops the
confirmed rate, misses flags, or raises the needs-evidence share blocks the
merge instead of shipping silently.

## Note

This scores artifacts a run produced; it does not run the agent. Generate the
artifacts by running `run_pentest.py` against authorized targets (set
`AEGIS_TRACES_DIR` / expected flags), then point `--runs` at that directory.
Flag pass/fail alone is also available via `grade_xben.py`.
