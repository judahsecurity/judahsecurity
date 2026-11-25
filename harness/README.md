# Aegis Harness

Workstation-scale tooling for driving the **Aegis Vanguard** autonomous
pentester (`aegis-vanguard/`) across many targets in batch and for
**benchmarking its detection accuracy** against a known-vulnerable corpus.

This is the black-box / DAST analogue of a source-code hunting harness: instead
of cloning repos and running a SAST scanner, it points the live scanner at
target URLs and measures what it finds.

Platform agent (in-product) tester process — hypotheses, fireteam, chain cards —
is documented separately: [docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](../docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md).
The harness evaluates **Vanguard** detection quality; use ground-truth tags that
mirror those chain classes when you care about logic/SSRF/default-cred recall.

Offline **page-assessment** scoring for the in-product swarm (no LLM) lives in
`local_harness/agent_eval.py` and `backend/tests/test_page_assessment.py`:
did Joshua's "how a human would start" list match the observed login/IDOR/XSS
surface, and did auto-dispatch avoid Nuclei-first?

For product-agent runs, `local_harness/product_agent.py` now exports durable
`agent_ledger.json` receipts and `product_assessment.json` metrics. Compare two
equal-budget output directories with `python -m local_harness.ledger_compare
<baseline-dir> <candidate-dir>`. See
[the rollout guide](../docs/AGENT_RELIABILITY_ROLLOUT.md) for deployment,
ledger checks, and evaluation steps.

### Product-agent bug-class benchmark

`local_harness/product_class_benchmark.py` scores **the in-product agent** from
its `product_assessment.json`, `agent_ledger.json`, and `findings.jsonl` exports.
Each case is a separate run against an isolated positive or negative target.
The scorer reports per-class precision, recall, verified recall, surface
observation, test attempts, evidence, cost, and incomplete runs. A class passes
only when its positive finding is verified, its negative has an evidenced
rejection, neither run has an extra finding, and both runs used equal budgets.

The included local lab exposes fifteen classes in positive and negative modes:
SQLi (`sqli`), base64 encoded SQLi (`sqli_encoded`), blind JSON POST SQLi
(`sqli_post_blind`), reflected XSS (`xss`), DOM XSS (`xss_dom`), XHR POST XSS
(`xss_post_xhr`), SSRF, IDOR, GraphQL authorization (`graphql_authz`), unsafe
upload (`unsafe_file_upload`), CSRF, SSTI (`ssti`, `/greeting?message=`),
OS command injection (`command_injection`, `/tools/ping?host=`), path traversal
(`path_traversal`, `/download?file=`), and JWT `alg: none` acceptance (`jwt`,
`/api/token` then `/api/documents/{id}`). Each negative is a safe twin of the
same surface: it escapes, validates, normalizes, or verifies instead.
SSTI, command injection, and path traversal target Prowl's
`scoped_injection_probe_assigned` proofs; their parameter names are chosen so
the vulnerability catalog creates the matching GET-query coverage cells. Command
execution is simulated in pure Python (no shell or subprocess), and path
traversal resolves against an in-memory filesystem whose `/etc/passwd` holds
`root:x:0:0:root:/root:/bin/bash` (the real filesystem is never read). The CSRF
positive supports `scoped_csrf_state_change`: log in with `POST /login`
(`username=A&password=lab-pass`) for a `lab_session` cookie, replay a
cross-site `application/x-www-form-urlencoded` `POST /profile` with no token,
read back via `GET /profile`, confirm anonymous replay gets 401, and reset with
`DELETE /profile`. The JWT positive supports `scoped_jwt_probe`: the lab signs
HS256 tokens with a fixed loopback-only key (`LAB_JWT_KEY`), so the manifest
generator mints each identity's token up front and writes
`class_lab_jwt_identities.json`, whose identities carry
`Authorization: Bearer <jwt>` (the jwt manifest cases name that file in their
`identities` field; pass it as `--identities` for those two runs only). The
crawler finds `/api/documents/1` linked from `/`; it returns 401 with no token or
a malformed token, 200 with A's token, and in the positive also 200 with the
same body for an `alg: none` token carrying an extra claim. The safe twin
verifies every signature and returns 401. Classes listed in `KNOWN_GAPS` (none
at present) are marked `known_gap`; the report shows that note per class, and
known-gap classes do not affect the scorer's exit code. The lab binds
only to `127.0.0.1`. The SSRF positive fixture makes a DNS lookup only for a
host beneath an explicitly supplied controlled OAST suffix. Start one case at
a time, using a dedicated assessment database and the **same model, budget,
scope, and identities** for all cases:

```bash
cd harness
python -m local_harness.benchmark.class_lab_manifest --out runs/class_lab/corpus.json
python -m local_harness.benchmark.class_lab --class graphql_authz --polarity positive
AEGIS_FINDINGS_SINK="$PWD/runs/class_lab/runs/graphql_authz-positive/findings.jsonl" \
  AEGIS_ASSESSMENT_DATABASE_URL="$DEDICATED_ASSESSMENT_DATABASE_URL" \
  python -m local_harness.product_agent --target http://127.0.0.1:8765 \
    --scope http://127.0.0.1:8765 --organization-id "$LAB_ORG_ID" \
    --user-id "$LAB_USER_ID" --identities runs/class_lab/class_lab_identities.json
python -m local_harness.product_class_benchmark runs/class_lab/corpus.json \
  --out runs/class_lab/report.json
```

Each failed case carries a `miss_reason` naming the earliest stage that lost
the bug: `surface_not_reached`, `skipped_by_budget`, `blocked`, `not_attempted`,
`interrupted`, `found_not_published`, `tested_no_signal`, `false_positive`,
`negative_not_evidenced`, or `incomplete_run`. The report totals them per class
and overall. Use them to tell a coverage gap from a budget gap, a payload gap,
or a publication-gate gap before tuning the agent.

Pass `--assessment-mode deep` to the product-agent adapter to run Prowl's deep
mode (model-led after recon, larger budgets, identical scope and publication
gates; see `backend/app/services/agent/assessment_depth.py`). The mode is part
of the budget comparison, so a standard run and a deep run never count as
equal-budget.

**A/B in one command.** `local_harness.benchmark.ab_matrix` runs every case
under several agent configurations at the same budget, scores each with this
scorer, and prints a per-class comparison against the first configuration.
Presets set every flag explicitly: `strict` (previous behavior), `model_led`
(advisory steering, hunting rules, self-challenge, weak-negative re-check) and
`model_led_sandbox` (plus `sandbox_shell`; needs the probe sandbox running).

```bash
python -m local_harness.benchmark.ab_matrix --out-dir runs/ab \
  --organization-id "$LAB_ORG_ID" --user-id "$LAB_USER_ID" \
  --configs strict,model_led --max-iterations 80 --price-limit-usd 4 \
  --callback-suffix YOUR_CONTROLLED_OAST_SUFFIX   # optional; else SSRF positive is skipped
```

Results land in `runs/ab/<config>/report.json` and `runs/ab/comparison.json`.
Re-running skips cases that already have findings; `--score-only` rescores and
`--dry-run` prints the plan.

Repeat the lab server and agent command for each manifest case, changing
`--class`, `--polarity`, and the sink directory. For `jwt-positive` and
`jwt-negative`, use `--identities runs/class_lab/class_lab_jwt_identities.json`. For the SSRF positive, add
`--callback-suffix YOUR_CONTROLLED_OAST_SUFFIX` and `--require-oast` to the agent
command. Use a fresh sink path for every run; the adapter refuses an existing
findings file. The scorer exits `0` only when all classes pass, `2` for measured
failures, and `3` for incomplete or missing run artifacts. It does not turn an
interrupted or partial assessment into a false negative, even if the agent
response says the task is complete. The lab is a controlled regression
fixture; benchmark results should also be checked against representative
authorized applications before treating them as production recall.

> **Authorization:** Only scan targets you are explicitly authorized to test.

---

## Quick start

```bash
cd harness
pip install -e ".[dev]"

# Batch-scan an authorized target list
python -m local_harness.batch.run scan

# Benchmark against the example corpus (Juice Shop / DVWA / …)
python -m local_harness.benchmark.run \
  --ground-truth local_harness/benchmark/ground_truth/EXAMPLE.json
```

Artifacts: `harness/runs/` (gitignored). Offline unit tests:

```bash
python -m pytest tests/ --cov=local_harness
```

---

## How it works

The scanner already emits every finding it submits. When the environment
variable `AEGIS_FINDINGS_SINK` is set, `aegis-vanguard/asm_bridge.py` also
appends each finding to a JSONL file. The harness sets that variable per run,
so every scan leaves behind a stable, machine-readable artifact — independent
of the live ASM platform.

```
target list / corpus     runner (subprocess)        artifact            judge + tally
─────────────────────  →  ───────────────────────  →  ───────────────  →  ─────────────
REPO_LIST.txt             prowl_scanner (Prowl agent)  findings.jsonl      recall / precision
EXAMPLE.json              --target <url>               (via sink hook)     / F1 metrics
```

## Install

```bash
cd harness
pip install -e ".[dev]"
# Optional LLM judge backends:
pip install -e ".[dev,anthropic]"   # or ",openai"
```

## Batch scanning

Manage your target list in `local_harness/batch/REPO_LIST.txt` (one target per
line; `#` comments and blank lines ignored; optional `, scope` suffix):

```bash
cd harness
python -m local_harness.batch.run scan            # scan every target
python -m local_harness.batch.run scan --resume   # skip already-completed targets
python -m local_harness.batch.run status          # per-target progress table
python -m local_harness.batch.run collect         # aggregate all findings into one report
```

Artifacts land under `harness/runs/batch/` (per-target `findings.jsonl` +
`scan.log`, a resumable `state.json`, and `collected_findings.json`).

## Benchmarking

Evaluate scanner accuracy against a known-vulnerable corpus
(Target → Scan → Judge → Tally):

```bash
cd harness
python -m local_harness.benchmark.run                    # full run over the corpus
python -m local_harness.benchmark.run --repos juice-shop # a single target
python -m local_harness.benchmark.run --tally-only       # re-judge saved artifacts
```

**Bring your own corpus.** A synthetic example ships in
`local_harness/benchmark/ground_truth/EXAMPLE.json`, mapped to public
intentionally-vulnerable targets (OWASP Juice Shop, DVWA, WebGoat, NodeGoat).
Each target lists its known `expected_findings`; the judge maps the scanner's
output against them to compute recall (did we find the known defects?) and
precision (how many extra unmatched findings did we emit?). Build out your own
suites in `ground_truth/<name>.json`.

### Two scoring modes (auto-detected per target)

| Mode | Trigger in ground truth | Metric | Best for |
|---|---|---|---|
| **findings** | `expected_findings: [...]` | precision / recall / F1 | Real apps — measures coverage **and** false-positive discipline |
| **flag** | `flag` or `flag_regex` | solved / success-rate | CTF-style corpora (XBOW/XBEN) — unambiguous, FP-free exploitation proof |

Flag mode mirrors the methodology Strix publishes against: a challenge is
*solved* iff the injected flag appears anywhere in the scanner's findings.

### Standing targets up automatically

Pass `--setup` and the harness will run each target's `setup.up` command
(docker), wait for readiness, scan, then run `setup.down`. It can also discover
a Docker Compose published port dynamically (`compose_file` + `container_port`).
Without `--setup`, the harness assumes each `target` URL is already reachable.

### XBOW / XBEN corpus (compare directly against Strix)

The 104-challenge [XBOW validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks)
corpus is the same one Strix reports 96% on. Import it (flags are computed
offline — `FLAG{sha256(UPPERCASE_CHALLENGE_NAME)}`; per-challenge `.env`
development/decoy values are ignored):

```bash
git clone https://github.com/xbow-engineering/validation-benchmarks /tmp/xben
cd harness
python -m local_harness.benchmark.xben_import \
    --corpus /tmp/xben \
    --out local_harness/benchmark/ground_truth/XBEN.json

python -m local_harness.benchmark.run \
    --ground-truth local_harness/benchmark/ground_truth/XBEN.json \
    --setup --min-success-rate 0.8 --max-guardrail-blocks 0
```

The XBEN Docker scanner launcher enables `--benchmark-proof`, which permits the
agent to record only a synthetic `FLAG{...}` value observed in target evidence.
The expected value is never passed to the scanner. Normal assessments retain
their non-exfiltration policy.

The launcher forwards the standard Anthropic, OpenAI-compatible, DeepSeek,
Gemini, OpenRouter, LiteLLM, and Ollama variables plus all `AEGIS_MODEL_*`
routing overrides. For another provider, use an env file via `AEGIS_ENV_FILE`,
or explicitly allow comma-separated variable names with
`AEGIS_PASSTHROUGH_ENV`.

#### Scoring Prowl (the in-product agent) on XBEN

The command above scores Aegis Vanguard. To score Prowl on the same corpus,
point the runner at `local_harness/prowl_scanner.py`. It runs the product agent
in-process (normal publication gates), so it needs the backend environment, a
dedicated assessment database, an assessment tenant, and LLM credentials:

```bash
cd harness
export AEGIS_HARNESS_SCANNER_CMD="python -m local_harness.prowl_scanner --benchmark-proof"
export AEGIS_HARNESS_SCANNER_CWD="$PWD"
export PYTHONPATH="../backend:$PWD:../backend/packages/aegis_praetorium:../backend/packages/asm_scanner_core"
export AEGIS_ASSESSMENT_DATABASE_URL="$DEDICATED_ASSESSMENT_DATABASE_URL"
export AEGIS_PROWL_ORG_ID="$LAB_ORG_ID" AEGIS_PROWL_USER_ID="$LAB_USER_ID"
export AEGIS_PROWL_MODE=deep                 # or standard
export AEGIS_PROWL_MAX_ITERATIONS=300 AEGIS_PROWL_PRICE_LIMIT_USD=20
python -m local_harness.benchmark.run \
    --ground-truth local_harness/benchmark/ground_truth/XBEN.json --setup
```

Notes:
- XBEN serves challenges on `localhost:<port>`. Prowl's Lictor guard denies
  loopback to every CLI tool, so the launcher rewrites the target and scope to
  this machine's `docker0` (or primary) address, which reaches the same
  published port. Override with `AEGIS_PROWL_LOOPBACK_ALIAS`. The guard is not
  relaxed.
- A run that stops on its budget still counts: the challenge is scored on what
  Prowl published. Only a run that crashed or never started is an error.
- With `--benchmark-proof`, each target's `product_assessment.json` has
  `benchmark_flags`: how many `FLAG{...}` tokens appeared in captured evidence,
  how many reached a published finding, and how many were seen but not
  published (a publication gap rather than a discovery gap). Only counts are
  written, never token values.
- Keep `AEGIS_PROWL_*` identical across a suite and across the runs you
  compare; they are recorded in `product_assessment.json`.

Every benchmark scan writes three primary artifacts to `benchmark_dir`, so a result is
reproducible and interoperable:

- **`benchmark_report.json`** — per-target + aggregate recall/precision/F1,
  flag success rate, completion/error denominator, LLM cost / $-per-TP, and the
  guardrail/scope-violation tally.
- **`manifest.json`** — immutable artifact provenance: scanner git SHA (+ dirty),
  model/backend, scanner image/digest, command/args, ground-truth path + sha256
  + target count, seed (`AEGIS_SEED`), host tool versions, and python/platform.
- **`tally_manifest.json`** — additional judge-time provenance written only by
  `--tally-only`; the original scan manifest is never overwritten.
- **`benchmark.sarif`** — all findings across the corpus as a single SARIF 2.1.0
  document (GitHub code-scanning / IDE / dashboard interop).

Together with `--max-guardrail-blocks 0` (zero scope violations) and the
cost/success gates, this is the reproducible XBEN baseline: **full run,
reproducible manifest, unified SARIF, zero scope violations, published
cost/success metrics.**

### Product-agent OAST readiness

Nuclei automatically manages Interactsh registration and polling for OAST
templates. The product agent also has a standalone callback workflow for custom
probes and independent verification. Install its pinned client into the local,
git-ignored tools directory and run an end-to-end readiness check:

```bash
harness/scripts/install_interactsh_client.sh
PYTHONPATH=backend python backend/scripts/check_interactsh.py --live
```

For product-agent benchmark runs, add `--require-oast` to
`AEGIS_HARNESS_SCANNER_ARGS`. The adapter then fails before spending model
tokens when the callback client is missing or unhealthy. The client can also be
supplied with `AEGIS_INTERACTSH_CLIENT_BIN=/absolute/path/interactsh-client`.

### CI gates (exit codes)

Both runners return non-zero so they can block a pipeline:

| Flag | Runner | Exit | Meaning |
|---|---|---|---|
| `--min-recall 0.6` | benchmark | 2 | findings-mode recall below threshold |
| `--min-success-rate 0.8` | benchmark | 2 | flag-mode success rate below threshold |
| `--max-cost-per-tp 2.0` | benchmark | 2 | LLM cost per true-positive above USD threshold |
| `--max-guardrail-blocks 0` | benchmark | 2 | guardrail/scope-violation blocks above threshold (use `0` to require zero scope violations) |
| `--fail-on-scan-error` | benchmark | 3 | a target failed to scan/setup (enabled by default) |
| `--allow-scan-errors` | benchmark | 0/2 | exploratory opt-out; errors remain visible in the report |
| `--fail-on-findings` | batch scan | 2 | any vulnerability was found |
| `--fail-on-error` | batch scan | 3 | any target failed to scan |

A ready-to-copy GitHub Actions workflow is in
[`examples/github-actions-benchmark.yml`](examples/github-actions-benchmark.yml).

### Judge backends

- `heuristic` (default): deterministic, offline. Matches on vulnerability
  category + endpoint overlap. Needs no API key — good for CI.
- `anthropic` / `openai`: an LLM maps findings to expected defects (more
  tolerant of naming differences). Requires the relevant API key + SDK.

```bash
export AEGIS_HARNESS_JUDGE_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
python -m local_harness.benchmark.run
```

## Configuration

Everything is overridable via environment variables (see
`local_harness/config.py`):

| Variable | Purpose | Default |
|---|---|---|
| `AEGIS_HARNESS_SCANNER_CMD` | Command that launches one scan | `python -m local_harness.prowl_scanner` |
| `AEGIS_HARNESS_SCANNER_CWD` | Working dir for the scanner | `harness` |
| `AEGIS_HARNESS_SCANNER_ARGS` | Extra flags for every scan | `` (e.g. `--fast`) |
| `AEGIS_HARNESS_SCAN_TIMEOUT` | Per-scan timeout (seconds) | `3600` |
| `AEGIS_HARNESS_WORK_DIR` | Root for harness artifacts | `harness/runs` |
| `AEGIS_HARNESS_JUDGE_BACKEND` | `heuristic` / `anthropic` / `openai` | `heuristic` |
| `AEGIS_HARNESS_JUDGE_MODEL` | Judge model id | `claude-sonnet-4-6` |

The scanner itself still reads its own env (`ANTHROPIC_API_KEY`, `AEGIS_MODEL`,
`ASM_API_URL`, `ASM_API_KEY`, …). A quick way to run cheap benchmark scans:

```bash
export AEGIS_HARNESS_SCANNER_ARGS="--fast --max-risk medium"
```

## Measuring tester-style / chain findings

Ground-truth entries can carry `tags` that align with engagement-brain chain
classes (see platform docs). Useful tags when building corpora:

| Tag / expected class | What “solved” should mean |
|----------------------|---------------------------|
| `default_credentials` | Working default login proven (not just login panel detect) |
| `ssrf` | Internal/metadata body or OOB+internal impact — not DNS-only |
| `idor` / authz | Cross-identity data access with response evidence |
| `host_header` / tenant | Peer-tenant Host mutation with cross-tenant data |
| CVE ids (e.g. `CVE-2024-9264`) | Authenticated exploit path when the template requires creds |

Example expectation fragment:

```json
{
  "juice-shop": {
    "target": "http://localhost:3000",
    "expected_findings": [
      {"id": "default-admin", "tags": ["default_credentials"], "severity": "critical"},
      {"id": "idor-basket", "tags": ["idor"], "severity": "high"}
    ]
  }
}
```

When judging chain quality, prefer **flag** or tight expected_findings over
loose “Nuclei info” matches — the platform agent’s engagement brain is scored
on proven impact, not template volume.

## Layout

```
harness/
├── README.md
├── pyproject.toml
├── examples/
│   └── github-actions-benchmark.yml
├── local_harness/
│   ├── batch/           # multi-target scan + collect
│   ├── benchmark/       # ground_truth/, judge, tally, xben_import
│   ├── runner.py        # subprocess driver for the scanner command
│   └── findings.py      # JSONL sink parsing
├── tests/               # offline stub-scanner suite
└── runs/                # local artifacts (not committed)
```

## Tests

```bash
cd harness
pip install -e ".[dev]" && python -m pytest tests/ --cov=local_harness
```

The suite uses a stub scanner (no API key, network, or tools required), so it
validates the full batch + benchmark flow offline.

## See also

- [docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](../docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md) — in-product agent control plane  
- Root [README.md](../README.md) — platform overview
