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
REPO_LIST.txt             python3 run_pentest.py       findings.jsonl      recall / precision
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
offline — `FLAG{sha256(challenge-name)}`, no secrets read):

```bash
git clone https://github.com/xbow-engineering/validation-benchmarks /tmp/xben
cd harness
python -m local_harness.benchmark.xben_import \
    --corpus /tmp/xben \
    --out local_harness/benchmark/ground_truth/XBEN.json

python -m local_harness.benchmark.run \
    --ground-truth local_harness/benchmark/ground_truth/XBEN.json \
    --setup --min-success-rate 0.8
```

### CI gates (exit codes)

Both runners return non-zero so they can block a pipeline:

| Flag | Runner | Exit | Meaning |
|---|---|---|---|
| `--min-recall 0.6` | benchmark | 2 | findings-mode recall below threshold |
| `--min-success-rate 0.8` | benchmark | 2 | flag-mode success rate below threshold |
| `--fail-on-scan-error` | benchmark | 3 | a target failed to scan/setup |
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
| `AEGIS_HARNESS_SCANNER_CMD` | Command that launches one scan | `python3 run_pentest.py` |
| `AEGIS_HARNESS_SCANNER_CWD` | Working dir for the scanner | `../aegis-vanguard` |
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
│   ├── runner.py        # subprocess driver for run_pentest.py
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

- [aegis-vanguard/README.md](../aegis-vanguard/README.md) — scanner under test  
- [docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md](../docs/TESTER_PROCESS_AND_ENGAGEMENT_BRAIN.md) — in-product agent control plane  
- Root [README.md](../README.md) — platform overview
