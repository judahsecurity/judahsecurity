# Running Aegis Vanguard for real

The verification + detection pipeline (flag oracle, proof gate, OOB, authz
matrix, JS analysis, fingerprinting, Caido, interaction crawl, scorecard) is
implemented and tested. This is how you actually run it against a target and get
measured results. **Only run against targets you are authorized to test.**

## 1. Preflight

```bash
cd aegis-vanguard
python3 doctor.py          # tells you exactly what's missing on this box
```

Fix every ❌ (required). `doctor.py --json` for CI.

## 2. Install the runtime

```bash
pip install -r requirements.txt
playwright install chromium          # the interaction crawl + DOM XSS prover need a real browser
export ANTHROPIC_API_KEY=sk-ant-...  # or AEGIS_LLM_BACKEND=litellm + AEGIS_MODEL
```

External recon CLIs (subfinder/nuclei/katana/…) are checked by `healthcheck.py`;
the Docker image installs them. They widen recon but are not required to run.

## 3. (Optional) Caido for full browse capture

```bash
# run Caido with its proxy listener + GraphQL API up, then:
export AEGIS_BROWSER_PROXY=http://127.0.0.1:8080     # browser routes through Caido
export AEGIS_CAIDO_API=http://127.0.0.1:8080/graphql
export AEGIS_CAIDO_TOKEN=...                          # if the API needs auth
```

See `docs/caido.md`. Without Caido, `browser_crawl` still captures the full
surface via Playwright into the session store.

## One command (preflight → run → score)

```bash
export ANTHROPIC_API_KEY=sk-ant-...            # set in your env, never inline it
./assess.sh https://app.example.com --scope example.com --login-user tester --login-pass "$PW"
./assess.sh http://host.docker.internal:PORT/ --no-guardrails --max-risk critical --expected-flag "$FLAG"
```

`assess.sh` runs `doctor.py` (aborts if not ready), then `run_pentest.py` with
everything after the URL passed through, then `scorecard.py` — writing artifacts
to `AEGIS_TRACES_DIR` (default `./results/<timestamp>/`). The manual steps below
are the same thing broken apart.

## 4. Run against a target

**Benchmark / lab (internal host, has a known flag):**

```bash
export AEGIS_EXPECTED_FLAG='FLAG{...}'
export AEGIS_TRACES_DIR=./results/run1        # where artifacts land
python3 run_pentest.py --target http://host.docker.internal:PORT/ \
    --no-guardrails --max-risk critical --expected-flag "$AEGIS_EXPECTED_FLAG"
```

`--no-guardrails --max-risk critical` is required for internal/benchmark hosts —
otherwise the guardrails + Aegis Praetorium reject every tool call (the original
all-blocked run). Keep guardrails ON for real external engagements.

**Real external engagement (authorized scope):**

```bash
export AEGIS_TRACES_DIR=./results/acme
python3 run_pentest.py --target https://app.example.com --scope example.com \
    --login-user tester --login-pass '...'      # for authenticated + authz-matrix coverage
```

The run writes, into `AEGIS_TRACES_DIR`: `flag_captures_*.json`, `grade_*.json`
(if a flag was expected), `proof_gate_*.json`, `findings_*.json`, and
`VULN-FINDINGS_*.md`. The FLAG VERIFICATION and PROOF GATE banners print at the
end. Only proof-token-backed findings are documented as CONFIRMED.

## 5. Measure and iterate

```bash
python3 scorecard.py --runs ./results/acme --out scorecard.json    # baseline
# ...change a hunter/prompt, re-run...
python3 scorecard.py --runs ./results/acme --baseline scorecard.json   # exit 1 on regression
```

Commit the baseline `scorecard.json`. Wire the `--baseline` form into CI so a
change that drops the confirmed rate, misses flags, or raises the
needs-evidence share fails the build. Flag-only grading: `grade_xben.py`.

## 6. What runs where

| Capability | Env / prerequisite |
|---|---|
| interaction crawl + DOM-XSS proof | Playwright + `playwright install chromium` |
| full browse capture | above; optional Caido via AEGIS_BROWSER_PROXY |
| authz matrix (missing-auth) | recorded authenticated traffic (crawl/login) |
| authz matrix (horizontal IDOR) | a second account's session (identity_b headers) |
| OOB proof (blind SSRF/RCE) | target can reach the local listener, or AEGIS_OOB_POLL_URL |
| flag grading | AEGIS_EXPECTED_FLAG |

## The honest status

Every layer is implemented and unit-tested, but nothing here has been run
against a live target yet — that step is yours, because it needs an authorized
target, a browser, and an LLM key this repo's sandbox does not have. Do a first
real run, commit the scorecard, and the numbers become the thing we iterate on.
