# Agent work ledger and reliability rollout

The agent writes a run row before runtime initialization, records model calls,
tool actions, recon work, specialist outcomes, and hypothesis coverage, and
returns a partial work report when its budget expires. The **Work performed**
panel reads the same authenticated ledger while a run is active.

## Deploy

1. Use a separate Terraform project name and state for staging. Apply
   `aws/terraform/main.tf` with `environment=staging` and that project name.
   This creates encrypted EFS storage mounted at `/app/data/evidence` on API
   tasks. The task role is limited to the agent evidence access point.
2. Deploy from a clean commit with
   `PROJECT_NAME=<staging-project> aws/scripts/deploy.sh api staging`.
   The script refuses to use the default production project name for staging,
   checks that the API task has the EFS volume, pushes the API image, runs and
   verifies the ledger schema migration task, then updates the service.
3. Run the authenticated check from the backend directory:

   ```bash
   AEGIS_API_TOKEN=<staging-token> python -m scripts.check_agent_ledger \
     --base-url https://<staging-host> --session-id <agent-session-id> --wait 90
   ```

   A terminal assessment should have nonempty, internally consistent action
   receipts. The check is read-only. The database migration can also be run
   directly with `python -m scripts.apply_agent_ledger_migration` in a backend
   environment connected to the intended database.

The API prunes expired evidence files every six hours. Retention defaults to
24 hours through `AEGIS_EVIDENCE_RETENTION_SECONDS`. Evidence is redacted on
write, but it can still contain sensitive assessment data, so access to the
EFS file system and its backups should remain restricted.

## Measure detection and efficiency

Run baseline and candidate product agents against the same authorized lab
targets, identities, scope, turn and iteration limits, and price limit. The
product harness writes `agent_ledger.json` and `product_assessment.json` beside
`AEGIS_FINDINGS_SINK`; it fails a real run if receipts are missing or left open.
Compare the two output directories with:

```bash
PYTHONPATH=backend:harness python -m local_harness.ledger_compare \
  <baseline-output-dir> <candidate-output-dir>
```

Track completed tests, repeated tool/target actions, timeouts, elapsed time,
verified findings, and known-vulnerability recall. A clean result requires
evidence of completed negative tests; zero findings alone does not establish
coverage. Compare finding quality against ground truth before claiming that
the new scheduler detects more vulnerabilities.

## Steering and hunt-discipline experiments

Two flags let the model lead more of an assessment. Both are off by default,
so production behavior is unchanged until you enable them. Measure each one
separately against a strict baseline with the comparison above.

| Setting | Default | Effect |
|---|---|---|
| `AGENT_STEERING_MODE` | `strict` | `advisory` turns post-map pipeline steps (enrichment, JS mining, threat-model sync, fireteam waves) into a suggestion in Joshua's prompt. |
| `AGENT_STEERING_FREE_TURNS` | `2` | In advisory mode, how many of its own decisions the model gets after the last forced step before the suggested step is forced (0-10). |
| `AGENT_HUNT_DISCIPLINE_PROMPT` | `false` | Adds hunting rules to Joshua and every specialist: exhaust bypasses before recording a negative, depth over breadth, keep 2-3 routes open, re-examine weak negatives once, hand off side clues. Also replaces the specialist rule "If unsure, finish with done=true". |

Advisory mode never defers the initial application map (crawl, map,
inspect_js), proof bookkeeping (candidate handoff, independent_verify,
create_finding), CVE-applicability steps, or bounded pilots. The completion
gate is unchanged in both modes, so the model cannot finish before coverage is
met. Each deferral is logged as `Advisory steering: deferring pipeline step`.

Suggested sequence: strict baseline, then `AGENT_HUNT_DISCIPLINE_PROMPT=true`,
then that plus `AGENT_STEERING_MODE=advisory`, all at the same budget.

## Custom probes (run_custom_probe / run_poc_python)

Specialists can write one-off Python HTTP probes. The original in-process
runner executed them inside the backend container behind AST checks, and those
checks are bypassable: module attributes reach `os` (shell as the backend user),
`codecs` (file reads), and raw `urllib`/`httpx` transports (any host). Because
probe source is model-written and target content can steer the model, the tool
is now controlled by `AGENT_CUSTOM_PROBE_MODE`:

| Mode | Behavior |
|---|---|
| `off` (default) | Tool refused and removed from specialist tool lists. |
| `isolated` | Script runs in `probe-runner` via `probe-egress`. |
| `inprocess` | Legacy runner in the backend container. Isolated lab hosts only. |

`isolated` architecture (`backend/probe_sandbox/`, compose profile
`probe-sandbox`):

- `probe-runner` is attached only to `probe_net`, an `internal: true` network
  with no route out. It holds no backend code, secrets, or volumes, runs with
  a read-only root and dropped capabilities, and executes each script as uid
  65534 with CPU, memory, file and process limits. Scripts cannot read the
  runner's environment.
- `probe-egress` bridges `asm_network` and `probe_net`. Its relay (port 9000)
  accepts jobs from the backend, registers that job's scope, and hands the
  runner a one-job proxy credential. Its proxy (port 3128) allows only
  in-scope hosts plus OAST suffixes, refuses names that resolve only to
  private, loopback, link-local or metadata addresses, connects to the address
  it checked, caps requests per job, and returns an egress log with the result.

Enable:

```bash
echo "AGENT_PROBE_RUNNER_TOKEN=$(openssl rand -hex 24)" >> .env
echo "PROBE_RUNNER_TOKEN=$(openssl rand -hex 24)" >> .env
echo "AGENT_CUSTOM_PROBE_MODE=isolated" >> .env
docker compose --profile probe-sandbox up -d --build probe-egress probe-runner backend autonomy-worker
```

Known limits: HTTPS through the proxy is tunneled, so request/response bodies
are not recorded (the egress log has host, port, method and verdict). DNS
queries from the runner go to Docker's embedded resolver. Lab targets on
private addresses need `PROBE_ALLOW_PRIVATE_TARGETS=true` on `probe-egress`.
