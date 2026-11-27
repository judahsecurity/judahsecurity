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

## Hunt engine (on by default in docker-compose)

`AGENT_HUNT_ENGINE` (off in config, `true` in `docker-compose.yml`) runs an
LLM planner and parallel specialists over what the deterministic first pass
found. The pipeline starts it by itself as soon as the first pass raises a
signal (proof signal or inconclusive), ahead of enrichment; a run with no
signals never starts it. It runs again for a new signal set, at most twice per
run, not in bounded pilots, and not once the request budget is spent. Every
worker request goes through scope, method policy and the request ceiling, and
workers only submit candidates for the independent verifier.

The planner works from facts with lineage: first-pass signals, verifier
verdicts, and each worker's positive and negative conclusions. Every task must
name the facts it builds on, a finished route is retried only with a newer
fact, and dependent steps run in order. The explorer worker (sandbox shell)
joins only when `AGENT_CUSTOM_PROBE_MODE=isolated` and the probe sandbox runs.

Roll back with `AGENT_HUNT_ENGINE=false`. Knobs: `AGENT_HUNT_WORKERS` (3),
`AGENT_HUNT_MAX_ROUNDS` (8), `AGENT_HUNT_MAX_INTENTS` (24).

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
  runner a one-job proxy credential plus the proxy's CA certificate. Its proxy
  (port 3128) allows only in-scope hosts plus OAST suffixes, refuses names that
  resolve only to private, loopback, link-local or metadata addresses, connects
  to the address it checked, and caps requests per job.
- HTTPS is intercepted. `probe-egress` generates an ephemeral CA at startup
  (the private key never leaves that process), issues a certificate per host,
  and verifies the real server's certificate upstream. The runner points every
  toolchain at the proxy CA (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
  `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`), so scripts need
  no proxy or `-k` flags. HTTP/1.1 is forced through ALPN and one request is
  served per connection, so each exchange parses exactly.
- Each request/response (headers and bodies, gzip/deflate decoded, 256 KB per
  body, 8 MB per job) is returned to the backend and stored as redacted
  `http_exchange` evidence with `test_type=custom_probe`. The tool result lists
  `exchanges[].evidence_id`; specialists read bodies with `read_evidence`,
  search them with `search_evidence`, and cite the IDs in
  `submit_finding_candidate`.

Enable:

```bash
echo "AGENT_PROBE_RUNNER_TOKEN=$(openssl rand -hex 24)" >> .env
echo "PROBE_RUNNER_TOKEN=$(openssl rand -hex 24)" >> .env
echo "AGENT_CUSTOM_PROBE_MODE=isolated" >> .env
docker compose --profile probe-sandbox up -d --build probe-egress probe-runner backend autonomy-worker
```

### sandbox_shell

With `AGENT_CUSTOM_PROBE_MODE=isolated` and `AGENT_SANDBOX_SHELL=true` (the
compose default), specialists that have `run_custom_probe` also get
`sandbox_shell(command, allowed_hosts?, timeout_sec<=120)`. It runs `bash -c`
as uid 65534 in `probe-runner`, whose image carries curl, wget, jq, sqlmap,
ffuf, python (requests, httpx, pyjwt) and `/opt/wordlists`. curl, wget and
python honor the proxy variables; ffuf and sqlmap need `-x "$PROBE_PROXY"` /
`--proxy="$PROBE_PROXY"`, and anything that ignores the proxy simply has no
route out. Every exchange is recorded as evidence like custom probes.
Destructive flags are refused before the job is sent (`--os-shell`,
`--os-pwn`, `--sql-shell`, `--file-write`, `--dump-all`, `--risk=3`, and
brute-force tools such as hydra); this is a guardrail on in-scope impact, not
the security boundary, which is the network sandbox.

Known limits: WebSocket upgrades and HTTP/2 are not supported through the
proxy (HTTP/1.1 only). Brotli bodies are stored still encoded. DNS queries
from the runner go to Docker's embedded resolver. Lab targets on private
addresses need `PROBE_ALLOW_PRIVATE_TARGETS=true` on `probe-egress`, and
self-signed lab certificates need `PROBE_UPSTREAM_VERIFY_TLS=false`; never set
either for customer targets.

## Logged-in capture (extension and HAR)

Analysts can hand Prowl sessions it cannot log in to itself. See
`capture-extension/README.md`. API:

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /agent/sessions/{id}/capture-token` | user | Issue a 4-hour token bound to one session and identity |
| `POST /agent/capture` | `Bearer jcap.…` | Extension batches (≤1000 entries, chunked into encrypted 50-entry batches) |
| `POST /agent/sessions/{id}/har` | user | DevTools HAR upload as a named identity |
| `GET /agent/sessions/{id}/captures` | user | Batches waiting to be drained |

Batches are AES-GCM encrypted under `AEGIS_EVIDENCE_DIR/operator_captures/`
(required) and drained at the start of each Joshua step: out-of-scope exchanges
are dropped, the identity's cookies and auth headers are registered, each
exchange becomes redacted `http_exchange` evidence (`test_type=operator_capture`),
and requests are mapped into operations.

### Non-HTTP TCP from sandbox_shell

`probe-egress` also runs a SOCKS5 listener (port 1080) with the same per-job
credential and scope checks. The runner writes a per-job `proxychains4` config
(`PROXYCHAINS_CONF_FILE`), so `proxychains4 nmap -sT -Pn -sV -p 22,6379 host`,
`proxychains4 nc host 25` and other TCP clients reach in-scope hosts only.
CONNECT only: SYN/UDP scans, OS detection and raw-packet scanners (masscan,
zmap, hping) are refused with an alternative, and brute/dos/exploit/intrusive
NSE scripts are blocked. Each job allows up to `PROBE_MAX_TCP_PER_JOB` (4000)
connections; the result's `tcp` field lists per-destination counts and verdicts.
Raw TCP is logged, not recorded byte-for-byte; use the HTTP proxy for web traffic
so it becomes evidence.
