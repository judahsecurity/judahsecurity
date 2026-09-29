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
