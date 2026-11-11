# Prowl pull-request checks

A PR check sends a pull request's changed files to Judah, returns advisory
source findings as GitHub annotations, and can fail the job. With an asset ID,
the HTTP routes and input names found in that source are handed to Prowl so a
live session tests them.

## Set up

1. As an admin, create an org agent API key with the `pr:check` scope:

   ```bash
   curl -X POST "$JUDAH/api/v1/ingest/api-keys" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"name":"github-pr-checks","agent_type":"ci_cd","scopes":["pr:check"]}'
   ```

   A key with an empty scope list does **not** get PR checks; the scope must be
   explicit. Save the key as the `JUDAH_API_KEY` repository secret.

2. Add a workflow to the application repository:

   ```yaml
   name: Judah PR check
   on: pull_request
   jobs:
     prowl:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
           with:
             fetch-depth: 0
         - uses: judahsecurity/judahsecurity/.github/actions/prowl-pr-check@main
           with:
             api-url: https://asm.example.com/api/v1
             api-key: ${{ secrets.JUDAH_API_KEY }}
             asset-id: "42"        # optional: live handoff target
             fail-on: medium
   ```

   `fetch-depth: 0` is needed so the base commit is available for the diff. If
   this repository is private, copy `.github/actions/prowl-pr-check/` into the
   application repository and use `uses: ./.github/actions/prowl-pr-check`.

## What runs

- The client uploads changed text files with their unified diffs; lockfiles,
  vendored code, build output and binaries are skipped. Limits: 300 files,
  256 KB per file, 5 MB total. No repository credentials reach Judah.
- **Routes:** Flask, FastAPI, Django `urls.py`, Express and Spring routes, with
  the query, form and JSON input names their handlers read.
- **Rules:** built-in high-signal rules on added lines only (SQL string
  building, shell execution, unsafe deserialization, eval, raw HTML sinks, TLS
  verification off, unverified JWTs, open redirects, hard-coded credentials with
  values masked), plus semgrep when its binary is installed on the backend.
- Findings carry `verification_level: source_only` and are **capped at medium**,
  matching the agent finding gate: a code pattern alone is never filed as
  high or critical. Each finding is linked to the nearest route in its file.
- The job fails when any finding is at or above `fail-on`. With the cap, only
  `info`, `low` and `medium` thresholds can fail on source findings.

## Live handoff

With `asset-id`, the check is stored against the asset. In a Prowl session on
that asset's origin, `import_source_routes` (no args loads the latest check for
the target) adds each route as a value-free operation (`sources=["source_code"]`)
so its inputs get XSS/SQLi coverage cells, and returns `source_leads`: rule hits
tied to a route and a live test class. A source lead becomes a finding only
through the usual live probe and independent verifier.

## API

- `POST /api/v1/pr-checks` (agent key, `pr:check` scope): run a check.
- `GET /api/v1/pr-checks?asset_id=` and `GET /api/v1/pr-checks/{id}` (user
  session): list and read checks for your organization.

Apply `db/migrations/add_pr_checks.sql` on existing databases; `create_all`
creates the table on fresh ones.
