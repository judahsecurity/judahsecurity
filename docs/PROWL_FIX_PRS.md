# Prowl fix pull requests

Prowl can write a minimal patch for a finding the independent verifier
reproduced (`verification_level = exploit_verified`) and open it as a **draft**
PR. The fix is marked verified only after Prowl re-runs the original proof
against the PR's preview deployment and the exploit no longer reproduces.

## Set up

1. Create a fine-grained GitHub token limited to the application repositories,
   with **Contents: read/write** and **Pull requests: read/write**. Save it in
   Settings → API Keys → *GitHub (fix PRs)* (service `github`). Each
   organization uses its own token; the global `GITHUB_TOKEN` is used only when
   `FIX_PR_ALLOW_GLOBAL_GITHUB_TOKEN=true` (single-tenant deployments).
   GitHub Enterprise: set `GITHUB_API_URL=https://ghe.example.com/api/v3`.
2. Apply `db/migrations/add_fix_requests.sql` on existing databases.

## Open a fix PR

From a verified finding, use *Open draft fix PR* on the Findings page, or:

```bash
curl -X POST "$JUDAH/api/v1/vulnerabilities/123/fix-pr" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"repository":"acme/shop","file_paths":["app/views/items.py"]}'
```

`file_paths` is optional when a PR check (see `PROWL_PR_CHECKS.md`) linked
source files to the finding's asset; files whose rule CWE or route matches the
finding are chosen first. At most five files (120 KB) are sent to the model.

Guardrails on the model's output:

- It may edit only the files it was shown and add **one** new test file under a
  test path (`tests/`, `__tests__/`, `spec/`, `test_*.py`, `*.test.ts`, ...).
- Workflow/CI files, dotfiles, lockfiles, dependency manifests, Dockerfiles and
  Makefiles are rejected. At most six files and 200 KB.
- File contents and finding text are passed as data. The PR is a draft and
  needs human review before merge.

The finding moves from *open* to *in progress* and records the fix request ID.

## Verify the fix

1. Deploy the PR to a preview environment, add its host to the rules of
   engagement, then save it: `PUT /api/v1/fix-requests/{id}/preview`
   `{"preview_origin": "https://pr-77.preview.example.com"}`.
2. In a Prowl session targeting that origin, `verify_fix(fix_id)` returns the
   original reproduction. Re-run it with the scoped probe tools, then call
   `record_fix_verification(fix_id, verdict="fixed"|"still_vulnerable",
   evidence_ids=[...])`.
3. Evidence must be execution-owned exchanges from this session, captured
   against the preview origin **after** the fix request was created; discovery
   and tool-output records do not count.

`verified_fixed` and `fix_ineffective` are recorded on the fix request and the
finding's metadata. The finding's production status is unchanged: close it
after merge with a production re-test or analyst review.

## API

- `POST /api/v1/vulnerabilities/{id}/fix-pr` (analyst)
- `GET /api/v1/fix-requests?vulnerability_id=`, `GET /api/v1/fix-requests/{id}`
- `PUT /api/v1/fix-requests/{id}/preview` (analyst)
