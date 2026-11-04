# Bitbucket Integration

Connect a Bitbucket Cloud workspace to import its repositories as assets and
scan them for exposed secrets.

Only **Bitbucket Cloud** (`bitbucket.org`) is supported. Bitbucket Data Center
and Bitbucket Server are not.

## Prerequisites

- Admin access to the Bitbucket workspace
- Permission to create workspace access tokens in Bitbucket
- Analyst (or higher) role in Judah

## Create a workspace access token

Judah connects with a **workspace access token**. App passwords and Connected
App (OAuth consumer) credentials are not supported.

> Atlassian offers workspace access tokens only on some Bitbucket Cloud plans.
> See [workspace access tokens](https://support.atlassian.com/bitbucket-cloud/docs/workspace-access-tokens/).

1. In Bitbucket go to **Settings → Workspace settings → Security → Access tokens**.
2. Click **Create access token**:
   - Name: `Judah`
   - Permissions: **Repository: Read** (nothing else)
3. Copy the token. Bitbucket will not show it again.

## Connect in Judah

1. Open **Integrations** and find the **Bitbucket** card.
2. Click **Connect Bitbucket**.
3. Enter your **Bitbucket Workspace URL**, for example `https://bitbucket.org/your-workspace`.
4. Paste the token into **Workspace Token**.
5. Click **Connect**.

Judah checks the token against the workspace before it saves anything, then
encrypts the token at rest. The first import starts right away in the background.

## What gets imported

- Each repository in the workspace becomes a `REPOSITORY` asset, with the value
  `https://bitbucket.org/<workspace>/<repo>`.
- Forked repositories are skipped.
- Public repositories have `is_public = true` and the `public` tag. Private ones get `private`.
- Repository metadata (main branch, language, size, project, timestamps) is
  stored under `metadata.bitbucket`.
- Workspace members and their personal repositories are not imported.

## Secret scanning

When **Scan repositories for exposed secrets** is on (the default):

- Judah shallow-clones each repository's main branch (`--depth 1`) into a
  temporary directory and deletes the clone when the scan finishes.
- It runs [Gitleaks](https://github.com/gitleaks/gitleaks) in redacted mode. If
  Gitleaks is not installed, it falls back to Judah's built-in secret patterns.
- Each finding becomes a vulnerability on the repository asset
  (`detected_by = bitbucket_secret_scanner`, CWE-798). It links to the file and
  line in Bitbucket.
- **Secret values are never stored.** Findings keep only the rule, file, line,
  commit and a fingerprint.
- A repository is scanned again only when Bitbucket reports it changed since the
  last scan. If a finding is not there on the next scan, it is marked resolved.
- Empty repositories, and repositories larger than the configured size limit
  (500 MB by default), are skipped.

The token is sent to git as an HTTP header through environment config. It
never appears in command-line arguments, git config files or error messages.

## Fix pull requests

Judah does not open pull requests in Bitbucket. Apply fixes in Bitbucket yourself.

## Webhooks

The integration uses no webhooks. New repositories are picked up on the next
scheduled sync (every 24 hours by default) or when you click **Sync now**.

## Managing the connection

Each connection card on the Integrations page has these actions:

- **Sync now** starts an import and scan in the background.
- **Test** checks the token again.
- **Details** shows the last test and sync and their stats.
- **Edit** rotates the token or changes scan and schedule settings.
- **Disable / Enable** pauses or resumes the connection.
- **Remove** deletes the stored token. Imported assets and findings are kept.

You can connect several workspaces. Add one connection per workspace, each with
a token created in that workspace.

## Troubleshooting

| Message | Fix |
| --- | --- |
| *Enter a valid Bitbucket workspace URL* | Use the form `https://bitbucket.org/your-workspace`. |
| *Bitbucket rejected the supplied access token or Connected App credentials* | The token is invalid, expired or revoked. Create a new one. |
| *The Bitbucket credentials authenticated successfully but cannot access workspace '…'* | Make sure the token was created in that workspace and has **Repository: Read**. |
| A repository shows `secret_scan_status: failed` | Check `metadata.bitbucket.secret_scan_note` on the asset. This is usually a clone timeout or a network problem. |

## API

All endpoints are under `/api/integrations/bitbucket`:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | List connections |
| POST | `/` | Create a connection (`workspace_url`, `access_token`, `scan_secrets`, …) |
| PUT | `/{id}` | Update settings or rotate the token |
| DELETE | `/{id}` | Remove the connection |
| POST | `/{id}/test` | Check the token again |
| POST | `/{id}/sync` | Start a background sync |

Implementation: `backend/app/services/bitbucket_service.py`,
`backend/app/models/bitbucket_integration.py`,
`frontend/src/components/integrations/BitbucketSection.tsx`.
