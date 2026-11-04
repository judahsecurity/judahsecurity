# Azure DevOps integration (Source Code Managers)

Judah connects to Azure DevOps Services, imports the active Git repositories in an organization or project as `REPOSITORY` assets, and scans every repository's code and full commit history for committed secrets. Repository scanning is read-only: Judah lists projects and repositories and clones them, but never pushes code, creates branches, or changes settings.

Only Azure DevOps Services (`https://dev.azure.com`) is supported. Azure DevOps Server, Team Foundation Server, and legacy `*.visualstudio.com` URLs are rejected.

## Scope

| URL entered | What is scanned |
| --- | --- |
| `https://dev.azure.com/{org}` | Every project in the organization the identity can see |
| `https://dev.azure.com/{org}/{project}` | Every repository in that project |
| `https://dev.azure.com/{org}/{project}/_git/{repo}` | Every repository in that project (the repository name does not narrow the scan) |

Forked repositories and disabled (or in-maintenance) repositories are skipped. Each sync re-enumerates the scope, so new repositories are imported and scanned on the next run; no webhooks or service hooks are needed. Organization and project members are not imported, and repositories in public projects are not yet marked public.

## Authentication

### Entra ID service principal (recommended)

Judah exchanges the app registration's client credentials with Microsoft Entra ID for an Azure DevOps token (`499b84ac-1321-427f-aa17-267ca6975798/.default`) and refreshes it automatically.

1. In Azure DevOps, open **Organization Settings → Users**, add the application (by Application ID) and grant **Basic** access.
2. Click the service principal, open **Manage access**, and add it to **every project** Judah should scan as a **Project Reader**. Adding it only at organization level authenticates successfully but shows zero projects.
3. In Judah, open **Integrations → Source Code Managers → Azure DevOps → Connect Azure DevOps** and enter the tenant ID, application (client) ID, client secret, and the organization or project URL.

### Personal Access Token

Select **Use alternative authentication (Personal Access Token)** and enter a PAT with **Code (Read)** and **Project and Team (Read)**. The PAT owner must be a member of every project to scan; a PAT can only see what its owner can see. Use a service account, a short expiry, and rotate regularly.

## What happens on sync

1. Judah validates the scope (`GET /{org}/_apis/projects` or `GET /{org}/_apis/projects/{project}`) and lists repositories per project (`GET /{org}/{project}/_apis/git/repositories`), with up to 25 concurrent requests. All calls use API version 7.1.
2. Each active, non-fork repository is upserted as a `REPOSITORY` asset keyed by its web URL, with project, repository ID, default branch, and size in `metadata.azure_devops`.
3. If secret scanning is enabled, a `trufflehog_scan` scan is queued. The scanner worker bare-clones each repository, runs TruffleHog over the full history (verified secrets only by default), attaches findings to the repository asset, and deletes the clone.

Syncs run on demand (**Sync now**) and on the configured schedule (default daily).

## Security behavior

- PATs and client secrets are encrypted at rest and never returned by the API.
- Credentials are only sent to `dev.azure.com` and `login.microsoftonline.com`. Clone URLs are re-validated to stay on `dev.azure.com` inside the connected organization.
- `git clone` receives credentials as an HTTP header through `GIT_CONFIG_*` environment variables, so tokens never appear in process arguments, remote URLs, or the queued scan's configuration.
- HTTP 429 responses are retried after `Retry-After` (10 seconds if absent, capped at 120 seconds).
- Worker limits are configurable: `SCM_SCAN_CONCURRENCY` (default 3), `SCM_CLONE_TIMEOUT` (900s), `SCM_SCAN_TIMEOUT` (1800s), `SCM_MAX_REPO_BYTES` (5 GiB; larger repositories are skipped).

## Troubleshooting

| Message | Fix |
| --- | --- |
| "Azure DevOps rejected the supplied access token" | Entra ID: confirm the service principal is listed under Organization Settings → Users. PAT: generate a new token with the required scopes. |
| "…authenticated successfully but cannot access organization…" / no repositories imported | Use **Manage access** to add the identity to each project. |
| "Enter a valid Azure DevOps organization or project URL" | Use `https://dev.azure.com/{org}`; `visualstudio.com` URLs are not supported. |
| "Entra ID token exchange failed" | Check tenant ID, application ID, and that the client secret has not expired. |

## Not yet implemented

Azure DevOps Work Item tracking (creating and syncing Work Items from findings) is a separate IT Service Management integration and is not part of this connection.
