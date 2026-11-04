# GitHub integration

Judah connects to GitHub to discover repositories, scan them for secrets, and optionally open fix pull requests. It lives under **Integrations → Source Code Managers → GitHub**.

## Connection methods

- **GitHub App (recommended).** An organization owner installs the platform's App and chooses **All repositories** or **Only select repositories**. Judah stores only the installation ID. For every sync it signs a short JWT with the App's private key and exchanges it for a one-hour installation access token, which acts as the App and reaches only the selected repositories.
- **Personal access token (PAT).** Use this when you can't install the App, to import a personal account's repositories, or to let Judah open fix pull requests. The token is validated against the organization before saving and encrypted at rest.

Read-only access is enough for discovery and scanning. Write access is needed only for fix pull requests and is off by default.

## Platform setup (operators)

Register a GitHub App once per deployment:

| Setting | Value |
| --- | --- |
| Repository permissions | Metadata: Read, Contents: Read |
| Organization permissions | Members: Read |
| Webhook | Inactive (no events) |
| Request user authorization (OAuth) during installation | Enabled |
| Callback URL | `https://<frontend>/integrations/github/callback` |

Then set, on the backend and the schedule worker:

```
GITHUB_APP_ID=
GITHUB_APP_SLUG=            # github.com/apps/<slug>
GITHUB_APP_CLIENT_ID=
GITHUB_APP_CLIENT_SECRET=
GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github-app.pem   # or GITHUB_APP_PRIVATE_KEY
```

Without these, the **Install GitHub App** button is disabled and only PAT connections are available.

## Installing the App

1. Click **Install GitHub App**. Judah creates a single-use install state (stored only as a SHA-256 digest, valid 7 days) and sends you to GitHub.
2. Choose the account and repositories, and confirm.
3. GitHub returns you to `/integrations/github/callback`. Judah exchanges the user-authorization code and confirms you **own or administer** the installation before linking it: for an organization, an active `admin` membership; for a user account, that you are that user. An installation can be linked to only one Judah organization.

If you are not an organization owner, GitHub sends an install request to the owners instead. Judah records the request with your GitHub login. When an owner approves within 7 days, the schedule worker (every 10 minutes, or **Check now** in the UI) finds the new installation, confirms you are a member of that organization, and links it. Requests that match more than one Judah organization are not linked automatically. After 7 days the request expires; start the install again.

To change repository access, edit the App's settings in GitHub (the **Repository access** button links there). To remove access entirely, uninstall the App in GitHub; removing the connection in Judah alone stops Judah from using it.

## Connecting with a PAT

1. Click **Use alternative authentication**.
2. Enter the token and the organization or user URL, e.g. `github.com/<organization>`.
3. Click **Connect**.

To import member-owned repositories, the token must list organization members (fine-grained: **Members** organization permission, read). Otherwise Judah imports the organization's repositories and skips member-owned ones.

## What is imported

- Every repository the credential can list becomes a `REPOSITORY` asset (`https://github.com/<owner>/<name>`) with visibility, default branch, archive/fork flags, language, and last push time. Private repositories of the token's own account are included when the URL names that account.
- For an organization, Judah lists members and imports the **public** repositories each member owns with the status **Pending**, for review.
- Repositories are re-read on every sync (default every 24 hours). GitHub webhooks are not used.

## Secret scanning

Each sync scans the default branch of the connection's own repositories (not member-owned ones) that changed since the last complete scan, up to 200 repositories per sync. Source and configuration files up to 512 KB are checked, skipping vendored directories and binary files, up to 300 files per repository.

Each secret becomes a finding on the repository asset. **The finding's evidence shows the matched value in full, and exports include it.** Treat these findings as sensitive and rotate exposed secrets. When a later scan covers the whole branch and the secret is gone, the finding is resolved; if it reappears, it is reopened.

## Fix pull requests

`POST /api/v1/integrations/github/{id}/pull-requests` opens a pull request with a patch (full file contents per path) for a finding: Judah creates a `judah/fix-<finding>-<suffix>` branch, commits the change, and opens the PR. It records the PR on the finding (`metadata.github_pull_request`). Judah never merges.

Requirements:

- A PAT connection with **Allow fix pull requests** enabled. The GitHub App is read-only and can't open pull requests.
- A token with **Contents: Read and write** and **Pull requests: Read and write** (fine-grained) or the `repo` scope (classic).
- The target repository must have been imported by this connection, and not as a member-owned repository.

Judah does not yet update the finding when the PR is merged or closed. No UI producer of patches exists yet; the endpoint and client method (`api.createGitHubFixPullRequest`) are in place for one.
