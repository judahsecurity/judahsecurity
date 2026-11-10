# SecurityScorecard integration

Connect SecurityScorecard to import your portfolio domains, their scores and grades, and active issues as risks into Judah.

The integration is **read-only**: Judah pulls data from the [SecurityScorecard API](https://securityscorecard.readme.io/reference) and never modifies your SecurityScorecard account.

## What a sync does

1. Validates the API key by calling `GET /portfolios`.
2. Lists every portfolio in the account, then the companies in each portfolio.
3. For each unique company domain (domains in more than one portfolio are processed once):
   - Creates or updates a **domain asset**. Name and value are the domain, e.g. `example.com`.
   - Records the overall `score` and `grade`.
   - Fetches the company's **risk factors**, records each factor's score, and creates a risk for each issue in the factor's issue summary. Each risk gets a mapped severity, a readable title, a shared definition, and evidence for that instance.
   - Fetches **six months of monthly score history**.

Up to 10 companies are processed at once. Transient API errors (HTTP 429, 5xx, connection resets) are retried with exponential backoff, and `Retry-After` is honoured up to 30 seconds. The network phase of a sync must finish within **120 seconds**.

## Severity mapping

| SecurityScorecard | Judah |
| --- | --- |
| high | Critical |
| medium | Medium |
| low | Low |
| info | Info |
| positive | Not imported (positive findings are good practice, not risks) |
| unknown/other | Info (fallback) |

## Where the data lands

### Assets

Each company domain becomes an asset of type `DOMAIN` with `discovery_source = securityscorecard` and the tag `source:securityscorecard`.

> **Scope safety:** SecurityScorecard portfolios usually track third-party vendors. So a **newly created** domain is imported with `in_scope = false` and `is_owned = false`, which keeps Judah's active scanners off it until an analyst confirms ownership. If a domain already exists in Judah, its scope and ownership are left as they are.

### Attributes

Ratings data is stored on the asset under `metadata.securityscorecard`:

| Key | Value |
| --- | --- |
| `score` | Overall score (0-100) |
| `grade` | Letter grade (A-F). Also added as the asset tag `ssc-grade:<grade>`, replacing any older grade tag. |
| `factors` | `{factor_name: score}`, using the factor names the API returns (e.g. `network_security`, `dns_health`) |
| `score_history` | List of `YYYY-MM-DD:score` points, one per month, for the last six months |
| `portfolios` | Names of the portfolios the domain appears in |
| `company_name`, `industry`, `platform_url`, `synced_at` | Context |
| `factors_error` | Set when the factors request was refused (see troubleshooting) |

The ten standard factors are Network Security, DNS Health, Patching Cadence, Endpoint Security, IP Reputation, Application Security, Cubit Score, Hacker Chatter, Information Leak, and Social Engineering. Judah stores whatever factor names the API returns.

### Risks

Each issue type in a domain's factor issue summaries becomes one vulnerability on the domain asset, with `detected_by = securityscorecard` and `template_id = securityscorecard:<issue_type>`.

| Field | Source |
| --- | --- |
| Title | The vendor's readable title (e.g. `SSL/TLS Service Supports Weak Protocol`). If none is returned, a title is built from the slug (`tlscert_weak_protocol` becomes `Tlscert Weak Protocol`). |
| Description, impact, remediation | The issue-type definition from `/metadata/issue-types/{type}`. It is fetched once per unique type per sync and shared by every risk of that type. |
| Evidence | An overview (issue type, factor, severity, active finding count, score impact), then each finding with its first-seen and last-seen dates and observations such as protocol versions and IP addresses (up to 50 per risk), then a link to the issue in the SecurityScorecard platform. |
| References | The platform link |
| First / last detected | The earliest first-seen and latest last-seen across the findings |

On later syncs, existing risks are updated in place. A risk that was resolved and is reported again is reopened. An open risk that SecurityScorecard no longer reports for the domain is **resolved**. This only happens when that domain's factors were fetched successfully, so a temporary 403 never closes risks.

If the individual findings cannot be fetched, the risk still has the overview and the platform link. If an issue type has no definition, the risk is still created, just without description, impact, and remediation.

## Prerequisites

- An active SecurityScorecard account with API access.
- A SecurityScorecard API token. In SecurityScorecard, go to **My Settings** (gear icon) → **API** → **Generate New API Token**, or copy your existing token.
- At least one portfolio that contains companies.

## Setup

1. Open **Integrations** in Judah and find the **SecurityScorecard** card.
2. Click **Connect SecurityScorecard**.
3. Paste the **API Key**. The connection name defaults to `SecurityScorecard`, and the hidden username is always `securityscorecard`.
4. Choose whether to import issues as risks and whether to re-sync automatically (default: every 24 hours).
5. Click **Connect**. The key is validated against `/portfolios` before it is saved.
6. Click **Sync now** for the first import, or wait for the scheduler.

## Security behaviour

- The API key is encrypted at rest and is never returned by the Judah API.
- Requests go only to `https://api.securityscorecard.io` with `Authorization: Token <key>` (Token, not Bearer).
- Domains and issue types are validated and URL-encoded before they are used in request paths.
- Errors are recorded without logging the API key.

## SecurityScorecard endpoints used

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/portfolios` | List portfolios; also used to validate the key |
| GET | `/portfolios/{id}/companies` | List the companies in a portfolio |
| GET | `/companies/{domain}/factors` | Factor scores and issue summaries |
| GET | `/companies/{domain}/issues/{issue_type}/` | Individual findings, for evidence |
| GET | `/metadata/issue-types/{issue_type}` | Issue-type definition (once per type per sync) |
| GET | `/companies/{domain}/history/score?from=&to=&timing=monthly` | Six months of monthly score history |

## Judah API

- `GET /api/integrations/securityscorecard`
- `POST /api/integrations/securityscorecard`
- `PUT /api/integrations/securityscorecard/{id}`
- `DELETE /api/integrations/securityscorecard/{id}`
- `POST /api/integrations/securityscorecard/{id}/test`
- `POST /api/integrations/securityscorecard/{id}/sync`

The table is created automatically at startup. For existing deployments, apply `db/migrations/add_securityscorecard_integration.sql`.

## Troubleshooting

- **HTTP 401 / authentication failed:** the token is expired or revoked, was pasted with extra characters, or the account lacks API access.
- **No data imported:** make sure at least one portfolio contains companies.
- **Domains with no factors or risks:** if SecurityScorecard refuses the factors request (for example HTTP 403 for a private custom scorecard that isn't shared with the token's user), Judah logs a warning and skips that domain's factors and risks. The domain's asset, score, and grade are still imported, and the sync result counts it under `companies_without_factors`.
- **Missing definitions:** the risk is created with the title and evidence but no description, impact, or remediation. The sync result counts these under `definitions_missing`.
- **Timeout:** very large accounts can exceed the 120-second limit (`SYNC_TIMEOUT_SECONDS` in `backend/app/services/securityscorecard_service.py`).
