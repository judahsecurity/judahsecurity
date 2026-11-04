# SecurityScorecard integration

Judah can import third-party security ratings from [SecurityScorecard](https://securityscorecard.com/). The integration is read-only: it pulls data from the SecurityScorecard API and never changes your SecurityScorecard account.

Judah discovers every company domain across all of your SecurityScorecard portfolios and imports each domain's overall score and letter grade, its risk-factor scores, six months of score history, and its active issues as findings.

## What a sync does

1. Validates the API key by listing portfolios (`GET /portfolios`).
2. Lists the companies in each portfolio. A domain that appears in more than one portfolio is processed once.
3. For each unique company domain:
   - Creates a **domain asset**, or enriches the existing asset with the same value.
   - Records `score` and `grade` attributes.
   - Fetches the company's **risk factors**, records each factor's score, and creates a finding for each issue in the factor's issue summary.
   - Fetches **six months of monthly score history**.

Up to 10 companies are fetched at the same time. Transient API errors (HTTP 429, 5xx, and connection resets) are retried with exponential backoff, and `Retry-After` is honoured up to 30 seconds.

## Severity mapping

| SecurityScorecard severity | Judah severity |
| --- | --- |
| high | Critical |
| medium | Medium |
| low | Low |
| info | Info |
| positive | Not imported (positive findings are healthy practices, not risks) |
| unknown or other | Info (fallback) |

## Data mapping

### Assets and attributes

Each company domain becomes a `DOMAIN` asset tagged `source:securityscorecard`. The SecurityScorecard attributes are stored on the asset under `metadata.securityscorecard`:

| Key | Value |
| --- | --- |
| `score` | Overall score (0–100) |
| `grade` | Overall letter grade (A–F) |
| `factors` | `{factor_name: score}` for every factor the API returns, such as `network_security` and `dns_health` |
| `factor_grades` | `{factor_name: grade}` |
| `score_history` | List of `YYYY-MM-DD:score` points, oldest first, covering the last six months |
| `portfolios` | Names of the portfolios the domain belongs to |
| `company_name`, `industry`, `scorecard_url` | Company details and a link to the scorecard |

Factor names are whatever the SecurityScorecard API returns. The ten standard factors are Network Security, DNS Health, Patching Cadence, Endpoint Security, IP Reputation, Application Security, Cubit Score, Hacker Chatter, Information Leak, and Social Engineering.

### Findings

Each non-positive issue in a company's factor issue summaries becomes one finding on the domain asset, keyed by issue type (`template_id = securityscorecard:<issue_type>`).

- **Title**: the vendor's human-readable title (for example, `SSL/TLS Service Supports Weak Protocol`). If SecurityScorecard returns none, Judah derives one from the issue-type slug (`tlscert_weak_protocol` becomes `Tlscert Weak Protocol`).
- **Shared definition**: description, impact, and remediation from `GET /metadata/issue-types/{issue_type}`. Each definition is fetched once per issue type per sync and shared by every finding of that type.
- **Per-instance evidence**: issue type, factor, severity, active finding count, and score impact; each individual finding with its first-seen and last-seen dates and observations, such as protocol versions and IP addresses; and a link to the issue in the SecurityScorecard platform. If the individual findings cannot be fetched, the finding keeps the overview and the link.

On later syncs, findings are updated in place. A finding whose issue no longer appears for that domain is resolved, and one that reappears is reopened. When factors could not be read for a domain, its existing findings are left as they are.

## Prerequisites

- A SecurityScorecard account with API access.
- A SecurityScorecard API token.
- At least one portfolio that contains companies.

To get a token, sign in to SecurityScorecard, open **My Settings** (the gear icon), select **API**, and click **Generate New API Token**, or copy your existing token.

## Configure Judah

1. Open **Integrations → SecurityScorecard → Connect SecurityScorecard**.
2. Enter a connection name and the API key.
3. Choose whether to create domain assets (when this is off, only domains already in inventory are enriched), whether to import issues as findings, and whether to sync automatically.
4. Select **Connect and validate**.
5. Use **Sync now** for the first import, or wait for the configured schedule.

## Security behaviour

- The API key is encrypted at rest and never returned by the API.
- Requests go only to `https://api.securityscorecard.io` with `Authorization: Token <api_key>` (the Token scheme, not Bearer).
- Domains and issue types from the API are validated and URL-encoded before they are used in request paths.
- Errors are recorded without logging the API key.

## SecurityScorecard API endpoints used

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/portfolios` | List portfolios; also used to validate the key |
| GET | `/portfolios/{id}/companies` | List the companies in a portfolio |
| GET | `/companies/{domain}/factors` | Factor scores and each factor's issue summary |
| GET | `/companies/{domain}/issues/{issue_type}/` | Individual findings for per-instance evidence |
| GET | `/metadata/issue-types/{issue_type}` | Issue-type definition; called once per type per sync |
| GET | `/companies/{domain}/history/score?from=…&to=…&timing=monthly` | Monthly score history for the last six months |

## Judah API endpoints

- `GET /api/integrations/securityscorecard`
- `POST /api/integrations/securityscorecard`
- `PUT /api/integrations/securityscorecard/{id}`
- `DELETE /api/integrations/securityscorecard/{id}`
- `POST /api/integrations/securityscorecard/{id}/test`
- `POST /api/integrations/securityscorecard/{id}/sync`

## Troubleshooting

**Authentication failed (HTTP 401).** Check that the key has not expired or been revoked, that it was pasted without extra characters, and that API access is enabled for your account.

**No data imported.** Make sure your account has at least one portfolio that contains companies. If **Create domain assets** is off, only domains that already exist as assets are enriched.

**A company has no factors or findings.** If SecurityScorecard refuses the factors request for a company (for example, HTTP 403 for a private custom scorecard that is not shared with the key's user), Judah logs a warning and skips that company's factors and findings. The asset, score, and grade are still imported, and the sync summary counts the company under `factors_unavailable`.

**A finding has no description, impact, or remediation.** SecurityScorecard returned no definition for that issue type. The finding is still created with its title and evidence.
