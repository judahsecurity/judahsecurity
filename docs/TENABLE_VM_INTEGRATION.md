# Tenable VM integration

Judah can import assets and open vulnerabilities from Tenable Vulnerability Management (Tenable.io / Tenable Cloud). The connection is read-only and uses Tenable's export APIs with a service account's API keys.

## What each sync does

- **Imports assets** (`POST /assets/export`, `last_assessed` = last 30 days). Each asset is named by its first FQDN, or its first IPv4 address when it has no usable FQDN. Private, internal (`.internal`, `.local`, `.corp`, single-label names, …), and cloud-provider addresses (known cloud/CDN ranges and provider-generated hostnames such as `*.compute.amazonaws.com`) are skipped.
- **Imports vulnerabilities** (`POST /vulns/export`, severity Low/Medium/High/Critical, state `OPEN`/`REOPENED`, `last_found` = last 30 days). Each finding becomes an open vulnerability attached to its asset, and to the asset's port (created if needed) when the finding has one. Assets referenced by findings are created even when **Import Assets** is off.
- **Sets severity** from the CVSSv3 temporal score, else the CVSSv3 base score: ≥ 9.0 Critical, ≥ 7.0 High, ≥ 4.0 Medium, ≥ 0.1 Low, otherwise Info. Findings with no CVSSv3 score fall back to Tenable's own risk factor.
- **Attaches details**: the plugin synopsis/description, solution, and references (`see_also`) become the finding's description, remediation, and references; plugin output, service, CVEs, and CVSS scores and vector are stored as evidence.

Findings are keyed on asset + plugin ID + port, so re-syncs update in place. A finding Judah marked resolved is reopened if Tenable still reports it open.

- **Closes fixed findings** (`POST /vulns/export`, state `FIXED`, `last_fixed` = last 30 days). Matching open or in-progress findings are marked resolved with Tenable's fix date. False positives, accepted risks, and mitigated findings are left as the analyst set them, and fixed findings never create new records.
- **Retires stale assets.** After a complete, non-empty asset export, assets that Tenable created and no longer reports are marked **Inactive**; they return to Discovered if Tenable reports them again. Assets found by other discovery and only enriched by Tenable are never retired. An empty asset export retires nothing, since that usually means a permissions problem.

Syncs run in the background: **Sync now** returns immediately and the card shows **Syncing…** until the result is in. Each connection holds a lock while syncing, so a manual sync and a scheduled sync can't overlap; a lock left by a crashed worker expires after 4 hours. Agent findings are recorded as `tenable_agent` and local-check findings as `tenable_credentialed`, so severity scoring treats them as not externally discoverable.

## Tenable prerequisites

1. **Settings → Access Control → Permissions**: confirm a permission grants **Can View** on **All Assets** (create one if not).
2. **Settings → Access Control → Users → Create User**: role **Standard User**, enable **API Key Authentication**, and assign the **Can View All Assets** permission.
3. Open the new user, expand **API Keys → More → Generate API Keys → Replace & Generate**, and copy the **Access Key** and **Secret Key** (Tenable shows them once).

## Configure Judah

1. Open **Integrations → Tenable VM → Integrate**.
2. Enter the **Tenable VM URL** (default `https://cloud.tenable.com`; FedRAMP tenants use `https://fedcloud.tenable.com`), **Access Key**, and **Secret Key**.
3. Choose **Import Assets** and/or **Import Vulnerabilities**, and the auto-sync interval.
4. Click **Connect**. Judah checks the keys by requesting an asset export and a vulnerability export (then cancels both). If either fails, check that the service account has **Can View** on **All Assets**.
5. Use **Sync now** for the first import or wait for the schedule. `POST …/sync` returns `202` (or `409` if a sync is already running); poll `GET /api/integrations/tenable` for `sync_in_progress` and `last_sync_stats`.

## Security behavior

- API keys are encrypted at rest and never returned by the API.
- Only HTTPS `tenable.com` hosts without credentials, ports, or paths are accepted.
- Requests retry boundedly on HTTP 429/5xx, honoring `Retry-After`.

## API endpoints

- `GET /api/integrations/tenable`
- `POST /api/integrations/tenable`
- `PUT /api/integrations/tenable/{id}`
- `DELETE /api/integrations/tenable/{id}`
- `POST /api/integrations/tenable/{id}/test`
- `POST /api/integrations/tenable/{id}/sync`
