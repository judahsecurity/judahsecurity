# Wiz integration

Judah can import Wiz virtual machines and vulnerability findings into the exposure-management inventory. The connection is read-only and uses a Wiz Custom Integration (GraphQL) service account.

## What is imported

- Internet-exposed virtual machines by default; the connection can optionally include all VMs.
- VM operating system, IP addresses, cloud platform, provider identifier, region, subscription, status, tags, and Wiz exposure flags.
- CVE, CVSS score, Wiz/vendor severity, affected and fixed versions, description, remediation, Wiz project, first/last detection time, status, and source links.
- Wiz finding-to-VM relationships, represented as Judah vulnerabilities attached to cloud-resource assets.

Existing records are updated by stable Wiz asset and finding identifiers. Findings reported as resolved by Wiz are resolved in Judah; findings seen open again are reopened. Judah never changes data in Wiz.

## Custom queries

Each Wiz connection can also run **custom queries** to pull any table Wiz exposes over GraphQL, such as application endpoints, attack-surface findings or issues, without code changes.

1. In Wiz, open the table you want with the filters you want, and copy its API request as Python (the script that defines `QUERY` and `VARIABLES`).
2. In Judah, open **Integrations → Wiz → Custom queries → Add query** and paste the whole script. Judah reads only the `QUERY` and `VARIABLES` literals; it never runs the script and ignores any credentials in it. A raw GraphQL query plus JSON variables also works, and **Application endpoints** is available as a template.
3. Select **Preview** to fetch a few rows. Judah finds the result list (`nodes` + `pageInfo`) automatically and lists the fields it returned.
4. Optionally set **Import hostname/URL field as assets** (for example `host`) so each row becomes an inventory asset tagged `source:wiz`, which agents can then validate.
5. Save. The query runs after every Wiz sync, or on demand with **Run now**.

Behaviour:

- Only read operations are accepted. A GraphQL `mutation` or `subscription` is rejected, because it would change data in Wiz rather than return findings. For example, the `UpdateUserPreferences` request Wiz sends when a page first loads only hides UI help banners; capture the request that loads the table rows instead.
- Paging is automatic. `$first` is set to the configured page size and `$after` starts empty, so a cursor or page size copied from the browser does not matter. Each run stops after the configured maximum number of pages.
- Every returned node is stored by its Wiz `id`. Rows a later complete run no longer returns are marked as gone, not deleted; a run cut short by the page limit marks nothing as gone.
- Rows are available at `GET /api/integrations/wiz/{id}/queries/{query_id}/records`.

## Wiz prerequisites

1. In Wiz, open **Settings → Access Management → Service Accounts**.
2. Add a **Custom Integration (GraphQL)** service account.
3. Grant at least **Read graph resources** and **Read vulnerabilities**. `read:all` is also supported.
4. Copy the Client ID and Client Secret when Wiz displays them.
5. In **Tenant Info**, copy the tenant-specific API endpoint, such as `https://api.us17.app.wiz.io/graphql`.

Wiz Active Scanner / Advanced licensing may be required for the VM vulnerability data that Wiz exposes.

## Configure Judah

1. Open **Integrations → Wiz → Connect Wiz**.
2. Enter a connection label, API endpoint, Client ID, and Client Secret.
3. Choose whether to import assets, vulnerabilities, only internet-exposed VMs, and whether to sync automatically.
4. Select **Connect and validate**.
5. Use **Sync now** for the first import or wait for the configured schedule.

The default OAuth token URL is `https://auth.app.wiz.io/oauth/token` with audience `wiz-api`. Government or legacy tenants can change both values under **Advanced authentication**.

## Security behavior

- Client ID and Client Secret are encrypted at rest and never returned by the API.
- Only HTTPS endpoints on `wiz.io` or `wiz.us` hosts are accepted.
- Authentication and GraphQL errors are recorded without logging OAuth tokens or credentials.
- API calls retry boundedly for rate limiting and transient gateway failures.

## API endpoints

- `GET /api/integrations/wiz`
- `POST /api/integrations/wiz`
- `PUT /api/integrations/wiz/{id}`
- `DELETE /api/integrations/wiz/{id}`
- `POST /api/integrations/wiz/{id}/test`
- `POST /api/integrations/wiz/{id}/sync` (also runs the connection's active custom queries)
- `GET /api/integrations/wiz/query-templates`
- `POST /api/integrations/wiz/queries/parse-script`
- `GET|POST /api/integrations/wiz/{id}/queries`
- `POST /api/integrations/wiz/{id}/queries/preview`
- `PUT|DELETE /api/integrations/wiz/{id}/queries/{query_id}`
- `POST /api/integrations/wiz/{id}/queries/{query_id}/run`
- `GET /api/integrations/wiz/{id}/queries/{query_id}/records`
