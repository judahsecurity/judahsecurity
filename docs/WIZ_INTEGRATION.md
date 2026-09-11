# Wiz integration

Judah can import Wiz virtual machines and vulnerability findings into the exposure-management inventory. The connection is read-only and uses a Wiz Custom Integration (GraphQL) service account.

## What is imported

- Internet-exposed virtual machines by default; the connection can optionally include all VMs.
- VM operating system, IP addresses, cloud platform, provider identifier, region, subscription, status, tags, and Wiz exposure flags.
- CVE, CVSS score, Wiz/vendor severity, affected and fixed versions, description, remediation, Wiz project, first/last detection time, status, and source links.
- Wiz finding-to-VM relationships, represented as Judah vulnerabilities attached to cloud-resource assets.

Existing records are updated by stable Wiz asset and finding identifiers. Findings reported as resolved by Wiz are resolved in Judah; findings seen open again are reopened. Judah never changes data in Wiz.

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
- `POST /api/integrations/wiz/{id}/sync`
