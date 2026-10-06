# NetBrain configuration evidence

Judah can use a customer NetBrain account to validate configuration-dependent exploit prerequisites on network devices. The connector is read-only: it matches Judah assets to NetBrain devices and retrieves NetBrain's stored device configuration. It does not execute configuration changes.

The first supported policy covers Cisco IOS XE CVE-2023-20198 and CVE-2023-20273. Judah evaluates the HTTP and HTTPS Web UI configuration independently using Cisco's documented conditions. A finding is eligible for `MITIGATED` when every relevant transport lacks the required Web UI exploit path. The vulnerable software finding is retained, along with the evidence and analysis. A fixed software version remains the condition for `RESOLVED`.

## Account setup

Create a dedicated NetBrain account with:

- Access to the required tenant and domain.
- Permission to query device inventory.
- Permission to read stored device configurations.
- No network-change or remediation privileges.

In Judah, open **Integrations → NetBrain → Connect NetBrain** and provide the NetBrain Web API Server URL, service-account credentials, tenant ID, domain ID, and an external authentication ID when the account uses LDAP, AD, or TACACS. Configure the maximum acceptable age for stored configurations.

Credentials are encrypted at rest. TLS verification is enabled by default.

## Assessment behavior

For supported CVEs, an assessment:

1. Matches the finding asset to exactly one NetBrain device by management IP or hostname.
2. Retrieves the device configuration and its NetBrain collection timestamp.
3. Rejects ambiguous, missing, undated, or stale evidence as `unknown`.
4. Stores only relevant configuration lines, a SHA-256 hash of the complete configuration, provenance, and the resulting analysis on the finding.
5. Optionally changes an open finding to `MITIGATED` with reason **exploit prerequisite absent**.
6. Reopens only mitigations previously managed by NetBrain when the prerequisite appears or the evidence becomes unavailable or stale.

Automatic mitigation and continuous reassessment are separate settings. Start in evidence-only mode, validate device matching, then enable automatic mitigation.

## API

- `GET /api/integrations/netbrain`
- `POST /api/integrations/netbrain`
- `PUT /api/integrations/netbrain/{id}`
- `DELETE /api/integrations/netbrain/{id}`
- `POST /api/integrations/netbrain/{id}/test`
- `POST /api/integrations/netbrain/{id}/assess`

Apply `db/migrations/add_netbrain_integration.sql` when migrations are managed separately from application startup.
