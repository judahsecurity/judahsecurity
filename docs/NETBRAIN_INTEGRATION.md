# NetBrain configuration and calculated route evidence

Judah can use a customer NetBrain account to validate configuration-dependent exploit prerequisites on network devices. The connector is read-only: it matches Judah assets to NetBrain devices and retrieves NetBrain's stored device configuration. It does not execute configuration changes.

The first supported policy covers Cisco IOS XE CVE-2023-20198 and CVE-2023-20273. Judah evaluates the HTTP and HTTPS Web UI configuration independently using Cisco's documented conditions. A finding is eligible for `MITIGATED` when every relevant transport lacks the required Web UI exploit path. The vulnerable software finding is retained, along with the evidence and analysis. A fixed software version remains the condition for `RESOLVED`.

## Account setup

Create a dedicated NetBrain account with:

- Access to the required tenant and domain.
- Permission to query device inventory.
- Permission to read stored device configurations.
- Permission to calculate and read network paths in the selected domain.
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

## Calculated routes

From the NetBrain integration card, enter two Judah asset IDs. If an asset has several recorded IPv4 addresses, select one in the form. If NetBrain returns multiple possible source gateways, select the exact gateway device and interface. This keeps duplicate RFC 1918 addresses separate by asset and network scope. A pair with the same selected IPv4 address is rejected because this API cannot distinguish the intended destination. The selected NetBrain tenant, domain, gateway, addresses, protocol, port, calculation task, and hop list are retained with the path.

The UI starts the path calculation, then **Refresh** reads the task status and hops. A successful path projects `Asset → NetworkPath → requested Asset` and ordered `NetworkHop` evidence into Neo4j. The requested target is an analyst association, not a provider-confirmed asset match. A path calculation is topology evidence; it does not prove packet delivery, firewall permission, or exploitability. Current attack-path scoring does not treat this evidence as a traversable route. If Neo4j is unavailable, the path remains in PostgreSQL and another refresh retries projection. Path calculations are requested only by an analyst, not during automatic asset sync.

## API

- `GET /api/integrations/netbrain`
- `POST /api/integrations/netbrain`
- `PUT /api/integrations/netbrain/{id}`
- `DELETE /api/integrations/netbrain/{id}`
- `POST /api/integrations/netbrain/{id}/test`
- `POST /api/integrations/netbrain/{id}/assess`
- `GET /api/integrations/netbrain/{id}/paths`
- `POST /api/integrations/netbrain/{id}/paths`
- `POST /api/integrations/netbrain/{id}/paths/{path_id}/refresh`

Apply `db/migrations/add_netbrain_integration.sql` and `db/migrations/add_netbrain_paths.sql` when migrations are managed separately from application startup.
