# CrowdStrike Falcon Exposure Management integration

Judah imports internet-facing exposure from CrowdStrike Falcon and records whether
the Falcon sensor on each host behind that exposure is **blocking** (prevent mode)
or only **detecting**. The connection is read-only; Judah never writes to Falcon.

## Why paths are rebuilt rather than downloaded

The public Falcon API (as used by `CrowdStrike/falconpy` and `CrowdStrike/falcon-mcp`)
does not expose the attack-path graph shown in the Exposure Management console.
Judah rebuilds the internet-facing part of each path from the endpoints that are public:

```
external asset (FEM) -> exposed port/service -> Falcon host (aid) -> open CVE -> prevention posture
```

| Step | Falcon endpoint |
|---|---|
| Internet-facing IPs/domains and services | `GET /fem/queries/external-assets/v2`, `GET /fem/entities/external-assets/v1` |
| Open CVEs on linked or internet-exposed hosts | `GET /spotlight/combined/vulnerabilities/v1` (`status:['open','reopen']`, by `aid`, plus `host_info.internet_exposure:'Yes'`) |
| Host sensor state and assigned prevention policy | `GET /devices/entities/devices/v2` |
| Prevention policy settings | `GET /policy/entities/prevention/v1` |

A host is linked to an external asset by the asset's `ip.aid`, or, when that is
empty, by the sensor's `external_ip` matching an external IP asset. Open CVEs on
hosts that cannot be linked to an external asset are counted as `vulns_unlinked`
and not imported, because Judah has no internet-facing endpoint to validate them against.

## Prevention posture (block vs detect)

Each linked host is classified from its assigned prevention policy and sensor state:

| Mode | Meaning |
|---|---|
| `prevent` | Policy enabled and at least one ML **prevention** level is above `DISABLED`, or a blocking control (prevent/block/quarantine/kill) is on |
| `detect_only` | Policy enabled, ML detection on, every prevention level and blocking control off |
| `disabled` | Policy disabled, or every detection and prevention setting off |
| `degraded` | Sensor is in Reduced Functionality Mode and cannot enforce prevention |
| `unknown` | No policy assigned, host aged out, or the Hosts / Prevention policies scope is missing |

The posture is stored on the asset (`metadata.crowdstrike.protection`), on each
finding (`metadata.crowdstrike_protection` and `metadata.compensating_controls`),
and as a `cs-prevention:<mode>` tag on both, so you can filter for, e.g.,
internet-exposed KEV CVEs on hosts that are only in detect mode. Imported
severity is CrowdStrike's; the posture is recorded as a compensating control and
does not lower severity on its own.

## What is imported

- **Assets:** IP and domain assets (`source:crowdstrike`, `is_public=true`) with criticality, triage, ASN/ISP, cloud VM and subsidiary data.
- **Ports:** every exposed service, with product/version/CPE from Falcon's application fingerprints.
- **Findings:** one per (external asset, Spotlight vulnerability), with CVE, CVSS, ExPRT rating, CISA KEV, exploit status, remediation and the full `exposure_path`.
- On each sync, imported findings that Falcon no longer reports as open are resolved.

## Validating the exposure

Each finding stores the external host and first exposed port (`metadata.scanned_ip`,
`metadata.port`). **Validate** on the finding (`POST /vulnerabilities/{id}/validate`)
re-probes that port with Nmap from Judah's scanner network:

- port closed/filtered → `false_positive` (the exposure CrowdStrike reports is not reachable from the internet);
- port open → `needs_more_evidence` (reachable; the CVE itself still needs its own reproduction, for example Nuclei or an Aegis Vanguard run against the asset).

## Falcon prerequisites

1. In Falcon, open **Support and resources → API clients and keys** and add an API client.
2. Grant **Read** on:
   - **Exposure Management** (required)
   - **Vulnerabilities** (exposure-path findings)
   - **Hosts** (host linking and sensor state)
   - **Prevention policies** (block vs detect posture)
3. Copy the client ID and secret, and note the cloud region (US-1, US-2, EU-1, US-GOV-1, US-GOV-2).
4. For Flight Control, enter the child tenant's **Member CID** under *Advanced*.

Missing optional scopes do not fail the connection: **Test** lists them, and sync
skips those steps and records a warning.

## Setup in Judah

**Integrations → CrowdStrike Falcon Exposure Management → Connect CrowdStrike.**
Credentials are validated before saving and encrypted at rest. The optional
*External-asset FQL filter* narrows the import (for example `criticality:'Critical'`).

API: `GET|POST /integrations/crowdstrike`, `PUT|DELETE /integrations/crowdstrike/{id}`,
`POST /integrations/crowdstrike/{id}/test`, `POST /integrations/crowdstrike/{id}/sync`.

Existing deployments that don't auto-create tables should apply
`db/migrations/add_crowdstrike_integration.sql`.
