# Censys ASM field mapping

Each Censys ASM workspace has its own field mapping rules. Open **Integrations → Censys ASM → Map fields** to add or edit them. The editor can request one live example of a host, domain, subdomain, certificate, or risk so an analyst can see paths and sample values before saving.

The existing import always controls identity, organization ownership, source attribution, and risk-to-asset association. Mapping rules enrich those records; they cannot change those protected fields. Rules take effect on the next manual or scheduled sync and also refresh existing assets and findings.

## Targets

The editor lists the canonical asset and finding fields it can populate. Asset targets include operating system, ASN, location, hosting provider, HTTP details, DNS, TLS, and last seen. Finding targets include CVE, CVSS, evidence, remediation, references, and detection timestamps. Values with the wrong type are skipped rather than overwriting existing data.

Choose **Custom metadata** for a field that has no canonical target. It is stored under `metadata.censys_asm.custom.<name>` and displayed on the asset or finding detail page. Custom values are bounded to 8 KiB each. This extends the data Judah retains without adding a database column for each Censys field; custom fields are not yet filterable or sortable in inventory and findings lists.

Source paths use dot notation, with a numeric list index when needed. Examples: `host.operating_system.product`, `host.location.country`, and `host.services[0].service_name`. A rule is specific to one Censys entity type. Up to 50 rules may be saved per workspace.

## Data quality and operational notes

- The sample field list shows a single current Censys record. A field absent from that record may still occur on other records. Use Censys's in-console API documentation and a representative sample when defining production mappings.
- The importer still uses Censys ASM asset-list and risk-instance endpoints. Service/port collections and certificate-to-host relationships need dedicated normalization before they can populate Judah's `PortService` and relationship models.
- Saving rules does not start a sync. Confirm `Last sync — OK` and inspect a mapped asset or finding after the next sync. A successful **Test** only validates the API key.
