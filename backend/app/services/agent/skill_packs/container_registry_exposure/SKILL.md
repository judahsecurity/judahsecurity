---
name: container_registry_exposure
description: Planner scenario for anonymous pull on Azure Container Registry or another Docker registry.
triggers: (?i)\.azurecr\.io\b|/v2/_catalog|docker.?registry
---

ACR *.azurecr.io anonymous pull is SUBMIT High on anonymous oauth2 token + catalog names; raise Critical if a bounded 1–3 image scan recovers ghp_* / git+https PATs — do not pull the whole catalog, do not push, do not re-authenticate recovered tokens.

Validation bar: ACR/Docker anonymous pull IMPROVE until an unauth oauth2 token and/or /v2/_catalog names are proven; raise to Critical if sampled images contain ghp_* / git+https PATs. Do not pull the whole catalog; do not re-authenticate recovered tokens.

Workflow (do not crawl registry hosts as websites):
1. Harvest hosts: `query_assets(search="azurecr.io", limit=30)` when you have an org. Do not brute customer-name patterns.
2. `probe_registry_anonymous(host="<name>.azurecr.io")`. Unauth token + catalog names is the finding. Do not `docker pull`.
3. If `verdict=SUBMIT`: `create_finding` High, then `queue_finding_followups(vuln_type="docker_registry")`. Bounded 1–3 tag config/history/lockfile only if hunting secrets — not the forced first probe.
4. Expired `ghs_*` is still a leak pattern. Internal Artifactory/NATS/Keycloak strings → rotate; do not hunt those hosts.

Finding bar: ACR anonymous pull + catalog names is High; live ghp_* in pullable images is Critical — do not pull the catalog or reuse recovered PATs.
