"""Read-only Wiz GraphQL client and exposure-management importer."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.db.database import SessionLocal
from app.models.wiz_integration import WizApplicationEndpoint, WizAssetLink
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.models.wiz_integration import WizIntegration
from app.services.integration_asset_reconciliation import mark_asset_seen, reconcile_asset_membership

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "wiz"
DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_AUDIENCE = "wiz-api"

VULNERABILITY_FINDINGS_QUERY = """
query JudahWizVulnerabilityFindings($first: Int!, $after: String, $filterBy: VulnerabilityFindingFilters) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    totalCount
    nodes {
      id
      portalUrl
      name
      CVEDescription
      score
      severity
      nvdSeverity
      vendorSeverity
      status
      firstDetectedAt
      lastDetectedAt
      updatedAt
      resolvedAt
      description
      remediation
      detailedName
      version
      fixedVersion
      link
      projects { id name }
      vulnerableAsset {
        __typename
        ... on VulnerableAssetBase {
          id
          type
          name
          region
          providerUniqueId
          cloudProviderURL
          cloudPlatform
          status
          subscriptionName
          subscriptionExternalId
          subscriptionId
          tags
          hasLimitedInternetExposure
          hasWideInternetExposure
        }
        ... on VulnerableAssetVirtualMachine {
          operatingSystem
          ipAddresses
          imageName
          nativeType
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

VIRTUAL_MACHINES_QUERY = """
query JudahWizVirtualMachines($first: Int!, $after: String, $filterBy: CloudResourceV2Filters) {
  cloudResourcesV2(first: $first, after: $after, filterBy: $filterBy) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id externalId providerUniqueId name type nativeType cloudPlatform region status
      isOpenToAllInternet isAccessibleFromInternet
      cloudAccount { id externalId name cloudProvider }
      typeFields {
        ... on CloudResourceV2VirtualMachine { operatingSystem ipAddresses instanceType }
      }
      issueAnalytics { issueCount criticalSeverityCount highSeverityCount mediumSeverityCount lowSeverityCount }
    }
  }
}
"""

APPLICATION_ENDPOINTS_QUERY = """
query JudahWizApplicationEndpoints($first: Int!, $after: String, $filterBy: ApplicationEndpointFilters) {
  applicationEndpoints(first: $first, after: $after, filterBy: $filterBy) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id externalId name host port protocols exposureLevel scanSources portStatus
      firstSeen updatedAt deletedAt cloudPlatform
      cloudAccount { id externalId cloudProvider }
      domain { id name }
      owningApplicationServices { id displayName }
      httpResults {
        pageTitle statusCode statusText contentType authenticationMethod
        authenticationServiceProvider screenshotUrl
      }
      hostedTechnologies {
        id name cpe
        versionDetails { version isEndOfLife latestVersion }
        technology { id name icon categories { id name stackLayer } }
      }
      resources { id providerUniqueId name type }
      issueAnalytics {
        issueCount criticalSeverityCount highSeverityCount mediumSeverityCount
        lowSeverityCount informationalSeverityCount
      }
    }
  }
}
"""

ENDPOINT_ISSUES_QUERY = """
query JudahWizEndpointIssues($first: Int!, $after: String) {
  cloudResources(first: $first, after: $after, filterBy: {type: ["ENDPOINT"]}) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id type
      graphEntity {
        id type
        relatedIssues(first: 100) {
          totalCount
          pageInfo { hasNextPage endCursor }
          nodes { id severity status url }
        }
      }
    }
  }
}
"""

MORE_ENDPOINT_ISSUES_QUERY = """
query JudahWizMoreEndpointIssues($id: ID!, $after: String) {
  graphEntity(id: $id, type: ENDPOINT) {
    id
    relatedIssues(first: 100, after: $after) {
      totalCount
      pageInfo { hasNextPage endCursor }
      nodes { id severity status url }
    }
  }
}
"""

AI_ENDPOINT_GRAPH_QUERY = """
query JudahWizAiEndpointPaths($query: GraphEntityQueryInput!, $first: Int!, $after: String) {
  graphSearch(query: $query, first: $first, after: $after) {
    totalCount
    maxCountReached
    pageInfo { hasNextPage endCursor }
    nodes { entities { id type name } }
  }
}
"""

AI_COMPONENT_TYPES = (
    "AI_AGENT", "AI_AGENT_REGISTRY", "AI_EXTENSION", "AI_GATEWAY", "AI_GUARDRAIL",
    "AI_MODEL", "AI_PIPELINE", "AI_PLUGIN", "MCP_SERVER", "AI_TOOL",
    "AI_SKILL_TEMPLATE", "AI_SKILL", "AI_SERVICE",
)

AI_ENDPOINT_GRAPH_FILTER = {
    "type": list(AI_COMPONENT_TYPES),
    "select": True,
    "relationships": [{
        "type": [{"type": "RUNS", "reverse": True}],
        "with": {
            "type": ["VIRTUAL_MACHINE", "CONTAINER", "CONTAINER_IMAGE", "SERVERLESS"],
            "select": True,
            "relationships": [{
                "type": [{"type": "SERVES"}],
                "with": {"type": ["ENDPOINT"], "select": True},
            }],
        },
    }],
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class WizApiError(RuntimeError):
    """A safe, user-displayable Wiz API error."""


def _validate_wiz_url(value: str, label: str) -> str:
    raw = (value or "").strip().rstrip("/")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise WizApiError(f"{label} must be an HTTPS Wiz URL without embedded credentials.")
    if not (host.endswith(".wiz.io") or host.endswith(".wiz.us")):
        raise WizApiError(f"{label} must use a wiz.io or wiz.us host.")
    return raw


class WizClient:
    """Read-only OAuth2 + GraphQL client for Wiz findings and endpoints."""

    PAGE_SIZE = 100
    VM_PAGE_SIZE = 500
    MAX_PAGES = 10000
    ENDPOINT_MAX_PAGES = 2000

    def __init__(
        self,
        api_endpoint: str,
        client_id: str,
        client_secret: str,
        *,
        auth_url: str = DEFAULT_AUTH_URL,
        audience: str = DEFAULT_AUDIENCE,
    ) -> None:
        endpoint = _validate_wiz_url(api_endpoint, "API endpoint")
        self.api_endpoint = endpoint if endpoint.endswith("/graphql") else f"{endpoint}/graphql"
        self.auth_url = _validate_wiz_url(auth_url, "Authentication URL")
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience or DEFAULT_AUDIENCE
        self._token: Optional[str] = None
        self.findings_truncated = False
        self.virtual_machines_total_count: Optional[int] = None
        self.vulnerability_findings_total_count: Optional[int] = None

    async def authenticate(self) -> str:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.auth_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "audience": self.audience,
                    },
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise WizApiError(f"Could not reach the Wiz authentication endpoint: {exc}") from exc
        if response.status_code != 200:
            raise WizApiError(f"Wiz authentication failed (HTTP {response.status_code}).")
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise WizApiError("Wiz authentication returned an invalid JSON response.") from exc
        if not token:
            raise WizApiError("Wiz authentication response did not contain an access token.")
        self._token = str(token)
        return self._token

    async def graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        token = self._token or await self.authenticate()
        for attempt in range(4):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        self.api_endpoint,
                        json={"query": query, "variables": variables},
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                        },
                    )
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise WizApiError(f"Could not reach the Wiz GraphQL endpoint: {exc}") from exc
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code in (429, 502, 503, 504) and attempt < 3:
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code in (401, 403):
                raise WizApiError(
                    f"Wiz rejected the request (HTTP {response.status_code}); check credentials and read scopes."
                )
            if response.status_code != 200:
                raise WizApiError(f"Wiz GraphQL request failed (HTTP {response.status_code}).")
            try:
                payload = response.json()
            except ValueError as exc:
                raise WizApiError("Wiz GraphQL returned an invalid JSON response.") from exc
            if payload.get("errors"):
                messages = "; ".join(
                    str(item.get("message", "GraphQL error")) for item in payload["errors"][:3]
                )
                raise WizApiError(f"Wiz GraphQL error: {messages[:700]}")
            return payload.get("data") or {}
        raise WizApiError("Wiz GraphQL request failed after retries.")

    async def iter_vulnerability_findings(
        self, *, limit: Optional[int] = None, filter_by: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Stream findings until Wiz confirms the last page; never accept a page cap as complete."""
        cursor: Optional[str] = None
        cursors: set[str] = set()
        seen = 0
        self.findings_truncated = False
        self.vulnerability_findings_total_count = None
        for _ in range(self.MAX_PAGES):
            data = await self.graphql(
                VULNERABILITY_FINDINGS_QUERY,
                {"first": min(self.PAGE_SIZE, limit - seen) if limit is not None else self.PAGE_SIZE,
                 "after": cursor, "filterBy": filter_by or {}},
            )
            connection = data.get("vulnerabilityFindings") or {}
            if self.vulnerability_findings_total_count is None:
                self.vulnerability_findings_total_count = connection.get("totalCount")
            batch = connection.get("nodes")
            if not isinstance(batch, list):
                raise WizApiError("Wiz returned an unexpected vulnerability findings payload.")
            rows = [item for item in batch if isinstance(item, dict)]
            seen += len(rows)
            if rows:
                yield rows
            page_info = connection.get("pageInfo") or {}
            if limit is not None and seen >= limit:
                self.findings_truncated = bool(page_info.get("hasNextPage"))
                return
            if not page_info.get("hasNextPage"):
                if (limit is None and isinstance(self.vulnerability_findings_total_count, int)
                        and seen < self.vulnerability_findings_total_count):
                    raise WizApiError("Wiz vulnerability findings ended before their reported total.")
                return
            next_cursor = page_info.get("endCursor")
            if not next_cursor or next_cursor in cursors:
                raise WizApiError("Wiz vulnerability finding pagination cursor was missing or repeated.")
            cursors.add(next_cursor)
            cursor = next_cursor
        raise WizApiError("Wiz vulnerability finding pagination exceeded the page limit.")

    async def get_vulnerability_findings(
        self, *, limit: Optional[int] = None, filter_by: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        async for page in self.iter_vulnerability_findings(limit=limit, filter_by=filter_by):
            findings.extend(page)
        return findings

    async def iter_virtual_machines(
        self, *, exposed_only: bool
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Stream the VM inventory independently of the much larger findings feed."""
        cursor: Optional[str] = None
        seen: set[str] = set()
        filter_by: Dict[str, Any] = {"type": {"equals": ["VIRTUAL_MACHINE"]}}
        if exposed_only:
            filter_by["isAccessibleFromInternet"] = {"equals": True}
        self.virtual_machines_total_count = None
        for _ in range(self.ENDPOINT_MAX_PAGES):
            data = await self.graphql(
                VIRTUAL_MACHINES_QUERY,
                {"first": self.VM_PAGE_SIZE, "after": cursor, "filterBy": filter_by},
            )
            connection = data.get("cloudResourcesV2") or {}
            if self.virtual_machines_total_count is None:
                self.virtual_machines_total_count = connection.get("totalCount")
            nodes = connection.get("nodes")
            if not isinstance(nodes, list):
                raise WizApiError("Wiz returned an unexpected virtual machine inventory payload.")
            batch = []
            for node in nodes:
                if not isinstance(node, dict) or node.get("type") != "VIRTUAL_MACHINE" or not node.get("id"):
                    continue
                wiz_id = str(node["id"])
                if wiz_id in seen:
                    continue
                seen.add(wiz_id)
                vm = node.get("typeFields") or {}
                account = node.get("cloudAccount") or {}
                batch.append({
                    **node,
                    "operatingSystem": vm.get("operatingSystem"),
                    "ipAddresses": vm.get("ipAddresses") or [],
                    "instanceType": vm.get("instanceType"),
                    "subscriptionId": account.get("id"),
                    "subscriptionExternalId": account.get("externalId"),
                    "subscriptionName": account.get("name"),
                    "hasWideInternetExposure": bool(node.get("isOpenToAllInternet")),
                    "hasLimitedInternetExposure": bool(node.get("isAccessibleFromInternet")),
                })
            if batch:
                yield batch
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                return
            next_cursor = page_info.get("endCursor")
            if not next_cursor or next_cursor == cursor:
                raise WizApiError("Wiz virtual machine pagination cursor was missing or repeated.")
            cursor = next_cursor
        raise WizApiError("Wiz virtual machine pagination exceeded the page limit.")

    async def iter_application_endpoints(
        self, *, limit: Optional[int] = None, ids: Optional[List[str]] = None
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Stream complete endpoint pages; stable Wiz IDs deduplicate moving pages."""
        cursor: Optional[str] = None
        seen: set[str] = set()
        reported_total: Optional[int] = None
        page_size = self.PAGE_SIZE
        for _ in range(self.ENDPOINT_MAX_PAGES):
            remaining = limit - len(seen) if limit is not None else page_size
            if remaining <= 0:
                return
            while True:
                try:
                    data = await self.graphql(
                        APPLICATION_ENDPOINTS_QUERY,
                        {
                            "first": min(page_size, remaining),
                            "after": cursor,
                            "filterBy": {"id": {"equals": ids}} if ids is not None else {},
                        },
                    )
                    break
                except WizApiError as exc:
                    if "'first' must be less than or equal" not in str(exc) or page_size == 1:
                        raise
                    page_size = max(1, page_size // 2)
                    logger.warning("Wiz application endpoint page size reduced to %s after API limit error", page_size)
            connection = data.get("applicationEndpoints") or {}
            if reported_total is None and isinstance(connection.get("totalCount"), int):
                reported_total = connection["totalCount"]
            nodes = connection.get("nodes")
            if not isinstance(nodes, list):
                raise WizApiError("Wiz returned an unexpected application endpoints payload.")
            batch = []
            for item in nodes:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                wiz_id = str(item["id"])
                if wiz_id not in seen:
                    seen.add(wiz_id)
                    batch.append(item)
            if batch:
                yield batch
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                if limit is None and reported_total is not None and len(seen) < reported_total:
                    raise WizApiError("Wiz application endpoint inventory ended before its reported total.")
                return
            next_cursor = page_info.get("endCursor")
            if not next_cursor or next_cursor == cursor:
                raise WizApiError("Wiz application endpoint pagination cursor was missing or repeated.")
            cursor = next_cursor
        raise WizApiError("Wiz application endpoint pagination exceeded the page limit.")

    async def iter_endpoint_issues(self) -> AsyncIterator[List[Dict[str, Any]]]:
        """Stream issue links belonging to ENDPOINT entities, including nested pages."""
        cursor: Optional[str] = None
        seen: set[str] = set()
        for _ in range(self.ENDPOINT_MAX_PAGES):
            data = await self.graphql(
                ENDPOINT_ISSUES_QUERY, {"first": 500, "after": cursor}
            )
            connection = data.get("cloudResources") or {}
            nodes = connection.get("nodes")
            if not isinstance(nodes, list):
                raise WizApiError("Wiz returned an unexpected endpoint issue payload.")
            batch = []
            for item in nodes:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                wiz_id = str(item["id"])
                if wiz_id in seen:
                    continue
                seen.add(wiz_id)
                entity = item.get("graphEntity") or {}
                if entity.get("id") != wiz_id or entity.get("type") != "ENDPOINT":
                    raise WizApiError("Wiz endpoint issue entity did not match its resource.")
                related = entity.get("relatedIssues") or {}
                issues = list(related.get("nodes") or [])
                reported_count = related.get("totalCount")
                issue_cursor = (related.get("pageInfo") or {}).get("endCursor")
                while (related.get("pageInfo") or {}).get("hasNextPage"):
                    if not issue_cursor:
                        raise WizApiError("Wiz endpoint issue cursor was missing.")
                    more = await self.graphql(
                        MORE_ENDPOINT_ISSUES_QUERY, {"id": wiz_id, "after": issue_cursor}
                    )
                    more_entity = more.get("graphEntity") or {}
                    if more_entity.get("id") != wiz_id:
                        raise WizApiError("Wiz endpoint issue page changed entity.")
                    related = more_entity.get("relatedIssues") or {}
                    issues.extend(related.get("nodes") or [])
                    next_cursor = (related.get("pageInfo") or {}).get("endCursor")
                    if next_cursor == issue_cursor:
                        raise WizApiError("Wiz endpoint issue cursor repeated.")
                    issue_cursor = next_cursor
                unique = {
                    str(issue["id"]): issue
                    for issue in issues
                    if isinstance(issue, dict) and issue.get("id")
                }
                if reported_count is not None and len(unique) != reported_count:
                    raise WizApiError("Wiz endpoint issue pagination returned an incomplete set.")
                batch.append({
                    "id": wiz_id,
                    "issues": list(unique.values()),
                    "issue_count": reported_count,
                })
            if batch:
                yield batch
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                return
            next_cursor = page_info.get("endCursor")
            if not next_cursor or next_cursor == cursor:
                raise WizApiError("Wiz endpoint graph pagination cursor was missing or repeated.")
            cursor = next_cursor
        raise WizApiError("Wiz endpoint graph pagination exceeded the page limit.")

    async def iter_ai_endpoint_paths(self) -> AsyncIterator[List[Dict[str, Any]]]:
        """Find ENDPOINTs served by workloads that run AI graph entities."""
        cursor: Optional[str] = None
        for _ in range(self.ENDPOINT_MAX_PAGES):
            data = await self.graphql(
                AI_ENDPOINT_GRAPH_QUERY,
                {"query": AI_ENDPOINT_GRAPH_FILTER, "first": 500, "after": cursor},
            )
            connection = data.get("graphSearch") or {}
            if connection.get("maxCountReached"):
                raise WizApiError("Wiz AI graph search reached its result cap.")
            nodes = connection.get("nodes")
            if not isinstance(nodes, list):
                raise WizApiError("Wiz returned an unexpected AI graph search payload.")
            yield [node for node in nodes if isinstance(node, dict)]
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                return
            next_cursor = page_info.get("endCursor")
            if not next_cursor or next_cursor == cursor:
                raise WizApiError("Wiz AI graph cursor was missing or repeated.")
            cursor = next_cursor
        raise WizApiError("Wiz AI graph pagination exceeded the page limit.")


def _client_for(integration: WizIntegration) -> WizClient:
    client_id = integration.get_client_id()
    client_secret = integration.get_client_secret()
    if not client_id or not client_secret:
        raise WizApiError("No Wiz client credentials are stored for this connection.")
    return WizClient(
        integration.api_endpoint,
        client_id,
        client_secret,
        auth_url=integration.auth_url,
        audience=integration.audience,
    )


async def test_connection(
    api_endpoint: str,
    client_id: str,
    client_secret: str,
    *,
    auth_url: str = DEFAULT_AUTH_URL,
    audience: str = DEFAULT_AUDIENCE,
) -> Dict[str, Any]:
    try:
        client = WizClient(
            api_endpoint,
            client_id,
            client_secret,
            auth_url=auth_url,
            audience=audience,
        )
        await client.get_vulnerability_findings(limit=1)
        vm_probe = await client.graphql(
            VIRTUAL_MACHINES_QUERY,
            {"first": 1, "after": None, "filterBy": {"type": {"equals": ["VIRTUAL_MACHINE"]}}},
        )
        if not isinstance((vm_probe.get("cloudResourcesV2") or {}).get("nodes"), list):
            raise WizApiError("Wiz virtual machine inventory access returned an unexpected payload.")
        async for _ in client.iter_application_endpoints(limit=1):
            break
        issue_probe = await client.graphql(
            ENDPOINT_ISSUES_QUERY, {"first": 1, "after": None}
        )
        if not isinstance((issue_probe.get("cloudResources") or {}).get("nodes"), list):
            raise WizApiError("Wiz endpoint graph access returned an unexpected payload.")
        return {
            "ok": True,
            "message": "Connected to Wiz and verified findings, virtual machines, application endpoints, and endpoint issue access.",
            "findings_accessible": True,
            "endpoints_accessible": True,
        }
    except WizApiError as exc:
        return {"ok": False, "message": str(exc), "findings_accessible": False, "endpoints_accessible": False}


def _map_severity(value: Any) -> Severity:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), Severity.MEDIUM)


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except (TypeError, ValueError):
        return None


def _is_virtual_machine(asset: Dict[str, Any]) -> bool:
    markers = " ".join(
        str(asset.get(key) or "") for key in ("__typename", "type", "nativeType")
    ).upper()
    return "VIRTUALMACHINE" in markers.replace("_", "") or bool(asset.get("operatingSystem"))


def _is_internet_exposed(asset: Dict[str, Any]) -> bool:
    return bool(asset.get("hasWideInternetExposure") or asset.get("hasLimitedInternetExposure"))


def _asset_value(asset: Dict[str, Any]) -> Optional[str]:
    return next(
        (
            str(value).strip()
            for value in (
                asset.get("providerUniqueId"),
                asset.get("id"),
                asset.get("name"),
                *((asset.get("ipAddresses") or []) if isinstance(asset.get("ipAddresses"), list) else []),
            )
            if value not in (None, "") and str(value).strip()
        ),
        None,
    )


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.assets_retired = 0
        self.vm_links_removed = 0
        self.endpoint_links_removed = 0
        self.legacy_vm_links_bootstrapped = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.findings_seen = 0
        self.findings_filtered = 0
        self.findings_unchanged = 0
        self.findings_truncated = False
        self.findings_total_count: Optional[int] = None
        self.findings_scope = "related_issues_on_internet_accessible_virtual_machines"
        self.assets_complete = False
        self.findings_complete = False
        self.virtual_machines_total_count: Optional[int] = None
        self.virtual_machines_seen = 0
        self.endpoints_seen = 0
        self.endpoints_created = 0
        self.endpoints_updated = 0
        self.ai_endpoints_seen = 0
        self.ai_graph_paths_seen = 0
        self.ai_graph_endpoints_seen = 0
        self.ai_graph_entities_missing = 0
        self.endpoints_with_issues = 0
        self.endpoint_issue_links = 0
        self.endpoint_issue_count_mismatches = 0
        self.endpoint_issue_entities_missing = 0

    def as_dict(self) -> Dict[str, Any]:
        return vars(self).copy()


def _upsert_asset(
    db: Session, integration: WizIntegration, source: Dict[str, Any], stats: _Stats, seen_at: datetime,
) -> Asset:
    value = _asset_value(source)
    if not value:
        raise ValueError("Wiz virtual machine has no stable identifier")
    wiz_id = str(source.get("id") or value)[:255]
    link = db.query(WizAssetLink).filter_by(integration_id=integration.id, wiz_id=wiz_id).first()
    asset = db.get(Asset, link.asset_id) if link else None
    if asset is None:
        asset = db.query(Asset).filter(
            Asset.organization_id == integration.organization_id, Asset.value == value,
        ).first()
    ips = [str(ip) for ip in (source.get("ipAddresses") or []) if ip]
    metadata = dict(asset.metadata_ or {}) if asset else {}
    metadata["wiz"] = {
        "id": source.get("id"),
        "integration_id": integration.id,
        "provider_unique_id": source.get("providerUniqueId"),
        "cloud_platform": source.get("cloudPlatform"),
        "cloud_provider_url": source.get("cloudProviderURL"),
        "subscription_id": source.get("subscriptionId"),
        "subscription_external_id": source.get("subscriptionExternalId"),
        "subscription_name": source.get("subscriptionName"),
        "region": source.get("region"),
        "native_type": source.get("nativeType"),
        "image_name": source.get("imageName"),
        "instance_type": source.get("instanceType"),
        "issue_analytics": source.get("issueAnalytics"),
        "status": source.get("status"),
        "tags": source.get("tags") or [],
        "has_wide_internet_exposure": bool(source.get("hasWideInternetExposure")),
        "has_limited_internet_exposure": bool(source.get("hasLimitedInternetExposure")),
    }
    if asset:
        asset.name = str(source.get("name") or asset.name)[:255]
        if asset.discovery_source == DISCOVERY_SOURCE:
            asset.value = value[:500]
        asset.last_seen = seen_at
        operating_system = source.get("operatingSystem")
        if operating_system:
            asset.operating_system = str(operating_system)[:200]
        asset.ip_addresses = ips or asset.ip_addresses
        asset.ip_address = (ips[0] if ips else asset.ip_address)
        asset.hosting_provider = (
            str(source.get("cloudPlatform") or asset.hosting_provider or "").lower()[:100] or None
        )
        asset.hosting_type = "cloud"
        asset.is_public = _is_internet_exposed(source)
        asset.metadata_ = metadata
        mark_asset_seen(asset, DISCOVERY_SOURCE)
        stats.assets_updated += 1
    else:
        asset = Asset(
            name=str(source.get("name") or value)[:255],
            asset_type=AssetType.CLOUD_RESOURCE,
            value=value[:500],
            organization_id=integration.organization_id,
            status=AssetStatus.DISCOVERED,
            discovery_source=DISCOVERY_SOURCE,
            association_reason="Virtual machine attributed to the organization by Wiz",
            association_confidence=95,
            tags=["source:wiz"],
            metadata_=metadata,
            operating_system=(str(source.get("operatingSystem"))[:200] if source.get("operatingSystem") else None),
            ip_addresses=ips,
            ip_address=ips[0] if ips else None,
            hosting_type="cloud",
            hosting_provider=str(source.get("cloudPlatform") or "").lower()[:100] or None,
            is_public=_is_internet_exposed(source),
        )
        db.add(asset)
        db.flush()
        stats.assets_created += 1
    if link is None:
        db.add(WizAssetLink(
            integration_id=integration.id, asset_id=asset.id, wiz_id=wiz_id,
            last_seen=seen_at, is_active=True,
        ))
    else:
        link.asset_id = asset.id
        link.last_seen = seen_at
        link.is_active = True
    return asset


def _cve_id(finding: Dict[str, Any]) -> Optional[str]:
    for value in (finding.get("name"), finding.get("detailedName"), finding.get("CVEDescription")):
        match = _CVE_RE.search(str(value or ""))
        if match:
            return match.group(0).upper()
    return None


def _upsert_vulnerability(
    db: Session, asset: Asset, finding: Dict[str, Any], stats: _Stats
) -> None:
    finding_id = str(finding.get("id") or "").strip()
    title = str(finding.get("detailedName") or finding.get("name") or "Wiz vulnerability")[:500]
    existing = None
    if finding_id:
        existing = db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.template_id == f"wiz:{finding_id}"[:255],
        ).first()
    if existing is None:
        existing = db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.title == title,
        ).first()

    severity = _map_severity(
        finding.get("severity") or finding.get("vendorSeverity") or finding.get("nvdSeverity")
    )
    raw_status = str(finding.get("status") or "OPEN").upper()
    resolved = raw_status in {"RESOLVED", "CLOSED"} or bool(finding.get("resolvedAt"))
    score = finding.get("score")
    try:
        cvss_score = float(score) if score is not None else None
    except (TypeError, ValueError):
        cvss_score = None
    references = [
        str(url) for url in (finding.get("portalUrl"), finding.get("link")) if url
    ]
    metadata = {
        "source": DISCOVERY_SOURCE,
        "wiz_finding_id": finding_id or None,
        "wiz_status": raw_status,
        "wiz_updated_at": finding.get("updatedAt"),
        "vendor_severity": finding.get("vendorSeverity"),
        "nvd_severity": finding.get("nvdSeverity"),
        "version": finding.get("version"),
        "fixed_version": finding.get("fixedVersion"),
        "projects": finding.get("projects") or [],
    }
    if existing:
        existing.title = title
        existing.description = finding.get("description") or finding.get("CVEDescription")
        existing.severity = severity
        existing.cvss_score = cvss_score
        existing.cve_id = _cve_id(finding)
        existing.references = references
        existing.remediation = finding.get("remediation")
        existing.affected_component = (
            str(finding.get("version"))[:500] if finding.get("version") is not None else None
        )
        existing.last_detected = _parse_datetime(finding.get("lastDetectedAt")) or datetime.utcnow()
        existing.metadata_ = metadata
        if resolved:
            existing.status = VulnerabilityStatus.RESOLVED
            existing.resolved_at = _parse_datetime(finding.get("resolvedAt")) or datetime.utcnow()
        elif existing.status == VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.OPEN
            existing.resolved_at = None
        stats.vulns_updated += 1
        return
    vulnerability = Vulnerability(
        title=title,
        description=finding.get("description") or finding.get("CVEDescription"),
        severity=severity,
        cvss_score=cvss_score,
        cve_id=_cve_id(finding),
        references=references,
        remediation=finding.get("remediation"),
        affected_component=(
            str(finding.get("version"))[:500] if finding.get("version") is not None else None
        ),
        asset_id=asset.id,
        detected_by=DISCOVERY_SOURCE,
        template_id=f"wiz:{finding_id}"[:255] if finding_id else None,
        status=VulnerabilityStatus.RESOLVED if resolved else VulnerabilityStatus.OPEN,
        first_detected=_parse_datetime(finding.get("firstDetectedAt")) or datetime.utcnow(),
        last_detected=_parse_datetime(finding.get("lastDetectedAt")) or datetime.utcnow(),
        resolved_at=_parse_datetime(finding.get("resolvedAt")) if resolved else None,
        tags=["source:wiz"],
        metadata_=metadata,
    )
    db.add(vulnerability)
    stats.vulns_created += 1


def _endpoint_is_ai(endpoint: Dict[str, Any]) -> bool:
    return any(
        category.get("stackLayer") == "MACHINE_LEARNING_AND_AI"
        for hosted in endpoint.get("hostedTechnologies") or []
        for category in (hosted.get("technology") or {}).get("categories") or []
    )


def _endpoint_asset_value(endpoint: Dict[str, Any]) -> Optional[str]:
    value = str(endpoint.get("name") or "").strip()
    if not value:
        host = str(endpoint.get("host") or "").strip()
        if not host:
            return None
        port = endpoint.get("port")
        value = f"{host}:{port}" if port is not None else host
    return value[:500]


def _upsert_endpoint_batch(
    db: Session,
    integration: WizIntegration,
    batch: List[Dict[str, Any]],
    stats: _Stats,
    seen_at: datetime,
) -> None:
    ids = [str(item["id"]) for item in batch]
    existing = {
        row.wiz_id: row
        for row in db.query(WizApplicationEndpoint).filter(
            WizApplicationEndpoint.integration_id == integration.id,
            WizApplicationEndpoint.wiz_id.in_(ids),
        ).all()
    }
    asset_values = {
        value for item in batch if (value := _endpoint_asset_value(item))
    }
    asset_by_value = {
        asset.value: asset
        for asset in db.query(Asset).filter(
            Asset.organization_id == integration.organization_id,
            Asset.value.in_(asset_values),
        ).order_by(Asset.id).all()
    } if integration.import_assets and asset_values else {}
    linked_ids = [row.asset_id for row in existing.values() if row.asset_id]
    linked_assets = {
        asset.id: asset
        for asset in db.query(Asset).filter(Asset.id.in_(linked_ids)).all()
    } if integration.import_assets and linked_ids else {}
    new_rows: List[WizApplicationEndpoint] = []
    for item in batch:
        wiz_id = str(item["id"])
        row = existing.get(wiz_id)
        if row is None:
            row = WizApplicationEndpoint(
                integration_id=integration.id,
                organization_id=integration.organization_id,
                wiz_id=wiz_id,
            )
            new_rows.append(row)
            stats.endpoints_created += 1
        else:
            stats.endpoints_updated += 1
        row.name = item.get("name")
        row.host = str(item.get("host"))[:500] if item.get("host") else None
        row.port = item.get("port")
        row.exposure_level = item.get("exposureLevel")
        row.is_ai = _endpoint_is_ai(item) or bool(row.ai_components)
        row.is_active = True
        row.endpoint_data = item
        row.last_seen = seen_at
        stats.endpoints_seen += 1
        stats.ai_endpoints_seen += int(row.is_ai)

        value = _endpoint_asset_value(item)
        if not integration.import_assets or not value:
            continue
        asset = linked_assets.get(row.asset_id) if row.asset_id else None
        if asset is None:
            asset = asset_by_value.get(value)
        if asset is None:
            is_http = urlparse(value).scheme in {"http", "https"}
            asset = Asset(
                organization_id=integration.organization_id,
                name=value[:255],
                value=value,
                asset_type=AssetType.URL if is_http else AssetType.SERVICE,
                status=AssetStatus.DISCOVERED,
                discovery_source=DISCOVERY_SOURCE,
                association_reason="Application endpoint attributed to the organization by Wiz",
                association_confidence=95,
                tags=["source:wiz", "type:endpoint"],
                is_public=item.get("exposureLevel") == "HIGH",
            )
            db.add(asset)
            asset_by_value[value] = asset
            stats.assets_created += 1
        else:
            stats.assets_updated += 1
        if asset.discovery_source == DISCOVERY_SOURCE:
            asset.name = value[:255]
            asset.value = value
        http = item.get("httpResults") or {}
        asset.http_status = http.get("statusCode")
        asset.http_title = str(http.get("pageTitle"))[:500] if http.get("pageTitle") else None
        if urlparse(value).scheme in {"http", "https"}:
            asset.live_url = value
        asset.is_live = item.get("portStatus") == "OPEN"
        asset.last_seen = seen_at
        metadata = dict(asset.metadata_ or {})
        ids_for_asset = list(metadata.get("wiz_endpoint_ids") or [])
        if wiz_id not in ids_for_asset:
            ids_for_asset.append(wiz_id)
        metadata["wiz_endpoint_ids"] = ids_for_asset
        asset.metadata_ = metadata
        tags = list(asset.tags or [])
        for tag in ("source:wiz", "type:endpoint"):
            if tag not in tags:
                tags.append(tag)
        asset.tags = tags
        mark_asset_seen(asset, DISCOVERY_SOURCE)
        row.asset = asset
    db.add_all(new_rows)
    db.flush()


async def _sync_application_endpoints(
    db: Session, integration: WizIntegration, client: WizClient, stats: _Stats,
    started_at: Optional[datetime] = None,
) -> set[int]:
    started_at = started_at or datetime.utcnow()
    async for batch in client.iter_application_endpoints():
        _upsert_endpoint_batch(db, integration, batch, stats, started_at)
        db.commit()
    async for batch in client.iter_endpoint_issues():
        ids = [item["id"] for item in batch]
        rows = {
            row.wiz_id: row
            for row in db.query(WizApplicationEndpoint).filter(
                WizApplicationEndpoint.integration_id == integration.id,
                WizApplicationEndpoint.wiz_id.in_(ids),
            ).all()
        }
        missing = [wiz_id for wiz_id in ids if wiz_id not in rows]
        for start in range(0, len(missing), client.PAGE_SIZE):
            async for endpoint_batch in client.iter_application_endpoints(
                ids=missing[start:start + client.PAGE_SIZE]
            ):
                _upsert_endpoint_batch(db, integration, endpoint_batch, stats, started_at)
        if missing:
            rows.update({
                row.wiz_id: row
                for row in db.query(WizApplicationEndpoint).filter(
                    WizApplicationEndpoint.integration_id == integration.id,
                    WizApplicationEndpoint.wiz_id.in_(missing),
                ).all()
            })
        for item in batch:
            row = rows.get(item["id"])
            if row is None:
                stats.endpoint_issue_entities_missing += 1
                continue
            row.related_issues = item["issues"]
            row.related_issue_count = item["issue_count"]
            stats.endpoint_issue_links += len(item["issues"])
            stats.endpoints_with_issues += int(bool(item["issues"]))
            analytics_count = (row.endpoint_data.get("issueAnalytics") or {}).get("issueCount")
            stats.endpoint_issue_count_mismatches += int(analytics_count != item["issue_count"])
        db.commit()
    await _sync_ai_endpoint_graph(db, integration, client, stats, started_at)
    stale_query = db.query(WizApplicationEndpoint).filter(
        WizApplicationEndpoint.integration_id == integration.id,
        WizApplicationEndpoint.last_seen < started_at,
        WizApplicationEndpoint.is_active.is_(True),
    )
    stale_asset_ids = {row[0] for row in stale_query.with_entities(
        WizApplicationEndpoint.asset_id,
    ).filter(WizApplicationEndpoint.asset_id.is_not(None)).distinct().all()}
    stats.endpoint_links_removed = stale_query.count()
    stale_query.update({WizApplicationEndpoint.is_active: False}, synchronize_session=False)
    stats.ai_endpoints_seen = db.query(WizApplicationEndpoint).filter(
        WizApplicationEndpoint.integration_id == integration.id,
        WizApplicationEndpoint.is_active.is_(True),
        WizApplicationEndpoint.is_ai.is_(True),
    ).count()
    return stale_asset_ids


async def _sync_ai_endpoint_graph(
    db: Session, integration: WizIntegration, client: WizClient,
    stats: _Stats, started_at: datetime,
) -> None:
    paths_by_endpoint: Dict[str, Dict[tuple[str, str], Dict[str, Any]]] = {}
    async for batch in client.iter_ai_endpoint_paths():
        stats.ai_graph_paths_seen += len(batch)
        for path in batch:
            entities = path.get("entities") or []
            components = [e for e in entities if e and e.get("type") in AI_COMPONENT_TYPES]
            workloads = [e for e in entities if e and e.get("type") in {
                "VIRTUAL_MACHINE", "CONTAINER", "CONTAINER_IMAGE", "SERVERLESS",
            }]
            endpoints = [e for e in entities if e and e.get("type") == "ENDPOINT"]
            if not components or not endpoints:
                continue
            for endpoint in endpoints:
                linked = paths_by_endpoint.setdefault(str(endpoint["id"]), {})
                for component in components:
                    for workload in workloads or [None]:
                        workload_id = str(workload["id"]) if workload else ""
                        linked[(str(component["id"]), workload_id)] = {
                            "id": component["id"], "type": component["type"],
                            "name": component.get("name"),
                            "workload_id": workload_id or None,
                            "workload_type": workload.get("type") if workload else None,
                        }
    stats.ai_graph_endpoints_seen = len(paths_by_endpoint)
    ids = list(paths_by_endpoint)
    for start in range(0, len(ids), client.PAGE_SIZE):
        batch_ids = ids[start:start + client.PAGE_SIZE]
        rows = {
            row.wiz_id: row
            for row in db.query(WizApplicationEndpoint).filter(
                WizApplicationEndpoint.integration_id == integration.id,
                WizApplicationEndpoint.wiz_id.in_(batch_ids),
            ).all()
        }
        missing = [wiz_id for wiz_id in batch_ids if wiz_id not in rows]
        if missing:
            async for endpoint_batch in client.iter_application_endpoints(ids=missing):
                _upsert_endpoint_batch(db, integration, endpoint_batch, stats, started_at)
            rows.update({
                row.wiz_id: row
                for row in db.query(WizApplicationEndpoint).filter(
                    WizApplicationEndpoint.integration_id == integration.id,
                    WizApplicationEndpoint.wiz_id.in_(missing),
                ).all()
            })
        for wiz_id in batch_ids:
            row = rows.get(wiz_id)
            if row is None:
                stats.ai_graph_entities_missing += 1
                continue
            row.ai_components = list(paths_by_endpoint[wiz_id].values())
            row.ai_graph_seen_at = started_at
            row.is_ai = True
        db.commit()
    stale = db.query(WizApplicationEndpoint).filter(
        WizApplicationEndpoint.integration_id == integration.id,
        WizApplicationEndpoint.ai_graph_seen_at.is_not(None),
        WizApplicationEndpoint.ai_graph_seen_at < started_at,
    ).all()
    for row in stale:
        row.ai_components = []
        row.ai_graph_seen_at = None
        row.is_ai = _endpoint_is_ai(row.endpoint_data)
    db.commit()


async def _sync_virtual_machines(
    db: Session, integration: WizIntegration, client: WizClient, stats: _Stats,
    started_at: Optional[datetime] = None,
) -> None:
    if not integration.import_assets:
        return
    started_at = started_at or datetime.utcnow()
    async for page in client.iter_virtual_machines(
        exposed_only=integration.internet_exposed_only
    ):
        for source in page:
            if not _asset_value(source):
                continue
            _upsert_asset(db, integration, source, stats, started_at)
            stats.virtual_machines_seen += 1
        db.commit()
    stats.virtual_machines_total_count = client.virtual_machines_total_count
    if (stats.virtual_machines_total_count is not None
            and stats.virtual_machines_seen < stats.virtual_machines_total_count):
        raise WizApiError("Wiz virtual machine inventory count did not match the completed pages.")


def _bootstrap_legacy_vm_links(db: Session, integration: WizIntegration, stats: _Stats) -> set[int]:
    """Attribute pre-link Wiz VMs when their connection can be identified safely."""
    connection_count = db.query(WizIntegration.id).filter(
        WizIntegration.organization_id == integration.organization_id,
    ).count()
    existing = {wiz_id: asset_id for wiz_id, asset_id in db.query(
        WizAssetLink.wiz_id, WizAssetLink.asset_id,
    ).filter(WizAssetLink.integration_id == integration.id).all()}
    orphan_ids: set[int] = set()
    for asset in db.query(Asset).filter(
        Asset.organization_id == integration.organization_id,
        Asset.discovery_source == DISCOVERY_SOURCE,
        Asset.asset_type == AssetType.CLOUD_RESOURCE,
    ).all():
        wiz = (asset.metadata_ or {}).get("wiz") or {}
        wiz_id = str(wiz.get("id") or "")[:255]
        owner = wiz.get("integration_id")
        if not wiz_id or (owner is None and connection_count != 1) or (owner is not None and owner != integration.id):
            continue
        if wiz_id in existing:
            if existing[wiz_id] != asset.id:
                orphan_ids.add(asset.id)
            continue
        db.add(WizAssetLink(
            integration_id=integration.id, asset_id=asset.id, wiz_id=wiz_id,
            last_seen=datetime.min, is_active=True,
        ))
        existing[wiz_id] = asset.id
        stats.legacy_vm_links_bootstrapped += 1
    db.flush()
    return orphan_ids


def _reconcile_wiz_assets(
    db: Session, integration: WizIntegration, stats: _Stats,
    started_at: datetime, stale_endpoint_asset_ids: set[int],
) -> None:
    if not integration.import_assets:
        return
    candidate_ids = set(stale_endpoint_asset_ids)
    candidate_ids.update(row[0] for row in db.query(WizApplicationEndpoint.asset_id).filter(
        WizApplicationEndpoint.integration_id == integration.id,
        WizApplicationEndpoint.is_active.is_(False),
        WizApplicationEndpoint.asset_id.is_not(None),
    ).distinct().all())
    candidate_ids.update(_bootstrap_legacy_vm_links(db, integration, stats))
    stale_links = db.query(WizAssetLink).filter(
        WizAssetLink.integration_id == integration.id,
        WizAssetLink.is_active.is_(True),
        WizAssetLink.last_seen < started_at,
    ).all()
    for link in stale_links:
        link.is_active = False
        candidate_ids.add(link.asset_id)
    stats.vm_links_removed = len(stale_links)
    db.flush()
    stats.assets_retired = reconcile_asset_membership(
        db, DISCOVERY_SOURCE, integration.organization_id, candidate_ids,
    )
    db.commit()


async def sync_integration(db: Session, integration: WizIntegration) -> Dict[str, Any]:
    stats = _Stats()
    started_at = datetime.utcnow()
    try:
        client = _client_for(integration)
        await _sync_virtual_machines(db, integration, client, stats, started_at)
        stale_endpoint_assets = await _sync_application_endpoints(
            db, integration, client, stats, started_at,
        )
        _reconcile_wiz_assets(db, integration, stats, started_at, stale_endpoint_assets or set())
        stats.assets_complete = True
        integration.last_sync_stats = {
            **stats.as_dict(), "sync_in_progress": True,
            "sync_started_at": (integration.last_sync_stats or {}).get("sync_started_at") or started_at.isoformat(),
        }
        db.commit()

        if integration.import_vulnerabilities:
            finding_filter: Dict[str, Any] = {
                "assetType": ["VIRTUAL_MACHINE"], "hasRelatedIssue": True,
            }
            if integration.internet_exposed_only:
                finding_filter["isAssetAccessibleFromInternet"] = True
            else:
                stats.findings_scope = "related_issues_on_virtual_machines"
            asset_cache: Dict[str, Asset] = {
                str(wiz_id): asset for wiz_id, asset in db.query(WizAssetLink.wiz_id, Asset).join(
                    Asset, WizAssetLink.asset_id == Asset.id,
                ).filter(
                    WizAssetLink.integration_id == integration.id,
                    WizAssetLink.is_active.is_(True),
                    WizAssetLink.last_seen >= started_at,
                ).all()
            } if integration.import_assets else {}
            existing_finding_stamps = {
                (asset_id, template_id): (metadata or {}).get("wiz_updated_at")
                for asset_id, template_id, metadata in db.query(
                    Vulnerability.asset_id, Vulnerability.template_id, Vulnerability.metadata_,
                ).join(Asset, Vulnerability.asset_id == Asset.id).filter(
                    Asset.organization_id == integration.organization_id,
                    Vulnerability.detected_by == DISCOVERY_SOURCE,
                    Vulnerability.template_id.is_not(None),
                ).all()
            }
            async for findings in client.iter_vulnerability_findings(filter_by=finding_filter):
                stats.findings_seen += len(findings)
                for finding in findings:
                    source = finding.get("vulnerableAsset") or {}
                    if not isinstance(source, dict) or not _is_virtual_machine(source):
                        stats.findings_filtered += 1
                        continue
                    if integration.internet_exposed_only and not _is_internet_exposed(source):
                        stats.findings_filtered += 1
                        continue
                    asset = asset_cache.get(str(source.get("id") or ""))
                    if asset is None and not integration.import_assets:
                        value = _asset_value(source)
                        if value:
                            asset = db.query(Asset).filter(
                                Asset.organization_id == integration.organization_id,
                                Asset.value == value,
                            ).first()
                    if asset is None:
                        stats.findings_filtered += 1
                        continue
                    finding_id = str(finding.get("id") or "").strip()
                    updated_at = finding.get("updatedAt")
                    if finding_id and updated_at and existing_finding_stamps.get(
                        (asset.id, f"wiz:{finding_id}"[:255])
                    ) == updated_at:
                        stats.findings_unchanged += 1
                        continue
                    _upsert_vulnerability(db, asset, finding, stats)
                db.commit()
            stats.findings_total_count = client.vulnerability_findings_total_count
            stats.findings_truncated = client.findings_truncated
            if stats.findings_truncated:
                raise WizApiError("Wiz vulnerability findings feed did not complete.")
        else:
            stats.findings_scope = "disabled"
        stats.findings_complete = True

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        return {
            "ok": True,
            "message": (
                f"Imported {stats.endpoints_seen} application endpoint(s), "
                f"{stats.assets_created} new asset(s), and "
                f"{stats.vulns_created} new vulnerability finding(s) from Wiz."
            ),
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Wiz sync failed for organization %s", integration.organization_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        integration.last_sync_stats = {**stats.as_dict(), "sync_in_progress": False}
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}


def claim_sync(db: Session, integration_id: int) -> bool:
    """Claim a Wiz run across API and scheduler processes using a locked row."""
    integration = db.query(WizIntegration).filter(
        WizIntegration.id == integration_id
    ).populate_existing().with_for_update().one()
    if not integration.is_active:
        db.rollback()
        return False
    state = integration.last_sync_stats or {}
    if state.get("sync_in_progress"):
        try:
            started = datetime.fromisoformat(state.get("sync_started_at", ""))
            if datetime.utcnow() - started < timedelta(hours=2):
                db.rollback()
                return False
        except (TypeError, ValueError):
            pass
    integration.last_sync_stats = {
        **state, "sync_in_progress": True,
        "sync_started_at": datetime.utcnow().isoformat(),
    }
    db.commit()
    return True


async def sync_integration_background(integration_id: int) -> None:
    """Run a long endpoint import after the HTTP response has been sent."""
    with SessionLocal() as db:
        integration = db.query(WizIntegration).filter_by(id=integration_id).first()
        if integration is not None:
            result = await sync_integration(db, integration)
            if result["ok"] or result.get("assets_complete"):
                from app.services.integration_graph_service import project_and_record_graph
                await asyncio.to_thread(
                    project_and_record_graph, integration.organization_id, "wiz", integration.id
                )
