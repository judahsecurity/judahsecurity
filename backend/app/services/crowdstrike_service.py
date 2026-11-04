"""Read-only CrowdStrike Falcon client and Hosts + Spotlight importer.

Hosts (``Hosts: Read``) become internal inventory assets keyed by the Falcon
agent ID (``aid``). Spotlight (``Vulnerabilities: Read``) findings become
vulnerabilities on those assets, correlated by the same ``aid``.

Everything the graph needs is kept in ``Asset.metadata_["crowdstrike"]`` so
``graph_service`` can model agents, internal IPs, egress IPs and AD placement
without calling Falcon again.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.crowdstrike_integration import CrowdStrikeIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "crowdstrike"
TAG = "source:crowdstrike"

REGION_HOSTS = {
    "us-1": "api.crowdstrike.com",
    "us-2": "api.us-2.crowdstrike.com",
    "eu-1": "api.eu-1.crowdstrike.com",
    "us-gov-1": "api.laggar.gcw.crowdstrike.com",
}

HOSTS_SCROLL_PATH = "/devices/queries/devices-scroll/v1"
HOSTS_DETAILS_PATH = "/devices/entities/devices/v2"
SPOTLIGHT_QUERY_PATH = "/spotlight/queries/vulnerabilities/v1"
SPOTLIGHT_COMBINED_PATH = "/spotlight/combined/vulnerabilities/v1"
SPOTLIGHT_FACETS = ("cve", "host_info", "remediation", "evaluation_logic")

PAGE_SIZE = 5000          # max for devices-scroll, device details and spotlight combined
MAX_PAGES = 400
INCREMENTAL_OVERLAP = timedelta(days=1)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
    "unknown": Severity.MEDIUM,
}
_OPEN_STATUSES = {"open", "reopen"}
_CLOSED_STATUSES = {"closed", "expired"}
# Statuses an analyst set deliberately; Falcon must not reopen or overwrite them.
_ANALYST_STATUSES = {
    VulnerabilityStatus.ACCEPTED,
    VulnerabilityStatus.FALSE_POSITIVE,
    VulnerabilityStatus.MITIGATED,
}


class CrowdStrikeApiError(RuntimeError):
    """A safe, user-displayable Falcon API error."""


class CrowdStrikeModuleError(CrowdStrikeApiError):
    """A Falcon module is not licensed, or the API client lacks its scope."""

    def __init__(self, module: str) -> None:
        super().__init__(
            f"The CrowdStrike {module} module is not licensed or not available for this tenant "
            f"(or the API client is missing its read scope)."
        )
        self.module = module


def base_url_for(region: str) -> str:
    host = REGION_HOSTS.get((region or "").strip().lower())
    if not host:
        raise CrowdStrikeApiError(
            f"Unsupported CrowdStrike cloud region {region!r}; expected one of {', '.join(REGION_HOSTS)}."
        )
    return f"https://{host}"


def _iso(dt: datetime) -> str:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class CrowdStrikeClient:
    """Minimal OAuth2 client for the Falcon Hosts and Spotlight APIs."""

    def __init__(self, region: str, client_id: str, client_secret: str) -> None:
        self.base_url = base_url_for(region)
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None

    async def authenticate(self) -> str:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/oauth2/token",
                    data={"client_id": self.client_id, "client_secret": self.client_secret},
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise CrowdStrikeApiError(f"Could not reach the CrowdStrike API: {exc}") from exc
        if response.status_code not in (200, 201):
            raise CrowdStrikeApiError(
                f"CrowdStrike authentication failed (HTTP {response.status_code}); "
                "check the client ID, secret and cloud region."
            )
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise CrowdStrikeApiError("CrowdStrike authentication returned invalid JSON.") from exc
        if not token:
            raise CrowdStrikeApiError("CrowdStrike authentication response had no access token.")
        self._token = str(token)
        return self._token

    async def request(
        self,
        method: str,
        path: str,
        *,
        module: str,
        params: Optional[Sequence[Tuple[str, Any]]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        token = self._token or await self.authenticate()
        reauthed = False
        attempt = 0
        while True:
            try:
                async with httpx.AsyncClient(timeout=90.0) as client:
                    response = await client.request(
                        method,
                        f"{self.base_url}{path}",
                        params=list(params or []),
                        json=json,
                        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    )
            except httpx.HTTPError as exc:
                if attempt >= 3:
                    raise CrowdStrikeApiError(f"Could not reach the CrowdStrike API: {exc}") from exc
                await asyncio.sleep(2**attempt)
                attempt += 1
                continue
            if response.status_code == 401 and not reauthed:
                token = await self.authenticate()
                reauthed = True
                continue
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                retry_after = response.headers.get("X-RateLimit-RetryAfter")
                delay = 2**attempt
                if retry_after and retry_after.isdigit():
                    # Falcon sends an epoch second; wait until then (capped).
                    delay = min(max(int(retry_after) - int(datetime.now(timezone.utc).timestamp()), 1), 30)
                await asyncio.sleep(delay)
                attempt += 1
                continue
            if response.status_code == 403:
                raise CrowdStrikeModuleError(module)
            if response.status_code >= 400:
                raise CrowdStrikeApiError(
                    f"CrowdStrike {module} request failed (HTTP {response.status_code})."
                )
            try:
                return response.json() or {}
            except ValueError as exc:
                raise CrowdStrikeApiError(f"CrowdStrike {module} returned invalid JSON.") from exc

    # ── Hosts ────────────────────────────────────────────────────────────────

    async def list_host_ids(self, *, seen_since: datetime, limit: Optional[int] = None) -> List[str]:
        ids: List[str] = []
        offset: Optional[str] = None
        for _ in range(MAX_PAGES):
            params: List[Tuple[str, Any]] = [
                ("limit", min(PAGE_SIZE, limit or PAGE_SIZE)),
                ("filter", f"last_seen:>='{_iso(seen_since)}'"),
            ]
            if offset:
                params.append(("offset", offset))
            payload = await self.request("GET", HOSTS_SCROLL_PATH, module="Hosts", params=params)
            batch = [str(item) for item in (payload.get("resources") or []) if item]
            ids.extend(batch)
            if limit and len(ids) >= limit:
                return ids[:limit]
            offset = ((payload.get("meta") or {}).get("pagination") or {}).get("offset")
            if not batch or not offset:
                break
        return ids

    async def get_hosts(self, ids: Sequence[str]) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        for start in range(0, len(ids), PAGE_SIZE):
            chunk = list(ids[start:start + PAGE_SIZE])
            payload = await self.request(
                "POST", HOSTS_DETAILS_PATH, module="Hosts", json={"ids": chunk}
            )
            devices.extend(d for d in (payload.get("resources") or []) if isinstance(d, dict))
        return devices

    # ── Spotlight ────────────────────────────────────────────────────────────

    async def get_spotlight_findings(
        self, *, fql_filter: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        after: Optional[str] = None
        for _ in range(MAX_PAGES):
            params: List[Tuple[str, Any]] = [
                ("filter", fql_filter),
                ("limit", min(PAGE_SIZE, limit or PAGE_SIZE)),
                ("sort", "updated_timestamp|asc"),
                *[("facet", facet) for facet in SPOTLIGHT_FACETS],
            ]
            if after:
                params.append(("after", after))
            payload = await self.request(
                "GET", SPOTLIGHT_COMBINED_PATH, module="Spotlight", params=params
            )
            batch = [f for f in (payload.get("resources") or []) if isinstance(f, dict)]
            findings.extend(batch)
            if limit and len(findings) >= limit:
                return findings[:limit]
            after = ((payload.get("meta") or {}).get("pagination") or {}).get("after")
            if not batch or not after:
                break
        return findings


def _client_for(integration: CrowdStrikeIntegration) -> CrowdStrikeClient:
    client_id = integration.get_client_id()
    client_secret = integration.get_client_secret()
    if not client_id or not client_secret:
        raise CrowdStrikeApiError("No CrowdStrike client credentials are stored for this connection.")
    return CrowdStrikeClient(integration.cloud_region, client_id, client_secret)


async def test_connection(
    region: str,
    client_id: str,
    client_secret: str,
    *,
    import_hosts: bool = True,
    import_spotlight: bool = True,
) -> Dict[str, Any]:
    """Validate credentials and access to each enabled module.

    Spotlight findings are correlated to assets by agent ID, so enabling
    Spotlight also requires Hosts access.
    """
    modules: Dict[str, Any] = {}
    try:
        client = CrowdStrikeClient(region, client_id, client_secret)
        await client.authenticate()
    except CrowdStrikeApiError as exc:
        return {"ok": False, "message": str(exc), "modules": modules}

    needs_hosts = import_hosts or import_spotlight
    if needs_hosts:
        try:
            await client.request(
                "GET", HOSTS_SCROLL_PATH, module="Hosts", params=[("limit", 1)]
            )
            modules["hosts"] = {"ok": True}
        except CrowdStrikeApiError as exc:
            modules["hosts"] = {"ok": False, "message": str(exc)}
    if import_spotlight:
        try:
            await client.request(
                "GET",
                SPOTLIGHT_QUERY_PATH,
                module="Spotlight",
                params=[("filter", "status:'open'"), ("limit", 1)],
            )
            modules["spotlight"] = {"ok": True}
        except CrowdStrikeApiError as exc:
            modules["spotlight"] = {"ok": False, "message": str(exc)}

    failures = [m["message"] for m in modules.values() if not m.get("ok")]
    if failures:
        message = " ".join(failures)
        if import_spotlight and not import_hosts and not modules.get("hosts", {}).get("ok"):
            message += " Spotlight needs Hosts: Read to map findings to assets."
        return {"ok": False, "message": message, "modules": modules}
    enabled = ", ".join(sorted(modules)) or "authentication"
    return {"ok": True, "message": f"Connected to CrowdStrike Falcon ({enabled} verified).", "modules": modules}


# ── Normalization helpers ───────────────────────────────────────────────────


def _parse_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _valid_ip(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def is_private_ip(value: Any) -> bool:
    ip = _valid_ip(value)
    return bool(ip) and not ipaddress.ip_address(ip).is_global


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if str(value).strip() else []


def normalize_host(device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Reduce a Falcon device to the fields used for correlation and the graph.

    Returns ``None`` for devices missing a hostname, a valid local IP, or an agent ID.
    """
    aid = str(device.get("device_id") or "").strip()
    hostname = str(device.get("hostname") or "").strip().lower()
    local_ip = _valid_ip(device.get("local_ip"))
    if not (aid and hostname and local_ip):
        return None
    machine_domain = str(device.get("machine_domain") or "").strip().lower() or None
    fqdn = hostname
    if machine_domain and "." not in hostname:
        fqdn = f"{hostname}.{machine_domain}"
    external_ip = _valid_ip(device.get("external_ip"))
    if external_ip and is_private_ip(external_ip):
        external_ip = None  # sensor saw no public egress (e.g., private cloud / proxy)
    return {
        "aid": aid,
        "hostname": hostname,
        "fqdn": fqdn,
        "machine_domain": machine_domain,
        "local_ip": local_ip,
        "external_ip": external_ip,
        "connection_ip": _valid_ip(device.get("connection_ip")),
        "mac_address": (str(device.get("mac_address") or "").lower().replace("-", ":") or None),
        "ou": _as_list(device.get("ou")),
        "site_name": device.get("site_name") or None,
        "platform_name": device.get("platform_name") or None,
        "os_version": device.get("os_version") or None,
        "product_type_desc": device.get("product_type_desc") or None,
        "agent_version": device.get("agent_version") or None,
        "status": device.get("status") or None,
        "first_seen": device.get("first_seen") or None,
        "last_seen": device.get("last_seen") or None,
        "system_manufacturer": device.get("system_manufacturer") or None,
        "system_product_name": device.get("system_product_name") or None,
        "falcon_tags": _as_list(device.get("tags")),
        "groups": _as_list(device.get("groups")),
    }


def _device_class(product_type_desc: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    kind = (product_type_desc or "").strip().lower()
    if kind == "domain controller":
        return "Server", "domain_controller"
    if kind == "server":
        return "Server", "server"
    if kind == "workstation":
        return "Workstation", "workstation"
    return None, (kind or None)


def map_severity(value: Any) -> Severity:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), Severity.MEDIUM)


def _has_network_vector(cve: Dict[str, Any]) -> bool:
    vector = str(cve.get("vector") or "").upper()
    if "AV:N" in vector:
        return True
    return str(cve.get("attack_vector") or "").strip().upper() in {"NETWORK", "N"}


def _is_kev(cve: Dict[str, Any]) -> bool:
    cisa = cve.get("cisa_info") or {}
    return bool(cisa.get("is_cisa_kev")) if isinstance(cisa, dict) else False


def prioritization_reasons(cve: Dict[str, Any], extra_cve_ids: Iterable[str] = ()) -> List[str]:
    """Why a Spotlight CVE is worth importing; empty means filtered out."""
    reasons: List[str] = []
    exprt = str(cve.get("exprt_rating") or "").strip().upper()
    if exprt in {"HIGH", "CRITICAL"} and _has_network_vector(cve):
        reasons.append(f"exprt_{exprt.lower()}_network")
    if _is_kev(cve):
        reasons.append("cisa_kev")
    cve_id = str(cve.get("id") or "").strip().upper()
    if cve_id and cve_id in {str(c).upper() for c in (extra_cve_ids or [])}:
        reasons.append("attack_chain_cve")
    return reasons


def spotlight_filter(last_success: Optional[datetime], now: datetime) -> str:
    """First sync: every open finding. Afterwards: anything updated since the last
    successful pass (minus an overlap), in any status, so closures propagate."""
    if last_success is None:
        return "status:['open','reopen']"
    since = min(last_success, now) - INCREMENTAL_OVERLAP
    return f"updated_timestamp:>'{_iso(since)}'"


def _references(cve: Dict[str, Any]) -> List[str]:
    refs = cve.get("references")
    if isinstance(refs, str):
        refs = [r.strip() for r in refs.split(",")]
    out = [str(r) for r in (refs or []) if str(r).startswith(("http://", "https://"))]
    advisory = cve.get("vendor_advisory")
    for item in _as_list(advisory):
        if item.startswith(("http://", "https://")) and item not in out:
            out.append(item)
    return out[:50]


def _remediation_text(finding: Dict[str, Any]) -> Optional[str]:
    entities = ((finding.get("remediation") or {}).get("entities")) or []
    lines = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        parts = [str(entity.get(k)) for k in ("title", "action") if entity.get(k)]
        if entity.get("link"):
            parts.append(str(entity["link"]))
        if parts:
            lines.append(" — ".join(parts))
    return "\n".join(lines) or None


def _apps(finding: Dict[str, Any]) -> List[str]:
    return [
        str(app.get("product_name_version"))
        for app in (finding.get("apps") or [])
        if isinstance(app, dict) and app.get("product_name_version")
    ]


class _Stats:
    def __init__(self) -> None:
        self.hosts_seen = 0
        self.hosts_skipped = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.findings_seen = 0
        self.findings_filtered = 0
        self.findings_uncorrelated = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.vulns_resolved = 0

    def as_dict(self) -> Dict[str, int]:
        return vars(self).copy()


# ── Asset correlation ───────────────────────────────────────────────────────


def _assets_by_aid(db: Session, org_id: int, aids: Sequence[str]) -> Dict[str, Asset]:
    found: Dict[str, Asset] = {}
    aid_expr = Asset.metadata_["crowdstrike"]["aid"].as_string()
    unique = list(dict.fromkeys(a for a in aids if a))
    for start in range(0, len(unique), 1000):
        chunk = unique[start:start + 1000]
        for asset in db.query(Asset).filter(
            Asset.organization_id == org_id, aid_expr.in_(chunk)
        ).all():
            aid = ((asset.metadata_ or {}).get("crowdstrike") or {}).get("aid")
            if aid:
                found[aid] = asset
    return found


def _claimed_by_other_agent(asset: Asset, aid: str) -> bool:
    existing = ((asset.metadata_ or {}).get("crowdstrike") or {}).get("aid")
    return bool(existing) and existing != aid


def _find_existing(db: Session, org_id: int, host: Dict[str, Any]) -> Optional[Asset]:
    """Fallback matches when no asset carries this agent ID yet:
    FQDN → short hostname → an IP_ADDRESS asset for the local IP."""
    for value in dict.fromkeys([host["fqdn"], host["hostname"]]):
        for asset in db.query(Asset).filter(
            Asset.organization_id == org_id, Asset.value == value
        ).all():
            if not _claimed_by_other_agent(asset, host["aid"]):
                return asset
    for asset in db.query(Asset).filter(
        Asset.organization_id == org_id,
        Asset.asset_type == AssetType.IP_ADDRESS,
        Asset.value == host["local_ip"],
    ).all():
        if not _claimed_by_other_agent(asset, host["aid"]):
            return asset
    return None


def _host_metadata(host: Dict[str, Any], integration_id: int) -> Dict[str, Any]:
    return {**host, "integration_id": integration_id, "synced_at": datetime.utcnow().isoformat()}


def upsert_host_asset(
    db: Session, integration: CrowdStrikeIntegration, host: Dict[str, Any],
    existing: Optional[Asset], stats: _Stats,
) -> Asset:
    device_class, system_type = _device_class(host.get("product_type_desc"))
    os_label = " ".join(p for p in (host.get("platform_name"), host.get("os_version")) if p) or None
    last_seen = _parse_datetime(host.get("last_seen")) or datetime.utcnow()

    if existing is not None:
        metadata = dict(existing.metadata_ or {})
        metadata["crowdstrike"] = _host_metadata(host, integration.id)
        existing.metadata_ = metadata
        existing.last_seen = max(existing.last_seen or last_seen, last_seen)
        existing.is_owned = True
        if os_label:
            existing.operating_system = os_label[:200]
        existing.system_type = existing.system_type or system_type
        existing.device_class = existing.device_class or device_class
        if existing.discovery_source == DISCOVERY_SOURCE:
            # Only assets this integration created are re-classified as internal;
            # an externally discovered asset we merely matched keeps its exposure.
            existing.name = host["hostname"][:255]
            existing.ip_addresses = [host["local_ip"]]  # DHCP churn: Falcon is authoritative
            existing.ip_address = host["local_ip"]
            existing.is_public = False
            existing.hosting_type = "owned"
            existing.is_live = True
        tags = list(existing.tags or [])
        if TAG not in tags:
            tags.append(TAG)
            existing.tags = tags
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=host["hostname"][:255],
        asset_type=AssetType.OTHER,
        value=host["fqdn"][:500],
        organization_id=integration.organization_id,
        status=AssetStatus.VERIFIED,
        discovery_source=DISCOVERY_SOURCE,
        discovery_chain=[{"source": DISCOVERY_SOURCE, "aid": host["aid"]}],
        association_reason="Endpoint managed by the organization's CrowdStrike Falcon tenant",
        association_confidence=95,
        tags=[TAG, "internal"],
        metadata_={"crowdstrike": _host_metadata(host, integration.id)},
        operating_system=os_label[:200] if os_label else None,
        system_type=system_type,
        device_class=device_class,
        ip_addresses=[host["local_ip"]],
        ip_address=host["local_ip"],
        hosting_type="owned",
        is_public=False,
        is_owned=True,
        is_live=True,
        first_seen=_parse_datetime(host.get("first_seen")) or datetime.utcnow(),
        last_seen=last_seen,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


# ── Spotlight → vulnerabilities ─────────────────────────────────────────────


def _template_id(finding_id: str) -> str:
    return f"crowdstrike:{finding_id}"[:255]


def upsert_spotlight_finding(
    db: Session, asset: Asset, finding: Dict[str, Any], reasons: List[str], stats: _Stats,
    existing: Optional[Vulnerability] = None,
) -> Optional[Vulnerability]:
    finding_id = str(finding.get("id") or "").strip()
    cve = finding.get("cve") or {}
    cve_id = str(cve.get("id") or "").strip().upper() or None
    raw_status = str(finding.get("status") or "open").strip().lower()
    closed = raw_status in _CLOSED_STATUSES
    if existing is None and finding_id:
        existing = db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.template_id == _template_id(finding_id),
        ).first()
    if existing is None and closed:
        return None  # never seen open; nothing to resolve

    apps = _apps(finding)
    title = f"{cve_id or 'Spotlight vulnerability'}: {apps[0]}" if apps else (cve_id or "Spotlight vulnerability")
    try:
        cvss = float(cve["base_score"]) if cve.get("base_score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    metadata = {
        "source": DISCOVERY_SOURCE,
        "spotlight_id": finding_id or None,
        "aid": finding.get("aid"),
        "spotlight_status": raw_status,
        "exprt_rating": cve.get("exprt_rating"),
        "exploit_status": cve.get("exploit_status"),
        "cisa_kev": _is_kev(cve),
        "network_attack_vector": _has_network_vector(cve),
        "prioritization_reasons": reasons,
        "apps": apps,
        # Kept verbatim for exploitability validation (what Falcon actually checked).
        "evaluation_logic": finding.get("evaluation_logic"),
        "host_info": {
            k: (finding.get("host_info") or {}).get(k)
            for k in ("hostname", "local_ip", "asset_criticality", "internet_exposure", "managed_by")
        },
    }
    common = {
        "title": title[:500],
        "description": cve.get("description"),
        "severity": map_severity(cve.get("severity")),
        "cvss_score": cvss,
        "cvss_vector": (str(cve.get("vector"))[:100] if cve.get("vector") else None),
        "cve_id": cve_id,
        "references": _references(cve),
        "remediation": _remediation_text(finding),
        "affected_component": (", ".join(apps)[:500] or None),
        "evidence": (
            f"CrowdStrike Spotlight reports {', '.join(apps) or 'a vulnerable component'} "
            f"installed on {asset.name} (agent {finding.get('aid')})."
        ),
        "last_detected": _parse_datetime(finding.get("updated_timestamp")) or datetime.utcnow(),
    }

    if existing is not None:
        for field, value in common.items():
            setattr(existing, field, value)
        existing.metadata_ = {**(existing.metadata_ or {}), **metadata}
        if existing.status in _ANALYST_STATUSES:
            pass
        elif closed:
            if existing.status != VulnerabilityStatus.RESOLVED:
                stats.vulns_resolved += 1
            existing.status = VulnerabilityStatus.RESOLVED
            existing.resolved_at = _parse_datetime(finding.get("closed_timestamp")) or datetime.utcnow()
        elif existing.status == VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.OPEN
            existing.resolved_at = None
        stats.vulns_updated += 1
        return existing

    vuln = Vulnerability(
        **common,
        asset_id=asset.id,
        detected_by=DISCOVERY_SOURCE,
        template_id=_template_id(finding_id) if finding_id else None,
        detection_confidence="high",
        status=VulnerabilityStatus.OPEN,
        first_detected=_parse_datetime(finding.get("created_timestamp")) or datetime.utcnow(),
        tags=[TAG],
        metadata_=metadata,
    )
    db.add(vuln)
    stats.vulns_created += 1
    return vuln


# ── Sync orchestration ──────────────────────────────────────────────────────


async def _sync_hosts(
    db: Session, client: CrowdStrikeClient, integration: CrowdStrikeIntegration, stats: _Stats,
) -> Dict[str, Asset]:
    since = datetime.utcnow() - timedelta(days=integration.host_lookback_days or 7)
    devices = await client.get_hosts(await client.list_host_ids(seen_since=since))
    stats.hosts_seen = len(devices)
    hosts = []
    for device in devices:
        host = normalize_host(device)
        if host is None:
            stats.hosts_skipped += 1
        else:
            hosts.append(host)
    by_aid = _assets_by_aid(db, integration.organization_id, [h["aid"] for h in hosts])
    for host in hosts:
        existing = by_aid.get(host["aid"]) or _find_existing(db, integration.organization_id, host)
        by_aid[host["aid"]] = upsert_host_asset(db, integration, host, existing, stats)
    return by_aid


async def _sync_spotlight(
    db: Session, client: CrowdStrikeClient, integration: CrowdStrikeIntegration,
    by_aid: Dict[str, Asset], stats: _Stats, now: datetime,
) -> List[Asset]:
    findings = await client.get_spotlight_findings(
        fql_filter=spotlight_filter(integration.last_spotlight_sync_at, now)
    )
    stats.findings_seen = len(findings)
    missing = [str(f.get("aid")) for f in findings if f.get("aid") and str(f.get("aid")) not in by_aid]
    if missing:
        by_aid.update(_assets_by_aid(db, integration.organization_id, missing))
    touched: Dict[int, Asset] = {}
    for finding in findings:
        asset = by_aid.get(str(finding.get("aid") or ""))
        if asset is None:
            stats.findings_uncorrelated += 1
            continue
        cve = finding.get("cve") or {}
        reasons = (
            ["all_open"] if integration.spotlight_filter_mode == "all"
            else prioritization_reasons(cve, integration.extra_cve_ids or [])
        )
        existing = None
        if not reasons:
            # A finding we imported earlier may since have been closed or deprioritized;
            # still update it so closures propagate. Otherwise it is filtered out.
            finding_id = str(finding.get("id") or "").strip()
            if finding_id:
                existing = db.query(Vulnerability).filter(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.detected_by == DISCOVERY_SOURCE,
                    Vulnerability.template_id == _template_id(finding_id),
                ).first()
            if existing is None:
                stats.findings_filtered += 1
                continue
        if upsert_spotlight_finding(db, asset, finding, reasons, stats, existing=existing) is not None:
            touched[asset.id] = asset
    return list(touched.values())


def _sync_graph(org_id: int, asset_values: List[str]) -> Optional[int]:
    if not asset_values:
        return 0
    try:
        from app.services.graph_service import sync_organization_background

        result = sync_organization_background(org_id, asset_values=asset_values)
        if result.get("error"):
            logger.info("CrowdStrike graph sync skipped: %s", result["error"])
            return None
        return int(result.get("synced") or 0)
    except Exception:  # noqa: BLE001 — graph is best-effort; Postgres is the source of truth
        logger.warning("CrowdStrike graph sync failed for org %s", org_id, exc_info=True)
        return None


async def sync_integration(db: Session, integration: CrowdStrikeIntegration) -> Dict[str, Any]:
    stats = _Stats()
    started = datetime.utcnow()
    try:
        client = _client_for(integration)
        by_aid: Dict[str, Asset] = {}
        touched: Dict[int, Asset] = {}
        if integration.import_hosts:
            by_aid = await _sync_hosts(db, client, integration, stats)
            touched.update({a.id: a for a in by_aid.values()})
        if integration.import_spotlight:
            for asset in await _sync_spotlight(db, client, integration, by_aid, stats, started):
                touched[asset.id] = asset
            integration.last_spotlight_sync_at = started

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        asset_values = [a.value for a in touched.values()]
        org_id = integration.organization_id
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("CrowdStrike sync failed for organization %s", integration.organization_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}

    graph_synced = await asyncio.to_thread(_sync_graph, org_id, asset_values)
    stats_dict = stats.as_dict()
    return {
        "ok": True,
        "message": (
            f"Mapped {stats.assets_created + stats.assets_updated} CrowdStrike host(s) "
            f"({stats.assets_created} new) and imported {stats.vulns_created} new Spotlight finding(s)."
        ),
        **stats_dict,
        "graph_synced": graph_synced,
    }
