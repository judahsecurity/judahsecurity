"""Read-only CrowdStrike Falcon Exposure Management importer.

The public Falcon API has no endpoint for the attack-path graph shown in the
Exposure Management console, so this module rebuilds internet-facing paths
from the pieces the API does expose:

    external asset (FEM)  ->  exposed service/port  ->  Falcon host (aid)
        ->  Spotlight CVE on that host  ->  host prevention-policy posture

* ``/fem/queries/external-assets/v2`` + ``/fem/entities/external-assets/v1``
  give the internet-facing IPs / domains and their services.
* ``/spotlight/combined/vulnerabilities/v1`` gives CVEs (ExPRT, CISA KEV) on
  hosts linked to those assets or flagged ``internet_exposure:'Yes'``.
* ``/devices/entities/devices/v2`` + ``/policy/entities/prevention/v1`` tell us
  whether the sensor on each host is actually *blocking* (prevent mode) or
  only detecting — the real compensating control for the path.

Every imported finding carries the host/port it claims is exposed so the
existing ``POST /vulnerabilities/{id}/validate`` flow can re-probe it from
the internet.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.crowdstrike_integration import FALCON_CLOUDS, CrowdStrikeIntegration
from app.models.port_service import PortService, PortState, Protocol
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "crowdstrike"
TEMPLATE_PREFIX = "crowdstrike:"
ID_BATCH = 100
FEM_PAGE = 100
SPOTLIGHT_PAGE = 400
MAX_PAGES = 250
OPEN_VULN_FILTER = "status:['open','reopen']"
SPOTLIGHT_FACETS = ["cve", "host_info", "remediation"]

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
    "unknown": Severity.MEDIUM,
}
_NEGATIVE = {"no", "false", "0", "not_exposed", "none"}
_DISABLED_LEVELS = {"", "disabled", "off", "none"}
# Toggle names/ids that mean the sensor will stop (not just report) activity.
_BLOCKING_TOGGLE_RE = re.compile(r"prevent|block|quarantine|kill|protect|enforce", re.I)
_DETECT_ONLY_TOGGLE_RE = re.compile(r"detect|visibility|notify|telemetry|log", re.I)

PROTECTION_MODES = ("prevent", "detect_only", "disabled", "degraded", "unknown")


class FalconApiError(RuntimeError):
    """A safe, user-displayable Falcon API error."""


class FalconScopeError(FalconApiError):
    """The API client is missing a scope for an endpoint."""


def base_url_for(cloud: str) -> str:
    try:
        return FALCON_CLOUDS[(cloud or "").strip().lower()]
    except KeyError as exc:
        raise FalconApiError(
            f"Unknown Falcon cloud '{cloud}'. Use one of: {', '.join(FALCON_CLOUDS)}."
        ) from exc


def _chunks(items: List[str], size: int = ID_BATCH) -> Iterable[List[str]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _fql_list(values: Iterable[str]) -> str:
    cleaned = [re.sub(r"[^A-Za-z0-9_-]", "", str(v)) for v in values]
    return "[" + ",".join(f"'{v}'" for v in cleaned if v) + "]"


class FalconClient:
    """Minimal OAuth2 client for the Falcon endpoints this importer reads."""

    def __init__(
        self,
        cloud: str,
        client_id: str,
        client_secret: str,
        *,
        member_cid: Optional[str] = None,
    ) -> None:
        self.base_url = base_url_for(cloud)
        self.client_id = client_id
        self.client_secret = client_secret
        self.member_cid = (member_cid or "").strip() or None
        self._token: Optional[str] = None

    async def authenticate(self) -> str:
        data = {"client_id": self.client_id, "client_secret": self.client_secret}
        if self.member_cid:
            data["member_cid"] = self.member_cid
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/oauth2/token",
                    data=data,
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            raise FalconApiError(f"Could not reach the Falcon API: {exc}") from exc
        if response.status_code not in (200, 201):
            raise FalconApiError(
                f"Falcon authentication failed (HTTP {response.status_code}); "
                "check the client ID/secret and cloud region."
            )
        try:
            token = response.json().get("access_token")
        except ValueError as exc:
            raise FalconApiError("Falcon authentication returned invalid JSON.") from exc
        if not token:
            raise FalconApiError("Falcon authentication response did not contain an access token.")
        self._token = str(token)
        return self._token

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        token = self._token or await self.authenticate()
        reauthed = False
        for attempt in range(4):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.get(
                        f"{self.base_url}{path}",
                        params=params,
                        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    )
            except httpx.HTTPError as exc:
                if attempt == 3:
                    raise FalconApiError(f"Could not reach the Falcon API: {exc}") from exc
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code == 401 and not reauthed:
                reauthed = True
                token = await self.authenticate()
                continue
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                retry_after = response.headers.get("X-Ratelimit-Retryafter")
                delay = 2**attempt
                if retry_after and retry_after.isdigit():
                    delay = max(1, min(30, int(retry_after) - int(datetime.now(timezone.utc).timestamp())))
                await asyncio.sleep(delay)
                continue
            if response.status_code == 403:
                raise FalconScopeError(
                    f"Falcon denied {path} (HTTP 403); the API client is missing the required read scope."
                )
            if response.status_code == 404:
                # Entity lookups return 404 when none of the IDs exist.
                try:
                    return response.json() or {}
                except ValueError:
                    return {}
            if response.status_code != 200:
                raise FalconApiError(f"Falcon request to {path} failed (HTTP {response.status_code}).")
            try:
                return response.json() or {}
            except ValueError as exc:
                raise FalconApiError(f"Falcon returned invalid JSON for {path}.") from exc
        raise FalconApiError(f"Falcon request to {path} failed after retries.")

    # Exposure Management ----------------------------------------------------

    async def query_external_asset_ids(
        self, fql: Optional[str] = None, *, limit: Optional[int] = None
    ) -> List[str]:
        ids: List[str] = []
        offset = 0
        for _ in range(MAX_PAGES):
            params: Dict[str, Any] = {"limit": min(FEM_PAGE, limit or FEM_PAGE), "offset": offset}
            if fql:
                params["filter"] = fql
            payload = await self.get("/fem/queries/external-assets/v2", params)
            batch = [str(i) for i in payload.get("resources") or [] if i]
            ids.extend(batch)
            if limit and len(ids) >= limit:
                return ids[:limit]
            total = ((payload.get("meta") or {}).get("pagination") or {}).get("total")
            offset += len(batch)
            if not batch or (isinstance(total, int) and offset >= total):
                break
        return ids

    async def get_external_assets(self, ids: List[str]) -> List[Dict[str, Any]]:
        assets: List[Dict[str, Any]] = []
        for batch in _chunks(ids):
            payload = await self.get("/fem/entities/external-assets/v1", {"ids": batch})
            assets.extend(r for r in payload.get("resources") or [] if isinstance(r, dict))
        return assets

    # Spotlight --------------------------------------------------------------

    async def get_vulnerabilities(
        self, fql: str, *, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        vulns: List[Dict[str, Any]] = []
        after: Optional[str] = None
        for _ in range(MAX_PAGES):
            params: Dict[str, Any] = {
                "filter": fql,
                "limit": min(SPOTLIGHT_PAGE, limit or SPOTLIGHT_PAGE),
                "facet": SPOTLIGHT_FACETS,
            }
            if after:
                params["after"] = after
            payload = await self.get("/spotlight/combined/vulnerabilities/v1", params)
            batch = [r for r in payload.get("resources") or [] if isinstance(r, dict)]
            vulns.extend(batch)
            if limit and len(vulns) >= limit:
                return vulns[:limit]
            after = ((payload.get("meta") or {}).get("pagination") or {}).get("after")
            if not batch or not after:
                break
        return vulns

    # Hosts & prevention policies -------------------------------------------

    async def get_devices(self, aids: List[str]) -> List[Dict[str, Any]]:
        devices: List[Dict[str, Any]] = []
        for batch in _chunks(aids):
            payload = await self.get("/devices/entities/devices/v2", {"ids": batch})
            devices.extend(r for r in payload.get("resources") or [] if isinstance(r, dict))
        return devices

    async def get_prevention_policies(self, ids: List[str]) -> List[Dict[str, Any]]:
        policies: List[Dict[str, Any]] = []
        for batch in _chunks(ids):
            payload = await self.get("/policy/entities/prevention/v1", {"ids": batch})
            policies.extend(r for r in payload.get("resources") or [] if isinstance(r, dict))
        return policies


def _client_for(integration: CrowdStrikeIntegration) -> FalconClient:
    client_id = integration.get_client_id()
    client_secret = integration.get_client_secret()
    if not client_id or not client_secret:
        raise FalconApiError("No Falcon API credentials are stored for this connection.")
    return FalconClient(
        integration.cloud, client_id, client_secret, member_cid=integration.member_cid
    )


async def test_connection(
    cloud: str,
    client_id: str,
    client_secret: str,
    *,
    member_cid: Optional[str] = None,
) -> Dict[str, Any]:
    """Authenticate and probe each read scope the importer uses."""
    try:
        client = FalconClient(cloud, client_id, client_secret, member_cid=member_cid)
        await client.authenticate()
    except FalconApiError as exc:
        return {"ok": False, "message": str(exc), "scopes": {}}

    probes = {
        "exposure_management": ("/fem/queries/external-assets/v2", {"limit": 1}),
        "vulnerabilities": (
            "/spotlight/combined/vulnerabilities/v1",
            {"filter": OPEN_VULN_FILTER, "limit": 1},
        ),
        "hosts": ("/devices/queries/devices/v1", {"limit": 1}),
        "prevention_policies": ("/policy/queries/prevention/v1", {"limit": 1}),
    }
    scopes: Dict[str, bool] = {}
    errors: List[str] = []
    for scope, (path, params) in probes.items():
        try:
            await client.get(path, params)
            scopes[scope] = True
        except FalconScopeError:
            scopes[scope] = False
        except FalconApiError as exc:
            scopes[scope] = False
            errors.append(str(exc))
    if not scopes.get("exposure_management"):
        return {
            "ok": False,
            "message": errors[0] if errors else (
                "Connected, but the API client lacks the 'Exposure Management: Read' scope."
            ),
            "scopes": scopes,
        }
    missing = [name for name, ok in scopes.items() if not ok]
    message = "Connected to Falcon and verified Exposure Management access."
    if missing:
        message += f" Missing read scope(s): {', '.join(missing)} — those parts of the import will be skipped."
    return {"ok": True, "message": message, "scopes": scopes}


# ── Normalization helpers ────────────────────────────────────────────────────


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


def _map_severity(value: Any) -> Severity:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), Severity.MEDIUM)


def _is_public_ip(value: Optional[str]) -> bool:
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return ip.is_global


def external_asset_identity(asset: Dict[str, Any]) -> Optional[Tuple[str, AssetType]]:
    """Return the Judah asset value/type for a FEM external asset."""
    ip_block = asset.get("ip") if isinstance(asset.get("ip"), dict) else {}
    dns_block = asset.get("dns_domain") if isinstance(asset.get("dns_domain"), dict) else {}
    kind = str(asset.get("asset_type") or "").lower()
    fqdn = str(dns_block.get("fqdn") or "").strip().rstrip(".").lower()
    address = str(ip_block.get("ip_address") or "").strip()
    if (kind.startswith("dns") or not address) and fqdn:
        parent = str(dns_block.get("parent_domain") or "").strip().rstrip(".").lower()
        return fqdn, (AssetType.DOMAIN if parent in ("", fqdn) else AssetType.SUBDOMAIN)
    if address:
        return address, AssetType.IP_ADDRESS
    return None


def external_asset_services(asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    block = asset.get("ip") if isinstance(asset.get("ip"), dict) else None
    if not block or not block.get("services"):
        block = asset.get("dns_domain") if isinstance(asset.get("dns_domain"), dict) else {}
    return [s for s in (block or {}).get("services") or [] if isinstance(s, dict)]


def external_asset_aid(asset: Dict[str, Any]) -> Optional[str]:
    ip_block = asset.get("ip") if isinstance(asset.get("ip"), dict) else {}
    aid = ip_block.get("aid") or asset.get("aid")
    return str(aid).strip() if aid else None


def is_external_asset_exposed(asset: Dict[str, Any]) -> bool:
    """FEM assets are discovered from the internet; honour an explicit 'No'."""
    exposure = str(asset.get("internet_exposure") or "").strip().lower()
    if exposure in _NEGATIVE:
        return False
    return str(asset.get("connectivity_status") or "").strip().lower() not in {"inactive", "offline"}


def _service_port(service: Dict[str, Any]) -> Optional[Tuple[int, Protocol]]:
    try:
        number = int(service.get("port"))
    except (TypeError, ValueError):
        return None
    if not 1 <= number <= 65535:
        return None
    transport = str(service.get("transport") or "tcp").strip().lower()
    protocol = {"udp": Protocol.UDP, "sctp": Protocol.SCTP}.get(transport, Protocol.TCP)
    return number, protocol


def _service_product(service: Dict[str, Any]) -> Optional[Dict[str, Optional[str]]]:
    for app in service.get("applications") or []:
        if isinstance(app, dict) and app.get("name"):
            return {
                "vendor": app.get("vendor"),
                "name": app.get("name"),
                "version": app.get("version"),
                "cpe": app.get("cpe"),
            }
    return None


# ── Prevention-policy posture ────────────────────────────────────────────────


def classify_prevention_policy(policy: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Decide whether a Falcon prevention policy blocks or only detects.

    Machine-learning sliders carry separate ``detection`` and ``prevention``
    levels; toggles carry ``enabled``. A policy is in *prevent* mode when it is
    enabled and at least one ML prevention level or blocking toggle is on.
    """
    if not policy:
        return {"mode": "unknown", "reason": "No prevention policy data returned by Falcon."}
    ml_prevention: Dict[str, str] = {}
    ml_detection: Dict[str, str] = {}
    blocking: List[str] = []
    blocking_off: List[str] = []
    detect_toggles: List[str] = []
    for category in policy.get("prevention_settings") or []:
        if not isinstance(category, dict):
            continue
        for setting in category.get("settings") or []:
            if not isinstance(setting, dict):
                continue
            value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
            label = str(setting.get("name") or setting.get("id") or "setting")
            key = f"{setting.get('id') or ''} {setting.get('name') or ''}"
            if "prevention" in value or "detection" in value:
                ml_prevention[label] = str(value.get("prevention") or "DISABLED").upper()
                ml_detection[label] = str(value.get("detection") or "DISABLED").upper()
            elif "enabled" in value:
                if _BLOCKING_TOGGLE_RE.search(key) and not _DETECT_ONLY_TOGGLE_RE.search(key):
                    (blocking if value.get("enabled") else blocking_off).append(label)
                elif value.get("enabled"):
                    detect_toggles.append(label)

    prevent_levels = {k: v for k, v in ml_prevention.items() if v.lower() not in _DISABLED_LEVELS}
    detect_levels = {k: v for k, v in ml_detection.items() if v.lower() not in _DISABLED_LEVELS}
    summary = {
        "policy_id": policy.get("id"),
        "policy_name": policy.get("name"),
        "platform": policy.get("platform_name"),
        "policy_enabled": bool(policy.get("enabled")),
        "ml_prevention_levels": ml_prevention,
        "ml_detection_levels": ml_detection,
        "blocking_controls_enabled": sorted(blocking),
        "blocking_controls_disabled": sorted(blocking_off),
    }
    if not policy.get("enabled"):
        return {**summary, "mode": "disabled", "reason": "Prevention policy is disabled."}
    if prevent_levels or blocking:
        reasons = [f"{k} prevention {v}" for k, v in sorted(prevent_levels.items())]
        reasons += [f"{name} on" for name in sorted(blocking)[:5]]
        return {**summary, "mode": "prevent", "reason": "; ".join(reasons)[:500]}
    if detect_levels or detect_toggles:
        return {
            **summary,
            "mode": "detect_only",
            "reason": "ML detection is on but every prevention level and blocking control is off.",
        }
    if ml_prevention or blocking_off:
        return {**summary, "mode": "disabled", "reason": "All detection and prevention settings are off."}
    return {**summary, "mode": "unknown", "reason": "Policy returned no prevention settings."}


def host_protection(
    device: Optional[Dict[str, Any]], policies: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Effective mitigation on one Falcon host: policy mode + sensor state."""
    if not device:
        return {"mode": "unknown", "reason": "Host details unavailable (Hosts: Read scope missing or host aged out)."}
    assigned = ((device.get("device_policies") or {}).get("prevention") or {})
    policy_id = assigned.get("policy_id")
    posture = classify_prevention_policy(policies.get(str(policy_id))) if policy_id else {
        "mode": "unknown", "reason": "No prevention policy assigned to this host.",
    }
    result = {
        **posture,
        "aid": device.get("device_id"),
        "hostname": device.get("hostname"),
        "external_ip": device.get("external_ip"),
        "local_ip": device.get("local_ip"),
        "platform": device.get("platform_name"),
        "os_version": device.get("os_version"),
        "agent_version": device.get("agent_version"),
        "last_seen": device.get("last_seen"),
        "containment_status": device.get("status"),
        "reduced_functionality_mode": device.get("reduced_functionality_mode"),
        "policy_applied": assigned.get("applied"),
        "policy_applied_date": assigned.get("applied_date"),
        "policy_id": policy_id,
    }
    if str(device.get("reduced_functionality_mode") or "").lower() == "yes":
        result["mode"] = "degraded"
        result["reason"] = "Sensor is in Reduced Functionality Mode and cannot enforce prevention."
    elif assigned and assigned.get("applied") is False and result["mode"] == "prevent":
        result["reason"] = f"{result.get('reason')}; policy assigned but not yet applied on the sensor"[:500]
        result["policy_pending"] = True
    if str(device.get("status") or "").lower() in {"contained", "containment_pending"}:
        result["contained"] = True
    return result


# ── Persistence ──────────────────────────────────────────────────────────────


class _Stats:
    def __init__(self) -> None:
        self.external_assets_seen = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.ports_created = 0
        self.ports_updated = 0
        self.vulns_seen = 0
        self.vulns_created = 0
        self.vulns_updated = 0
        self.vulns_resolved = 0
        self.vulns_unlinked = 0
        self.hosts_seen = 0
        self.policies_seen = 0
        self.hosts_prevent = 0
        self.hosts_detect_only = 0
        self.hosts_unprotected = 0
        self.exposure_paths = 0
        self.warnings: List[str] = []

    def as_dict(self) -> Dict[str, Any]:
        return vars(self).copy()


def _add_tag(tags: Optional[List[str]], *new: str) -> List[str]:
    out = [t for t in (tags or []) if not str(t).startswith("cs-prevention:")] if any(
        n.startswith("cs-prevention:") for n in new
    ) else list(tags or [])
    for tag in new:
        if tag not in out:
            out.append(tag)
    return out


def _upsert_asset(
    db: Session,
    org_id: int,
    source: Dict[str, Any],
    protection: Optional[Dict[str, Any]],
    stats: _Stats,
    *,
    create: bool,
) -> Optional[Asset]:
    identity = external_asset_identity(source)
    if not identity:
        return None
    value, asset_type = identity
    asset = db.query(Asset).filter(Asset.organization_id == org_id, Asset.value == value).first()
    if asset is None and not create:
        return None
    ip_block = source.get("ip") if isinstance(source.get("ip"), dict) else {}
    dns_block = source.get("dns_domain") if isinstance(source.get("dns_domain"), dict) else {}
    cloud_provider = ip_block.get("cloud_provider") or next(
        (s.get("cloud_provider") for s in external_asset_services(source) if s.get("cloud_provider")), None
    )
    cs_meta = {
        "external_asset_id": source.get("id"),
        "asset_type": source.get("asset_type"),
        "criticality": source.get("criticality"),
        "confidence": source.get("confidence"),
        "connectivity_status": source.get("connectivity_status"),
        "internet_exposure": source.get("internet_exposure"),
        "perimeter": source.get("perimeter"),
        "discovered_by": source.get("discovered_by"),
        "data_providers": source.get("data_providers"),
        "triage": source.get("triage"),
        "subsidiaries": source.get("subsidiaries"),
        "first_seen": source.get("first_seen"),
        "last_seen": source.get("last_seen"),
        "aid": external_asset_aid(source),
        "asn": ip_block.get("asn"),
        "isp": ip_block.get("isp"),
        "fqdns": ip_block.get("fqdns"),
        "resolved_ips": dns_block.get("resolved_ips"),
        "cloud_vm": ip_block.get("cloud_vm"),
        "protection": protection,
    }
    ip_value = value if asset_type == AssetType.IP_ADDRESS else next(
        (ip for ip in dns_block.get("resolved_ips") or [] if _is_public_ip(ip)), None
    )
    tags = ["source:crowdstrike"]
    if protection:
        tags.append(f"cs-prevention:{protection.get('mode', 'unknown')}")
    if asset is None:
        asset = Asset(
            name=value[:255],
            asset_type=asset_type,
            value=value[:500],
            organization_id=org_id,
            status=AssetStatus.DISCOVERED,
            discovery_source=DISCOVERY_SOURCE,
            association_reason="External asset attributed to the organization by CrowdStrike Falcon Exposure Management",
            association_confidence=90,
            tags=tags,
            metadata_={"crowdstrike": cs_meta},
            ip_address=ip_value,
            ip_addresses=[ip_value] if ip_value else [],
            hosting_provider=(str(cloud_provider).lower()[:100] if cloud_provider else None),
            hosting_type="cloud" if cloud_provider else None,
            is_public=True,
        )
        db.add(asset)
        db.flush()
        stats.assets_created += 1
        return asset
    metadata = dict(asset.metadata_ or {})
    metadata["crowdstrike"] = cs_meta
    asset.metadata_ = metadata
    asset.last_seen = datetime.utcnow()
    asset.is_public = True
    if ip_value and not asset.ip_address:
        asset.ip_address = ip_value
    if cloud_provider and not asset.hosting_provider:
        asset.hosting_provider = str(cloud_provider).lower()[:100]
    asset.tags = _add_tag(asset.tags, *tags)
    stats.assets_updated += 1
    return asset


def _upsert_port(db: Session, asset: Asset, service: Dict[str, Any], stats: _Stats) -> Optional[PortService]:
    key = _service_port(service)
    if key is None:
        return None
    number, protocol = key
    product = _service_product(service) or {}
    port = db.query(PortService).filter(
        PortService.asset_id == asset.id,
        PortService.port == number,
        PortService.protocol == protocol,
    ).first()
    service_name = str(service.get("protocol") or service.get("platform_name") or "").strip().lower() or None
    meta = {
        "crowdstrike": {
            "service_id": service.get("id"),
            "status": service.get("status"),
            "status_code": service.get("status_code"),
            "platform_name": service.get("platform_name"),
            "cpes": service.get("cpes"),
            "applications": service.get("applications"),
            "first_seen": service.get("first_seen"),
            "last_seen": service.get("last_seen"),
        }
    }
    if port is None:
        port = PortService(
            asset_id=asset.id,
            port=number,
            protocol=protocol,
            service_name=service_name[:100] if service_name else None,
            service_product=(str(product.get("name"))[:255] if product.get("name") else None),
            service_version=(str(product.get("version"))[:100] if product.get("version") else None),
            cpe=(str(product.get("cpe"))[:255] if product.get("cpe") else None),
            state=PortState.OPEN,
            discovered_by=DISCOVERY_SOURCE,
            scanned_ip=asset.ip_address,
            first_seen=_parse_datetime(service.get("first_seen")) or datetime.utcnow(),
            last_seen=_parse_datetime(service.get("last_seen")) or datetime.utcnow(),
            is_ssl=service_name in {"https", "tls", "ssl"} or number in (443, 8443),
            tags=["source:crowdstrike"],
            metadata_=meta,
        )
        db.add(port)
        db.flush()
        stats.ports_created += 1
        return port
    port.last_seen = datetime.utcnow()
    if service_name and not port.service_name:
        port.service_name = service_name[:100]
    if product.get("name") and not port.service_product:
        port.service_product = str(product["name"])[:255]
    if product.get("version") and not port.service_version:
        port.service_version = str(product["version"])[:100]
    merged = dict(port.metadata_ or {})
    merged.update(meta)
    port.metadata_ = merged
    port.tags = _add_tag(port.tags, "source:crowdstrike")
    stats.ports_updated += 1
    return port


def _exposure_path(
    asset: Asset, services: List[Dict[str, Any]], vuln: Dict[str, Any], protection: Dict[str, Any]
) -> Dict[str, Any]:
    cve = vuln.get("cve") or {}
    exposed = []
    for service in services:
        key = _service_port(service)
        if key:
            exposed.append({
                "port": key[0],
                "transport": key[1].value,
                "protocol": service.get("protocol"),
                "product": _service_product(service),
            })
    host = vuln.get("host_info") or {}
    return {
        "external_asset": asset.value,
        "exposed_services": exposed,
        "host": {
            "aid": vuln.get("aid"),
            "hostname": host.get("hostname"),
            "local_ip": host.get("local_ip"),
            "asset_criticality": host.get("asset_criticality"),
            "internet_exposure": host.get("internet_exposure"),
        },
        "cve": cve.get("id"),
        "exprt_rating": cve.get("exprt_rating"),
        "is_cisa_kev": cve.get("is_cisa_kev"),
        "protection_mode": protection.get("mode"),
    }


def _upsert_vulnerability(
    db: Session,
    asset: Asset,
    services: List[Dict[str, Any]],
    vuln: Dict[str, Any],
    protection: Dict[str, Any],
    stats: _Stats,
) -> str:
    vuln_id = str(vuln.get("id") or "").strip()
    template_id = f"{TEMPLATE_PREFIX}{vuln_id}"[:255]
    cve = vuln.get("cve") or {}
    host = vuln.get("host_info") or {}
    apps = [a for a in vuln.get("apps") or [] if isinstance(a, dict)]
    product = next((a.get("product_name_version") for a in apps if a.get("product_name_version")), None)
    remediation = [
        r for r in ((vuln.get("remediation") or {}).get("entities") or []) if isinstance(r, dict)
    ]
    path = _exposure_path(asset, services, vuln, protection)
    first_port = path["exposed_services"][0] if path["exposed_services"] else None
    cve_id = str(cve.get("id") or "").upper() or None
    title = f"{cve_id or 'Vulnerability'} on internet-facing host {host.get('hostname') or vuln.get('aid')}"
    if product:
        title = f"{cve_id or 'Vulnerability'} in {product} ({host.get('hostname') or vuln.get('aid')})"
    description_parts = [
        cve.get("description") or "",
        f"\n\nExposure path: {asset.value}"
        + (f" :{first_port['port']}/{first_port['transport']}" if first_port else "")
        + f" -> Falcon host {host.get('hostname') or vuln.get('aid')} -> {cve_id}.",
        f"\nCrowdStrike prevention posture: {protection.get('mode')} — {protection.get('reason') or ''}",
    ]
    try:
        cvss = float(cve.get("base_score")) if cve.get("base_score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    references = [str(r) for r in (cve.get("references") or []) if r][:20]
    metadata = {
        "source": DISCOVERY_SOURCE,
        "source_kind": "network_service",
        "spotlight_id": vuln_id,
        "aid": vuln.get("aid"),
        "hostname": host.get("hostname"),
        "exprt_rating": cve.get("exprt_rating"),
        "is_cisa_kev": cve.get("is_cisa_kev"),
        "exploit_status": cve.get("exploit_status"),
        "remediation_level": cve.get("remediation_level"),
        "crowdstrike_status": vuln.get("status"),
        "host_asset_criticality": host.get("asset_criticality"),
        "host_internet_exposure": host.get("internet_exposure"),
        "exposure_path": path,
        "crowdstrike_protection": protection,
        "compensating_controls": [{
            "control": "crowdstrike_falcon_prevention",
            "mode": protection.get("mode"),
            "reason": protection.get("reason"),
            "policy": protection.get("policy_name"),
        }],
        # Fields the revalidation flow reads to re-probe the exposure.
        "host": asset.ip_address or asset.value,
        "scanned_ip": asset.ip_address,
        "port": first_port["port"] if first_port else None,
        "protocol": first_port["transport"] if first_port else None,
    }
    tags = ["source:crowdstrike", f"cs-prevention:{protection.get('mode', 'unknown')}"]
    if cve.get("is_cisa_kev"):
        tags.append("cisa-kev")
    remediation_text = "\n".join(
        f"- {r.get('title') or r.get('action')}" + (f" ({r.get('link')})" if r.get("link") else "")
        for r in remediation[:10]
    ) or None
    existing = db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset.id,
        Vulnerability.detected_by == DISCOVERY_SOURCE,
        Vulnerability.template_id == template_id,
    ).first()
    fields = dict(
        title=title[:500],
        description="".join(description_parts).strip(),
        severity=_map_severity(cve.get("severity")),
        cvss_score=cvss,
        cve_id=cve_id,
        references=references,
        remediation=remediation_text,
        affected_component=(str(product)[:500] if product else None),
        last_detected=_parse_datetime(vuln.get("updated_timestamp")) or datetime.utcnow(),
        metadata_=metadata,
    )
    if existing:
        for key, value in fields.items():
            setattr(existing, key, value)
        existing.tags = _add_tag(existing.tags, *tags)
        if existing.status == VulnerabilityStatus.RESOLVED:
            existing.status = VulnerabilityStatus.OPEN
            existing.resolved_at = None
        stats.vulns_updated += 1
        return template_id
    db.add(Vulnerability(
        **fields,
        asset_id=asset.id,
        detected_by=DISCOVERY_SOURCE,
        template_id=template_id,
        status=VulnerabilityStatus.OPEN,
        first_detected=_parse_datetime(vuln.get("created_timestamp")) or datetime.utcnow(),
        tags=tags,
    ))
    stats.vulns_created += 1
    return template_id


def _resolve_missing(db: Session, org_id: int, seen: set, stats: _Stats) -> None:
    """Close imported findings CrowdStrike no longer reports as open."""
    stale = (
        db.query(Vulnerability)
        .join(Asset, Asset.id == Vulnerability.asset_id)
        .filter(
            Asset.organization_id == org_id,
            Vulnerability.detected_by == DISCOVERY_SOURCE,
            Vulnerability.status == VulnerabilityStatus.OPEN,
        )
        .all()
    )
    now = datetime.utcnow()
    for vuln in stale:
        if (vuln.asset_id, vuln.template_id) not in seen:
            vuln.status = VulnerabilityStatus.RESOLVED
            vuln.resolved_at = now
            stats.vulns_resolved += 1


async def sync_integration(db: Session, integration: CrowdStrikeIntegration) -> Dict[str, Any]:
    stats = _Stats()
    org_id = integration.organization_id
    try:
        client = _client_for(integration)

        # 1) Internet-facing external assets from Exposure Management.
        ids = await client.query_external_asset_ids((integration.asset_filter or "").strip() or None)
        external = await client.get_external_assets(ids)
        stats.external_assets_seen = len(external)
        if integration.internet_exposed_only:
            external = [a for a in external if is_external_asset_exposed(a)]

        by_aid: Dict[str, List[Dict[str, Any]]] = {}
        by_ip: Dict[str, Dict[str, Any]] = {}
        for item in external:
            aid = external_asset_aid(item)
            if aid:
                by_aid.setdefault(aid, []).append(item)
            identity = external_asset_identity(item)
            if identity and identity[1] == AssetType.IP_ADDRESS:
                by_ip[identity[0]] = item

        # 2) Open CVEs on hosts behind those assets or that Falcon flags as internet exposed.
        vulns: Dict[str, Dict[str, Any]] = {}
        if integration.import_vulnerabilities:
            queries = [f"{OPEN_VULN_FILTER}+aid:{_fql_list(batch)}" for batch in _chunks(sorted(by_aid))]
            queries.append(f"{OPEN_VULN_FILTER}+host_info.internet_exposure:'Yes'")
            for fql in queries:
                try:
                    for item in await client.get_vulnerabilities(fql):
                        if item.get("id"):
                            vulns[str(item["id"])] = item
                except FalconScopeError as exc:
                    stats.warnings.append(str(exc))
                    break
            stats.vulns_seen = len(vulns)

        # 3) Host details + prevention policies => real mitigation posture.
        aids = sorted(set(by_aid) | {str(v.get("aid")) for v in vulns.values() if v.get("aid")})
        devices: Dict[str, Dict[str, Any]] = {}
        policies: Dict[str, Dict[str, Any]] = {}
        if aids:
            try:
                devices = {str(d.get("device_id")): d for d in await client.get_devices(aids) if d.get("device_id")}
            except FalconScopeError as exc:
                stats.warnings.append(str(exc))
        stats.hosts_seen = len(devices)
        if integration.import_policies and devices:
            policy_ids = sorted({
                str(((d.get("device_policies") or {}).get("prevention") or {}).get("policy_id"))
                for d in devices.values()
                if ((d.get("device_policies") or {}).get("prevention") or {}).get("policy_id")
            })
            try:
                policies = {str(p.get("id")): p for p in await client.get_prevention_policies(policy_ids) if p.get("id")}
            except FalconScopeError as exc:
                stats.warnings.append(str(exc))
        stats.policies_seen = len(policies)

        protection_by_aid: Dict[str, Dict[str, Any]] = {}
        for aid in aids:
            if integration.import_policies:
                protection_by_aid[aid] = host_protection(devices.get(aid), policies)
            else:
                protection_by_aid[aid] = {"mode": "unknown", "reason": "Policy import disabled for this connection."}
            mode = protection_by_aid[aid]["mode"]
            if mode == "prevent":
                stats.hosts_prevent += 1
            elif mode == "detect_only":
                stats.hosts_detect_only += 1
            else:
                stats.hosts_unprotected += 1

        # Link hosts to external assets by sensor external IP when FEM has no aid.
        for aid, device in devices.items():
            ext_ip = str(device.get("external_ip") or "").strip()
            if aid not in by_aid and ext_ip in by_ip:
                by_aid[aid] = [by_ip[ext_ip]]

        # 4) Persist assets, services and exposure-path findings.
        asset_rows: Dict[str, Optional[Asset]] = {}
        for item in external:
            aid = external_asset_aid(item)
            asset = _upsert_asset(
                db, org_id, item, protection_by_aid.get(aid) if aid else None, stats,
                create=integration.import_assets,
            )
            asset_rows[str(item.get("id"))] = asset
            if asset is not None:
                for service in external_asset_services(item):
                    _upsert_port(db, asset, service, stats)

        seen: set = set()
        for vuln in vulns.values():
            aid = str(vuln.get("aid") or "")
            linked = by_aid.get(aid) or []
            if not linked:
                stats.vulns_unlinked += 1
                continue
            for item in linked:
                asset = asset_rows.get(str(item.get("id")))
                if asset is None:
                    continue
                template_id = _upsert_vulnerability(
                    db, asset, external_asset_services(item), vuln,
                    protection_by_aid.get(aid) or {"mode": "unknown"}, stats,
                )
                seen.add((asset.id, template_id))
                stats.exposure_paths += 1

        if integration.import_vulnerabilities and not any("spotlight" in w for w in stats.warnings):
            db.flush()
            _resolve_missing(db, org_id, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = "; ".join(stats.warnings)[:1000] or None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        message = (
            f"Imported {stats.assets_created} new external asset(s), {stats.exposure_paths} exposure path(s); "
            f"hosts in prevent mode: {stats.hosts_prevent}, detect-only: {stats.hosts_detect_only}, "
            f"unprotected/unknown: {stats.hosts_unprotected}."
        )
        if stats.warnings:
            message += " Warnings: " + "; ".join(stats.warnings)
        return {"ok": True, "message": message, **stats.as_dict()}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("CrowdStrike sync failed for organization %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {"ok": False, "message": f"Sync failed: {exc}", **stats.as_dict()}
