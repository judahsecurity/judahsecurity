"""Select safe web screenshot targets for in-scope ICS/OT assets.

This module does not probe native control protocols.  It turns existing asset
and port-service evidence into HTTP(S) URLs that the normal screenshot service
can capture without authentication or form submission.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session, selectinload

from app.models.asset import Asset, AssetType
from app.models.port_service import PortState


DEFAULT_ICS_WEB_PORTS = frozenset({80, 443, 8000, 8080, 8088, 8443, 8888, 10000})
TLS_WEB_PORTS = frozenset({443, 8443})
HTTP_SERVICE_MARKERS = ("http", "https", "ssl/http", "http-proxy")
ICS_TOKEN_PATTERN = re.compile(r"\b(?:ics|ot|plc|scada|hmi)\b")
ICS_PRODUCT_MARKERS = (
    "industrial",
    "c-more",
    "cmore",
    "red lion",
    "crimson",
    "ignition",
    "codesys",
    "wincc",
    "niagara",
    "bacnet",
    "modbus",
    "opc ua",
    "opc_ua",
    "rockwell",
    "allen-bradley",
    "schneider",
    "siemens",
    "mitsubishi",
    "omron",
    "historian",
)


def _text_has_ics_marker(*values: object) -> bool:
    text = " ".join(str(value) for value in values if value is not None).lower()
    return bool(ICS_TOKEN_PATTERN.search(text)) or any(
        marker in text for marker in ICS_PRODUCT_MARKERS
    )


def asset_has_ics_evidence(asset: Asset) -> bool:
    """Return whether stored asset classification contains an ICS/OT signal."""
    return _text_has_ics_marker(
        asset.system_type,
        asset.device_class,
        asset.device_subclass,
        asset.tags,
        asset.metadata_,
        asset.description,
    )


def service_has_ics_evidence(service: object) -> bool:
    """Return whether a port-service fingerprint contains an ICS/OT signal."""
    return _text_has_ics_marker(
        getattr(service, "service_name", None),
        getattr(service, "service_product", None),
        getattr(service, "service_version", None),
        getattr(service, "service_extra_info", None),
        getattr(service, "banner", None),
        getattr(service, "tags", None),
        getattr(service, "metadata_", None),
    )


def asset_or_services_have_ics_evidence(asset: Asset) -> bool:
    """Recognize an OT host when any observed service supplies the evidence."""
    return asset_has_ics_evidence(asset) or any(
        service_has_ics_evidence(service) for service in asset.port_services
    )


def service_is_web(service: object, web_ports: set[int] | frozenset[int]) -> bool:
    name = str(getattr(service, "service_name", "") or "").lower()
    port = int(getattr(service, "port", 0) or 0)
    return port in web_ports or any(marker in name for marker in HTTP_SERVICE_MARKERS)


def _url_host(value: str) -> str:
    """Bracket IPv6 literals so they are valid URL hosts."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value
    return f"[{value}]" if ip.version == 6 else value


def service_url(asset: Asset, service: object) -> str:
    """Build an HTTP(S) URL from an observed web service."""
    port = int(getattr(service, "port", 0) or 0)
    is_ssl = bool(getattr(service, "is_ssl", False))
    scheme = "https" if is_ssl or port in TLS_WEB_PORTS else "http"
    host = _url_host(str(asset.value).strip())
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"


def _requested_scope(targets: Optional[Iterable[str]]) -> tuple[set[str], list]:
    hosts: set[str] = set()
    networks = []
    for raw in targets or []:
        value = str(raw).strip()
        if not value:
            continue
        if "/" in value:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
                continue
            except ValueError:
                pass
        literal = value.strip("[]")
        try:
            host = str(ipaddress.ip_address(literal))
        except ValueError:
            try:
                parsed = urlparse(value if "://" in value else f"//{value}")
                host = parsed.hostname or value.split(":", 1)[0]
            except ValueError:
                host = value
        if host:
            hosts.add(host.lower())
    return hosts, networks


def _asset_in_requested_scope(asset: Asset, hosts: set[str], networks: list) -> bool:
    if not hosts and not networks:
        return True
    values = {str(asset.value).lower()}
    values.update(str(ip).lower() for ip in (asset.ip_addresses or []))
    if values & hosts:
        return True
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if any(ip.version == network.version and ip in network for network in networks):
            return True
    return False


def select_ics_web_screenshot_targets(
    db: Session,
    *,
    organization_id: int,
    max_hosts: int = 100,
    require_owned: bool = False,
    requested_targets: Optional[Iterable[str]] = None,
    web_ports: Optional[Iterable[int]] = None,
) -> list[str]:
    """Return deduplicated web URLs backed by stored ICS/OT evidence.

    Only in-scope assets are considered.  A target is selected when the asset
    or the web service has an ICS marker; merely having port 80/443 open is not
    enough.
    """
    ports = frozenset(int(port) for port in (web_ports or DEFAULT_ICS_WEB_PORTS))
    requested_hosts, requested_networks = _requested_scope(requested_targets)

    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.in_scope.is_(True),
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
    )
    if require_owned:
        query = query.filter(Asset.is_owned.is_(True))

    urls: list[str] = []
    seen: set[str] = set()
    for asset in query.options(selectinload(Asset.port_services)).all():
        if not _asset_in_requested_scope(asset, requested_hosts, requested_networks):
            continue

        asset_is_ics = asset_or_services_have_ics_evidence(asset)

        for service in asset.port_services:
            if getattr(service, "state", None) != PortState.OPEN:
                continue
            if not service_is_web(service, ports):
                continue
            if not (asset_is_ics or service_has_ics_evidence(service)):
                continue
            url = service_url(asset, service)
            if url not in seen:
                seen.add(url)
                urls.append(url)
            if len(urls) >= max_hosts:
                return urls

    return urls[:max_hosts]
