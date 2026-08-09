"""Palo Alto Networks Panorama integration service.

Read-only import of address objects as assets from either:

1. Live Panorama REST API (X-PAN-KEY)
2. Configuration export files (.gz / .tgz / .xml) for air-gapped deployments

API reference (Praetorian / PAN-OS REST):
    Auth       : request header ``X-PAN-KEY: <api key>``
    Addresses  : GET /restapi/{version}/Objects/Addresses
    Groups     : GET /restapi/{version}/Objects/AddressGroups
    Scope      : location=shared | location=device-group&device-group={name}

Config export (Praetorian air-gapped path):
    Upload a Panorama configuration export (gzipped XML or .tgz bundle).
    Address objects are parsed from shared / device-group / vsys sections.
"""

from __future__ import annotations

import asyncio
import gzip
import io
import logging
import os
import re
import tarfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.panorama_integration import (
    CONNECTION_MODE_API,
    CONNECTION_MODE_CONFIG_EXPORT,
    PanoramaIntegration,
)

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "panorama"
CLOUD_SERVICE_TAG = "paloalto"
SOURCE_TAG = f"source:{DISCOVERY_SOURCE}"

# Panorama REST commonly returns up to 500 entries per page.
PAGE_SIZE = 500
MAX_PAGES = 200
RATE_LIMIT_DELAY = 0.25

# On-disk storage for uploaded configuration exports.
PANORAMA_DATA_DIR = os.environ.get("PANORAMA_DATA_DIR", "/app/data/panorama")
MAX_EXPORT_BYTES = int(os.environ.get("PANORAMA_MAX_EXPORT_BYTES", str(200 * 1024 * 1024)))
ALLOWED_EXPORT_SUFFIXES = (".gz", ".tgz", ".tar.gz", ".xml")


def _normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip("/")
    if host and not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host


def _scope_params(device_group: Optional[str]) -> Dict[str, str]:
    if device_group and device_group.strip():
        return {"location": "device-group", "device-group": device_group.strip()}
    return {"location": "shared"}


def _as_entry_list(payload: Optional[Dict]) -> List[Dict]:
    """Normalize Panorama REST list responses to a list of entry dicts."""
    if not payload or not isinstance(payload, dict):
        return []
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    if not isinstance(result, dict):
        return []
    entry = result.get("entry")
    if entry is None:
        return []
    if isinstance(entry, list):
        return [e for e in entry if isinstance(e, dict)]
    if isinstance(entry, dict):
        return [entry]
    return []


def _total_count(payload: Optional[Dict]) -> Optional[int]:
    if not payload or not isinstance(payload, dict):
        return None
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    if not isinstance(result, dict):
        return None
    for key in ("@total-count", "total-count", "totalCount"):
        raw = result.get(key)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                continue
    return None


class PanoramaClient:
    """Thin async client for the read-only Panorama REST API."""

    def __init__(
        self,
        panorama_host: str,
        api_key: str,
        *,
        api_version: str = "v11.1",
        device_group: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.base_url = _normalize_host(panorama_host)
        self.api_version = api_version if api_version.startswith("v") else f"v{api_version}"
        self.device_group = device_group
        self.verify_ssl = verify_ssl
        self._headers = {
            "X-PAN-KEY": api_key,
            "Accept": "application/json",
        }

    def _url(self, resource_path: str) -> str:
        return f"{self.base_url}/restapi/{self.api_version}/{resource_path.lstrip('/')}"

    async def _get(self, resource_path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        url = self._url(resource_path)
        query = {**(params or {}), **_scope_params(self.device_group)}
        try:
            async with httpx.AsyncClient(
                timeout=45.0,
                headers=self._headers,
                verify=self.verify_ssl,
            ) as client:
                resp = await client.get(url, params=query)
                if resp.status_code == 429:
                    logger.warning("Panorama rate limited on %s, backing off 10s", resource_path)
                    await asyncio.sleep(10)
                    return await self._get(resource_path, params)
                if resp.status_code in (401, 403):
                    logger.error(
                        "Panorama: unauthorized (HTTP %s) on %s", resp.status_code, resource_path
                    )
                    return None
                if resp.status_code != 200:
                    logger.warning(
                        "Panorama GET %s -> HTTP %s: %s",
                        resource_path,
                        resp.status_code,
                        resp.text[:300],
                    )
                    return None
                return resp.json()
        except Exception as exc:  # noqa: BLE001 — network errors are expected
            logger.error("Panorama GET %s error: %s", resource_path, exc)
            return None

    async def _paginate(self, resource_path: str) -> List[Dict]:
        """Fetch all entries, preferring limit/offset pagination when supported."""
        results: List[Dict] = []
        offset = 0
        for _ in range(MAX_PAGES):
            payload = await self._get(
                resource_path,
                params={"limit": PAGE_SIZE, "offset": offset},
            )
            if payload is None:
                if offset == 0:
                    payload = await self._get(resource_path)
                    if payload is None:
                        break
                    return _as_entry_list(payload)
                break

            batch = _as_entry_list(payload)
            if not batch:
                break

            if offset > 0 and results and batch[0].get("@name") == results[0].get("@name"):
                break

            results.extend(batch)
            total = _total_count(payload)
            if total is not None and len(results) >= total:
                break
            if len(batch) < PAGE_SIZE:
                break
            offset += len(batch)
            await asyncio.sleep(RATE_LIMIT_DELAY)
        return results

    async def list_addresses(self, *, limit: Optional[int] = None) -> List[Dict]:
        if limit is not None:
            payload = await self._get("Objects/Addresses", params={"limit": limit})
            return _as_entry_list(payload)
        return await self._paginate("Objects/Addresses")

    async def list_address_groups(self) -> List[Dict]:
        return await self._paginate("Objects/AddressGroups")


async def test_connection(
    panorama_host: str,
    api_key: str,
    *,
    api_version: str = "v11.1",
    device_group: Optional[str] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    """Validate Panorama credentials with a lightweight Addresses probe."""
    host = _normalize_host(panorama_host)
    parsed = urlparse(host)
    if not parsed.scheme or not parsed.netloc:
        return {
            "ok": False,
            "message": "Panorama host must be a full URL (e.g. https://panorama.example.com).",
            "address_count": None,
        }

    client = PanoramaClient(
        host,
        api_key,
        api_version=api_version,
        device_group=device_group,
        verify_ssl=verify_ssl,
    )
    payload_probe = await client._get("Objects/Addresses", params={"limit": 1})
    if payload_probe is None:
        payload_probe = await client._get("Objects/Addresses")
    if payload_probe is None:
        scope = f"device group '{device_group}'" if device_group else "shared location"
        return {
            "ok": False,
            "message": (
                f"Could not authenticate to Panorama at {host} ({scope}). "
                "Check the host URL, API key, API version, and network connectivity."
            ),
            "address_count": None,
        }

    count = _total_count(payload_probe)
    if count is None:
        count = len(_as_entry_list(payload_probe))
    scope_label = f"device group '{device_group}'" if device_group else "shared"
    return {
        "ok": True,
        "message": f"Connected to Panorama successfully ({scope_label}).",
        "address_count": count,
    }


# ── Address object → asset value mapping ─────────────────────────────────────

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def _is_ip(value: str) -> bool:
    return bool(_IP_RE.match(value))


def _looks_like_subdomain(fqdn: str) -> bool:
    labels = [p for p in fqdn.split(".") if p]
    return len(labels) >= 3


def parse_address_object(entry: Dict) -> Optional[Tuple[str, AssetType, str]]:
    """Return (asset_value, asset_type, address_kind) or None if unusable."""
    if not isinstance(entry, dict):
        return None

    ip_netmask = entry.get("ip-netmask") or entry.get("ip_netmask")
    if isinstance(ip_netmask, str) and ip_netmask.strip():
        value = ip_netmask.strip()
        if "/" in value:
            ip_part, prefix = value.split("/", 1)
            if prefix.strip() in ("32", "128"):
                return ip_part.strip(), AssetType.IP_ADDRESS, "ip"
            return value, AssetType.IP_RANGE, "cidr"
        return value, AssetType.IP_ADDRESS, "ip"

    fqdn = entry.get("fqdn")
    if isinstance(fqdn, str) and fqdn.strip():
        name = fqdn.strip().rstrip(".").lower()
        atype = AssetType.SUBDOMAIN if _looks_like_subdomain(name) else AssetType.DOMAIN
        return name, atype, "fqdn"

    ip_range = entry.get("ip-range") or entry.get("ip_range")
    if isinstance(ip_range, str) and ip_range.strip():
        first = ip_range.strip().split("-", 1)[0].strip()
        if first:
            return first, AssetType.IP_ADDRESS, "range"

    ip_wildcard = entry.get("ip-wildcard") or entry.get("ip_wildcard")
    if isinstance(ip_wildcard, str) and ip_wildcard.strip():
        base = ip_wildcard.strip().split("/", 1)[0].strip()
        if base:
            return base, AssetType.IP_ADDRESS, "wildcard"

    return None


def _group_membership_index(groups: List[Dict]) -> Dict[str, List[str]]:
    """Map address object name → list of containing address-group names."""
    index: Dict[str, List[str]] = {}
    for group in groups:
        group_name = group.get("@name") or group.get("name")
        if not group_name:
            continue
        static = group.get("static") or {}
        members = static.get("member") if isinstance(static, dict) else None
        if members is None and isinstance(group.get("static"), list):
            members = group.get("static")
        if isinstance(members, str):
            members = [members]
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, str) or not member.strip():
                continue
            index.setdefault(member.strip(), []).append(str(group_name))
    return index


class _Stats:
    def __init__(self) -> None:
        self.assets_created = 0
        self.assets_updated = 0
        self.addresses_seen = 0
        self.address_groups_seen = 0
        self.ips_imported = 0
        self.cidrs_imported = 0
        self.fqdns_imported = 0
        self.ranges_seeded = 0
        self.assets_missing_from_source = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "assets_created": self.assets_created,
            "assets_updated": self.assets_updated,
            "addresses_seen": self.addresses_seen,
            "address_groups_seen": self.address_groups_seen,
            "ips_imported": self.ips_imported,
            "cidrs_imported": self.cidrs_imported,
            "fqdns_imported": self.fqdns_imported,
            "ranges_seeded": self.ranges_seeded,
            "assets_missing_from_source": self.assets_missing_from_source,
        }


def _bump_kind(stats: _Stats, kind: str) -> None:
    if kind == "ip":
        stats.ips_imported += 1
    elif kind == "cidr":
        stats.cidrs_imported += 1
    elif kind == "fqdn":
        stats.fqdns_imported += 1
    elif kind in ("range", "wildcard"):
        stats.ranges_seeded += 1


def _upsert_asset(
    db: Session,
    integration: PanoramaIntegration,
    value: str,
    asset_type: AssetType,
    stats: _Stats,
    *,
    object_name: str,
    address_kind: str,
    description: Optional[str] = None,
    tags_from_panorama: Optional[List[str]] = None,
    group_names: Optional[List[str]] = None,
    source_scope: Optional[str] = None,
) -> Optional[Asset]:
    value = (value or "").strip()
    if not value:
        return None

    org_id = integration.organization_id
    device_group = source_scope or integration.device_group or "shared"
    existing = (
        db.query(Asset)
        .filter(Asset.organization_id == org_id, Asset.value == value)
        .first()
    )

    meta_patch = {
        "panorama_integration_id": integration.id,
        "panorama_object_name": object_name,
        "panorama_device_group": device_group,
        "panorama_address_kind": address_kind,
        "panorama_host": integration.panorama_host,
        "panorama_groups": group_names or [],
        "panorama_connection_mode": integration.connection_mode or CONNECTION_MODE_API,
        "cloud_service": CLOUD_SERVICE_TAG,
    }

    desired_tags = {SOURCE_TAG, CLOUD_SERVICE_TAG, f"panorama-dg:{device_group}"}
    if tags_from_panorama:
        for t in tags_from_panorama:
            if t:
                desired_tags.add(f"panorama-tag:{t}")

    if existing:
        existing.last_seen = datetime.utcnow()
        tags = [t for t in (existing.tags or []) if t != "panorama:removed"]
        for t in desired_tags:
            if t not in tags:
                tags.append(t)
        existing.tags = tags
        meta = dict(existing.metadata_ or {})
        meta.update(meta_patch)
        existing.metadata_ = meta
        if description and not existing.description:
            existing.description = description
        stats.assets_updated += 1
        return existing

    asset = Asset(
        name=object_name[:255] if object_name else value[:255],
        asset_type=asset_type,
        value=value[:500],
        organization_id=org_id,
        status=AssetStatus.DISCOVERED,
        description=description,
        discovery_source=DISCOVERY_SOURCE,
        association_reason=(
            f"Address object '{object_name}' imported from Palo Alto Panorama "
            f"({device_group})"
        ),
        association_confidence=85,
        tags=sorted(desired_tags),
        metadata_=meta_patch,
        system_type="firewall",
        device_class="Network Infrastructure",
        device_subclass="Firewall and Next Generation Firewall",
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


def _panorama_tag_members(entry: Dict) -> List[str]:
    tag = entry.get("tag")
    if isinstance(tag, dict):
        members = tag.get("member")
        if isinstance(members, str):
            return [members]
        if isinstance(members, list):
            return [m for m in members if isinstance(m, str)]
    if isinstance(tag, list):
        return [m for m in tag if isinstance(m, str)]
    return []


# ── Config export parsing ─────────────────────────────────────────────────────

def _local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _child_text(entry: ET.Element, *names: str) -> Optional[str]:
    wanted = set(names)
    for child in list(entry):
        if _local_tag(child.tag) in wanted:
            text = (child.text or "").strip()
            if text:
                return text
    return None


def _child_members(entry: ET.Element, container_name: str, member_name: str = "member") -> List[str]:
    members: List[str] = []
    for child in list(entry):
        if _local_tag(child.tag) != container_name:
            continue
        for member in list(child):
            if _local_tag(member.tag) == member_name:
                text = (member.text or "").strip()
                if text:
                    members.append(text)
        # Some exports put members directly under the container.
        if not members:
            direct = (child.text or "").strip()
            if direct:
                members.append(direct)
    return members


def _xml_entry_to_address(entry: ET.Element, scope: str) -> Optional[Dict[str, Any]]:
    name = entry.attrib.get("name") or entry.attrib.get("Name")
    if not name:
        return None
    result: Dict[str, Any] = {"@name": name, "@location": scope}
    for key in ("ip-netmask", "fqdn", "ip-range", "ip-wildcard", "description"):
        value = _child_text(entry, key)
        if value:
            result[key] = value
    tags = _child_members(entry, "tag")
    if tags:
        result["tag"] = {"member": tags}
    # Skip entries with no usable address type.
    if not any(k in result for k in ("ip-netmask", "fqdn", "ip-range", "ip-wildcard")):
        return None
    return result


def _xml_entry_to_group(entry: ET.Element, scope: str) -> Optional[Dict[str, Any]]:
    name = entry.attrib.get("name") or entry.attrib.get("Name")
    if not name:
        return None
    result: Dict[str, Any] = {"@name": name, "@location": scope}
    static_members = _child_members(entry, "static")
    if static_members:
        result["static"] = {"member": static_members}
    # Dynamic groups have no static members; keep for count/metadata.
    return result


def _iter_named_sections(root: ET.Element, section: str):
    """Yield (scope_label, section_element) for address / address-group blocks."""
    for node in root.iter():
        if _local_tag(node.tag) != section:
            continue
        parent = _find_parent_scope(root, node)
        yield parent, node


def _find_parent_scope(root: ET.Element, target: ET.Element) -> str:
    """Best-effort scope label for an address/address-group node."""
    # Walk parents via a parent map (ElementTree has no .parent).
    parent_map = {c: p for p in root.iter() for c in p}
    current: Optional[ET.Element] = target
    device_group_name: Optional[str] = None
    vsys_name: Optional[str] = None
    in_shared = False
    while current is not None:
        tag = _local_tag(current.tag)
        name = current.attrib.get("name")
        if tag == "shared":
            in_shared = True
        elif tag == "entry" and name:
            parent = parent_map.get(current)
            parent_tag = _local_tag(parent.tag) if parent is not None else ""
            if parent_tag == "device-group":
                device_group_name = name
            elif parent_tag == "vsys":
                vsys_name = name
        current = parent_map.get(current)

    if device_group_name:
        return f"device-group:{device_group_name}"
    if in_shared:
        return "shared"
    if vsys_name:
        return f"vsys:{vsys_name}"
    return "unknown"


def _parse_xml_bytes(data: bytes) -> Tuple[List[Dict], List[Dict]]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Panorama XML: {exc}") from exc

    addresses: List[Dict] = []
    groups: List[Dict] = []
    seen_addr: set[tuple] = set()
    seen_group: set[tuple] = set()

    for scope, section in _iter_named_sections(root, "address"):
        for entry in list(section):
            if _local_tag(entry.tag) != "entry":
                continue
            obj = _xml_entry_to_address(entry, scope)
            if not obj:
                continue
            key = (obj.get("@name"), scope, obj.get("ip-netmask"), obj.get("fqdn"), obj.get("ip-range"))
            if key in seen_addr:
                continue
            seen_addr.add(key)
            addresses.append(obj)

    for scope, section in _iter_named_sections(root, "address-group"):
        for entry in list(section):
            if _local_tag(entry.tag) != "entry":
                continue
            obj = _xml_entry_to_group(entry, scope)
            if not obj:
                continue
            key = (obj.get("@name"), scope)
            if key in seen_group:
                continue
            seen_group.add(key)
            groups.append(obj)

    return addresses, groups


def _looks_like_tar(data: bytes) -> bool:
    # gzip magic + try tarfile, or ustar signature in first blocks
    bio = io.BytesIO(data)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as tf:
            return any(True for _ in tf.getmembers()[:1])
    except tarfile.TarError:
        return False


def _gunzip_bytes(data: bytes) -> bytes:
    try:
        return gzip.decompress(data)
    except OSError as exc:
        raise ValueError(f"Invalid gzip archive: {exc}") from exc


def parse_config_export_bytes(
    data: bytes,
    *,
    filename: Optional[str] = None,
    device_group: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse a Panorama config export into address / address-group dicts.

    Accepts raw XML, gzipped XML (.gz), or tar/gzip bundles (.tgz / .tar.gz).
    """
    if not data:
        raise ValueError("Empty configuration export file.")

    name = (filename or "").lower()
    addresses: List[Dict] = []
    groups: List[Dict] = []
    xml_files_parsed = 0

    def _merge(addr: List[Dict], grp: List[Dict]) -> None:
        nonlocal xml_files_parsed
        xml_files_parsed += 1
        addresses.extend(addr)
        groups.extend(grp)

    is_tar_name = name.endswith(".tgz") or name.endswith(".tar.gz")
    if is_tar_name or (data[:2] == b"\x1f\x8b" and _looks_like_tar(data)) or (
        not name.endswith(".gz") and _looks_like_tar(data)
    ):
        bio = io.BytesIO(data)
        try:
            with tarfile.open(fileobj=bio, mode="r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    mname = member.name.lower()
                    if not (mname.endswith(".xml") or mname.endswith(".xml.gz") or mname.endswith(".conf")):
                        # Panorama bundles often use bare names like running-config.xml
                        # or device serial folders; also accept files containing "config".
                        if ".xml" not in mname and "config" not in mname:
                            continue
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        continue
                    raw = extracted.read()
                    if mname.endswith(".gz") or raw[:2] == b"\x1f\x8b":
                        raw = _gunzip_bytes(raw)
                    # Skip non-XML payloads
                    sample = raw.lstrip()[:64]
                    if not (sample.startswith(b"<") or sample.startswith(b"<?xml")):
                        continue
                    _merge(*_parse_xml_bytes(raw))
        except tarfile.TarError as exc:
            raise ValueError(f"Invalid Panorama config bundle: {exc}") from exc
    elif name.endswith(".gz") or data[:2] == b"\x1f\x8b":
        raw = _gunzip_bytes(data)
        _merge(*_parse_xml_bytes(raw))
    else:
        _merge(*_parse_xml_bytes(data))

    if xml_files_parsed == 0:
        raise ValueError(
            "No Panorama configuration XML found in the upload. "
            "Expected a .xml, .gz (gzipped XML), or .tgz config bundle."
        )

    # Optional device-group filter for config exports.
    if device_group and device_group.strip():
        dg = device_group.strip()
        wanted = {f"device-group:{dg}", "shared"}
        addresses = [a for a in addresses if a.get("@location") in wanted]
        groups = [g for g in groups if g.get("@location") in wanted]

    return {
        "addresses": addresses,
        "address_groups": groups,
        "xml_files_parsed": xml_files_parsed,
    }


def validate_export_filename(filename: str) -> str:
    name = (filename or "").strip()
    if not name:
        raise ValueError("Filename is required.")
    # Prevent path traversal
    base = os.path.basename(name)
    lower = base.lower()
    if not any(lower.endswith(sfx) for sfx in ALLOWED_EXPORT_SUFFIXES):
        raise ValueError(
            "Unsupported file type. Upload a Panorama config export: .gz, .tgz, .tar.gz, or .xml"
        )
    return base


def export_storage_dir(org_id: int, integration_id: int) -> Path:
    path = Path(PANORAMA_DATA_DIR) / f"org_{org_id}" / f"integration_{integration_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def store_export_file(
    integration: PanoramaIntegration,
    *,
    filename: str,
    data: bytes,
) -> Dict[str, Any]:
    """Validate, parse, and persist a config export for later syncs."""
    safe_name = validate_export_filename(filename)
    if len(data) > MAX_EXPORT_BYTES:
        raise ValueError(
            f"File exceeds maximum size of {MAX_EXPORT_BYTES // (1024 * 1024)} MB."
        )

    parsed = parse_config_export_bytes(
        data, filename=safe_name, device_group=integration.device_group
    )
    dest_dir = export_storage_dir(integration.organization_id, integration.id)
    dest_path = dest_dir / safe_name

    # Replace previous export for this integration.
    for old in dest_dir.iterdir():
        if old.is_file() and old.name != safe_name:
            try:
                old.unlink()
            except OSError:
                pass

    dest_path.write_bytes(data)

    integration.export_file_path = str(dest_path)
    integration.export_filename = safe_name
    integration.export_file_size = len(data)
    integration.export_uploaded_at = datetime.utcnow()
    integration.connection_mode = CONNECTION_MODE_CONFIG_EXPORT
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = True
    integration.last_error = None

    return {
        "ok": True,
        "message": (
            f"Stored configuration export '{safe_name}' "
            f"({len(parsed['addresses'])} address object(s), "
            f"{len(parsed['address_groups'])} address group(s))."
        ),
        "filename": safe_name,
        "file_size": len(data),
        "address_count": len(parsed["addresses"]),
        "address_groups_count": len(parsed["address_groups"]),
        "parsed": parsed,
    }


def test_config_export(integration: PanoramaIntegration) -> Dict[str, Any]:
    """Validate that the stored export exists and still parses."""
    path = integration.export_file_path
    if not path or not os.path.isfile(path):
        return {
            "ok": False,
            "message": "No configuration export uploaded for this connection yet.",
            "address_count": None,
        }
    try:
        data = Path(path).read_bytes()
        parsed = parse_config_export_bytes(
            data,
            filename=integration.export_filename or os.path.basename(path),
            device_group=integration.device_group,
        )
        return {
            "ok": True,
            "message": (
                f"Configuration export OK "
                f"({integration.export_filename or os.path.basename(path)})."
            ),
            "address_count": len(parsed["addresses"]),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "message": f"Failed to parse stored configuration export: {exc}",
            "address_count": None,
        }


def _import_address_entries(
    db: Session,
    integration: PanoramaIntegration,
    addresses: List[Dict],
    groups: List[Dict],
    stats: _Stats,
) -> set[str]:
    stats.address_groups_seen = len(groups)
    stats.addresses_seen = len(addresses)
    membership = _group_membership_index(groups)
    seen_values: set[str] = set()

    for entry in addresses:
        object_name = str(entry.get("@name") or entry.get("name") or "").strip()
        parsed = parse_address_object(entry)
        if not parsed:
            continue
        value, asset_type, kind = parsed
        groups_for_obj = membership.get(object_name, []) if object_name else []
        scope = entry.get("@location") if isinstance(entry.get("@location"), str) else None
        asset = _upsert_asset(
            db,
            integration,
            value,
            asset_type,
            stats,
            object_name=object_name or value,
            address_kind=kind,
            description=entry.get("description")
            if isinstance(entry.get("description"), str)
            else None,
            tags_from_panorama=_panorama_tag_members(entry),
            group_names=groups_for_obj,
            source_scope=scope,
        )
        if asset:
            seen_values.add(value)
            _bump_kind(stats, kind)
    return seen_values


def _mark_missing_assets(
    db: Session,
    integration: PanoramaIntegration,
    seen_values: set[str],
    stats: _Stats,
) -> None:
    prior = (
        db.query(Asset)
        .filter(
            Asset.organization_id == integration.organization_id,
            Asset.discovery_source == DISCOVERY_SOURCE,
        )
        .all()
    )
    for asset in prior:
        meta = asset.metadata_ or {}
        if meta.get("panorama_integration_id") != integration.id:
            continue
        if asset.value not in seen_values:
            stats.assets_missing_from_source += 1
            tags = list(asset.tags or [])
            if "panorama:removed" not in tags:
                tags.append("panorama:removed")
                asset.tags = tags


async def sync_integration(db: Session, integration: PanoramaIntegration) -> Dict[str, Any]:
    """Import address objects from Panorama REST or a stored config export."""
    org_id = integration.organization_id
    mode = integration.connection_mode or CONNECTION_MODE_API
    stats = _Stats()

    try:
        if mode == CONNECTION_MODE_CONFIG_EXPORT:
            path = integration.export_file_path
            if not path or not os.path.isfile(path):
                return {
                    "ok": False,
                    "message": "No configuration export uploaded for this connection.",
                    "source": mode,
                    **stats.as_dict(),
                }
            data = Path(path).read_bytes()
            parsed = parse_config_export_bytes(
                data,
                filename=integration.export_filename or os.path.basename(path),
                device_group=integration.device_group,
            )
            seen = _import_address_entries(
                db, integration, parsed["addresses"], parsed["address_groups"], stats
            )
            source_label = "config export"
        else:
            api_key = integration.get_api_key()
            if not api_key:
                return {
                    "ok": False,
                    "message": "No API key stored for this connection.",
                    "source": mode,
                    **stats.as_dict(),
                }
            if not integration.panorama_host:
                return {
                    "ok": False,
                    "message": "No Panorama host configured for this connection.",
                    "source": mode,
                    **stats.as_dict(),
                }
            client = PanoramaClient(
                integration.panorama_host,
                api_key,
                api_version=integration.api_version or "v11.1",
                device_group=integration.device_group,
                verify_ssl=bool(integration.verify_ssl),
            )
            groups = await client.list_address_groups()
            addresses = await client.list_addresses()
            seen = _import_address_entries(db, integration, addresses, groups, stats)
            source_label = "Panorama API"

        _mark_missing_assets(db, integration, seen, stats)

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()

        return {
            "ok": True,
            "message": (
                f"Imported {stats.assets_created} new asset(s) from {source_label} "
                f"({stats.addresses_seen} address object(s) seen)."
            ),
            "source": mode,
            **stats.as_dict(),
        }
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Panorama sync failed for org %s", org_id)
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = str(exc)[:1000]
        db.commit()
        return {
            "ok": False,
            "message": f"Sync failed: {exc}",
            "source": mode,
            **stats.as_dict(),
        }
