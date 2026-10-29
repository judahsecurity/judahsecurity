"""Ingest ZPA LSS user activity and microsegmentation flows as discovery evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.zpa_integration import ZpaIntegration, ZpaObservation

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedEvent:
    fingerprint: str
    feed: str
    source_key: str
    source_name: str
    destination: str
    asset_type: AssetType
    network_scope_id: str
    port: int | None
    protocol: str | None
    action: str | None
    connected: bool
    occurred_at: datetime


def _fields(payload: dict[str, Any]) -> dict[str, Any]:
    # LSS JSON formats can vary by configured output template.
    return {str(key).lower().replace("_", ""): value for key, value in payload.items()}


def _value(fields: dict[str, Any], *names: str) -> str:
    for name in names:
        value = fields.get(name.lower().replace("_", ""))
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        if value.isdigit():
            divisor = 1_000_000_000 if len(value) >= 19 else 1_000_000 if len(value) >= 16 else 1000 if len(value) >= 13 else 1
            seconds = int(value) / divisor
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc).replace(tzinfo=None) if parsed.tzinfo is None else parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        return None


def _destination(value: str) -> tuple[str, AssetType] | None:
    value = value.strip().strip("[]").rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value)), AssetType.IP_ADDRESS
    except ValueError:
        pass
    if len(value) > 253 or not value or "." not in value:
        return None
    try:
        ascii_name = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if all(part.isdigit() for part in ascii_name.split(".")) or any(
        not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
        or not all(c.isalnum() or c == "-" for c in part)
        for part in ascii_name.split(".")
    ):
        return None
    return ascii_name, AssetType.DOMAIN


def parse_event(payload: dict[str, Any], integration_id: int) -> ParsedEvent | None:
    """Parse documented ZPA fields; omit events without useful target or scope."""
    fields = _fields(payload)
    microseg = bool(_value(fields, "ResourceID", "AppZoneID", "EnforcementDisposition", "Direction"))
    feed = "microsegmentation" if microseg else "user_activity"
    if microseg and _value(fields, "Direction").upper() != "OUTBOUND":
        return None

    normalized = next((candidate for candidate in (
        _destination(_value(fields, name)) for name in ("DestinationIP", "ServerIP", "Server", "Host", "Application")
    ) if candidate is not None), None)
    if not normalized:
        return None
    destination, asset_type = normalized

    microtenant = _value(fields, "MicroTenantID", "MicrotenantID")
    zone = _value(fields, "AppZoneID", "AppZoneName")
    resource = _value(fields, "ResourceID", "ResourceName")
    application = _value(fields, "ApplicationID", "Application")
    if microseg:
        source_name = _value(fields, "ResourceName", "ResourceID")
        source_identity = resource
        scope_identity = zone or resource
    else:
        source_name = _value(fields, "Application", "AppGroup")
        source_identity = application
        scope_identity = application
    if not source_identity or not scope_identity:
        return None
    source_name = source_name or source_identity
    # Do not pool all RFC1918 destinations under one ZPA connection. When the
    # feed lacks a network ID, the narrowest known app/resource is the scope.
    scope = f"zpa:{integration_id}:tenant:{microtenant or 'unknown'}:{'zone' if zone else 'source'}:{scope_identity}"
    if len(scope) > 128:
        scope = f"zpa:{integration_id}:sha256:{hashlib.sha256(scope.encode()).hexdigest()}"
    source_key = f"zpa:{integration_id}:{feed}:{microtenant}:{source_identity}"
    if len(source_key) > 500:
        source_key = f"zpa:{integration_id}:sha256:{hashlib.sha256(source_key.encode()).hexdigest()}"

    raw_port = _value(fields, "DestinationPort", "ServerPort", "ServicePort")
    try:
        port = int(raw_port) if raw_port else None
    except ValueError:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    raw_protocol = _value(fields, "Protocol", "IPProtocol").upper()
    protocol = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPV6"}.get(raw_protocol, raw_protocol)[:32] or None
    action = _value(fields, "EnforcementAction", "ConnectionStatus").upper()[:32] or None
    disposition = _value(fields, "EnforcementDisposition", "ConnectionStatus").upper()
    connected = (disposition in {"CONNECTED", "SUCCESS", "SUCCESSFUL"}) and action not in {"BLOCK", "SIMBLOCK", "DENY"}

    occurred_at = _timestamp(_value(fields, "ConnectionStartTime", "TimestampConnectionStart", "Timestamp"))
    if occurred_at is None:
        return None
    event_id = _value(fields, "ConnectionID", "EventID")
    dedupe = [feed, source_key, scope, destination, str(port), protocol, action, disposition,
              occurred_at.isoformat(), event_id,
              _value(fields, "SourceIP") if microseg else "",
              fields.get("sourceports") if microseg else None]
    fingerprint = hashlib.sha256(json.dumps(dedupe, separators=(",", ":")).encode()).hexdigest()
    return ParsedEvent(fingerprint, feed, source_key, source_name[:255], destination,
                       asset_type, scope, port, protocol, action, connected, occurred_at)


def _find_candidate(db: Session, org_id: int, integration_id: int, parsed: ParsedEvent) -> Asset | None:
    candidates = db.query(Asset).filter(
        Asset.organization_id == org_id,
        Asset.discovery_source == "zpa",
        Asset.value == parsed.destination,
    ).all()
    return next((asset for asset in candidates if (asset.metadata_ or {}).get("zpa_integration_id") == integration_id
                 and (asset.metadata_ or {}).get("network_scope_id") == parsed.network_scope_id), None)


def ingest_events(db: Session, integration: ZpaIntegration, payloads: list[dict[str, Any]]) -> dict[str, int]:
    # Serialize batches for one connection in PostgreSQL so concurrent
    # collectors cannot create duplicate candidates before the unique event
    # fingerprint is committed.
    db.query(ZpaIntegration.id).filter(
        ZpaIntegration.id == integration.id,
        ZpaIntegration.organization_id == integration.organization_id,
    ).with_for_update().one()
    stats = {"received": len(payloads), "accepted": 0, "duplicates": 0, "ignored": 0, "assets_created": 0}
    seen: set[str] = set()
    for payload in payloads:
        parsed = parse_event(payload, integration.id)
        if parsed is None:
            stats["ignored"] += 1
            continue
        if parsed.fingerprint in seen or db.query(ZpaObservation.id).filter(
            ZpaObservation.integration_id == integration.id,
            ZpaObservation.fingerprint == parsed.fingerprint,
        ).first():
            stats["duplicates"] += 1
            continue
        seen.add(parsed.fingerprint)
        asset = _find_candidate(db, integration.organization_id, integration.id, parsed)
        if asset is None:
            asset = Asset(
                organization_id=integration.organization_id,
                name=parsed.destination,
                value=parsed.destination,
                asset_type=parsed.asset_type,
                status=AssetStatus.DISCOVERED,
                discovery_source="zpa",
                association_reason="Observed as a ZPA flow or private application destination; ownership unverified",
                association_confidence=40,
                tags=["source:zpa", "candidate"],
                metadata_={"zpa_integration_id": integration.id, "network_scope_id": parsed.network_scope_id,
                           "zpa_feed": parsed.feed},
                is_public=False,
                is_owned=False,
                in_scope=False,
                is_live=False,
                first_seen=parsed.occurred_at,
                last_seen=parsed.occurred_at,
            )
            db.add(asset)
            db.flush()
            stats["assets_created"] += 1
        else:
            asset.last_seen = max(asset.last_seen or parsed.occurred_at, parsed.occurred_at)
        db.add(ZpaObservation(
            integration_id=integration.id,
            organization_id=integration.organization_id,
            fingerprint=parsed.fingerprint,
            feed=parsed.feed,
            source_key=parsed.source_key,
            source_name=parsed.source_name,
            destination_asset_id=asset.id,
            destination=parsed.destination,
            destination_port=parsed.port,
            protocol=parsed.protocol,
            action=parsed.action,
            connected=parsed.connected,
            occurred_at=parsed.occurred_at,
        ))
        stats["accepted"] += 1
    integration.last_ingest_at = datetime.utcnow()
    db.commit()
    return stats
