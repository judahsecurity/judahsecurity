"""Cross-source asset identity.

Connectors identify an asset by the IDs their own data carries, strongest
first, rather than by a display string or by another vendor's record ID:

1. Cloud provider IDs — AWS instance ID / ARN, Azure resource ID / VM ID,
   GCP instance ID / self link. These come from the source's own record, so
   no Tenable UUID (or any other vendor ID) is needed to match.
2. Hardware IDs — BIOS UUID, MAC address (globally administered only).
3. The source's own record IDs — Wiz ID, Tenable asset / agent UUID. These
   let a source find its asset again on the next sync; they are aliases,
   not authority.
4. Only when none of those match does a connector fall back to its weak key
   (a public FQDN or IP), and even then a weak match is refused when the
   candidate already holds a different cloud or hardware ID.

Cloud and hardware IDs are *exclusive*: an asset holds at most one value per
namespace, and assets holding different values are never merged. That is the
rule that stops two cloud VMs that once shared a public IP from collapsing.

All values are normalized (case-insensitive, canonical formats), so an ARN
from one connector matches the bare instance ID from another.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Set

from sqlalchemy import String, and_, cast, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.asset_identifier import AssetIdentifier

logger = logging.getLogger(__name__)

# ── Namespaces ──────────────────────────────────────────────────────────────

AWS_INSTANCE = "aws:ec2_instance"
AWS_ARN = "aws:arn"
AZURE_RESOURCE = "azure:resource_id"
AZURE_VM = "azure:vm_id"
GCP_INSTANCE = "gcp:instance_id"
GCP_SELF_LINK = "gcp:self_link"
BIOS_UUID = "bios_uuid"
MAC = "mac"
WIZ_ID = "wiz:id"
TENABLE_ASSET = "tenable:asset_uuid"
TENABLE_AGENT = "tenable:agent_uuid"

CLOUD_NAMESPACES = frozenset({AWS_INSTANCE, AWS_ARN, AZURE_RESOURCE, AZURE_VM, GCP_INSTANCE, GCP_SELF_LINK})
# One value per asset; different values block a merge.
EXCLUSIVE_NAMESPACES = CLOUD_NAMESPACES | {BIOS_UUID}

# When one record's identifiers point at several existing assets, the asset
# matched by the earliest namespace here is preferred (after asset type).
PRIORITY = (
    AWS_INSTANCE, AZURE_VM, AZURE_RESOURCE, GCP_INSTANCE, GCP_SELF_LINK, AWS_ARN,
    BIOS_UUID, MAC,
    WIZ_ID, TENABLE_ASSET, TENABLE_AGENT,
)
_RANK = {ns: i for i, ns in enumerate(PRIORITY)}

# Domains are the primary asset in the canonical model, so a hostname asset
# absorbs the VM records that describe it, not the other way round.
_TYPE_RANK = {
    AssetType.DOMAIN: 0,
    AssetType.SUBDOMAIN: 0,
    AssetType.CLOUD_RESOURCE: 1,
    AssetType.IP_ADDRESS: 2,
}


@dataclass(frozen=True)
class Identifier:
    namespace: str
    value: str


# ── Normalizers ─────────────────────────────────────────────────────────────

_AWS_INSTANCE_RE = re.compile(r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_GCP_SELF_LINK_RE = re.compile(r"(?:^|/)projects/([^/]+)/zones/([^/]+)/instances/([^/?#]+)")
# Placeholder BIOS UUIDs some firmware ships with on every unit.
_JUNK_BIOS = {"03000200-0400-0500-0006-000700080009"}


def _clean(value: object) -> str:
    return str(value).strip() if value not in (None, "") else ""


def aws_ids(value: object) -> List[Identifier]:
    """An ARN or a bare EC2 instance ID."""
    raw = _clean(value).lower()
    if not raw:
        return []
    if raw.startswith("arn:"):
        parts = raw.split(":", 5)
        if len(parts) != 6 or not parts[5]:
            return []
        out = [Identifier(AWS_ARN, raw)]
        service, resource = parts[2], parts[5]
        if service == "ec2" and resource.startswith("instance/"):
            instance = resource.split("/", 1)[1]
            if _AWS_INSTANCE_RE.match(instance):
                out.append(Identifier(AWS_INSTANCE, instance))
        return out
    if _AWS_INSTANCE_RE.match(raw):
        return [Identifier(AWS_INSTANCE, raw)]
    return []


def azure_ids(resource_id: object = None, vm_id: object = None) -> List[Identifier]:
    out: List[Identifier] = []
    rid = _clean(resource_id).lower().rstrip("/")
    if rid.startswith("/subscriptions/") and rid.count("/") >= 4:
        out.append(Identifier(AZURE_RESOURCE, rid))
    vid = _clean(vm_id).lower().strip("{}")
    if _GUID_RE.match(vid):
        out.append(Identifier(AZURE_VM, vid))
    return out


def gcp_ids(instance_id: object = None, self_link: object = None) -> List[Identifier]:
    out: List[Identifier] = []
    iid = _clean(instance_id)
    if iid.isdigit():
        out.append(Identifier(GCP_INSTANCE, iid))
    match = _GCP_SELF_LINK_RE.search(_clean(self_link).lower())
    if match:
        out.append(Identifier(GCP_SELF_LINK, "projects/{}/zones/{}/instances/{}".format(*match.groups())))
    return out


def provider_ids(value: object, platform: object = None) -> List[Identifier]:
    """Classify a provider-native ID of unknown shape (e.g. Wiz's providerUniqueId)."""
    raw = _clean(value)
    if not raw:
        return []
    lowered = raw.lower()
    hint = _clean(platform).lower()
    if lowered.startswith("arn:") or _AWS_INSTANCE_RE.match(lowered):
        return aws_ids(raw)
    if lowered.startswith("/subscriptions/"):
        return azure_ids(resource_id=raw)
    if _GCP_SELF_LINK_RE.search(lowered):
        return gcp_ids(self_link=raw)
    if "azure" in hint and _GUID_RE.match(lowered.strip("{}")):
        return azure_ids(vm_id=raw)
    if ("gcp" in hint or "google" in hint) and raw.isdigit():
        return gcp_ids(instance_id=raw)
    return []


def mac_id(value: object) -> Optional[Identifier]:
    """A globally administered unicast MAC. Locally administered MACs (cloud
    ENIs, containers, VPN adapters) are reused across machines and skipped."""
    digits = re.sub(r"[^0-9a-f]", "", _clean(value).lower())
    if len(digits) != 12 or len(set(digits)) == 1:
        return None
    if int(digits[1], 16) & 0b11:  # multicast or locally administered
        return None
    return Identifier(MAC, ":".join(digits[i:i + 2] for i in range(0, 12, 2)))


def bios_id(value: object) -> Optional[Identifier]:
    raw = _clean(value).lower().strip("{}")
    if not _GUID_RE.match(raw) or raw in _JUNK_BIOS or len(set(raw.replace("-", ""))) <= 2:
        return None
    return Identifier(BIOS_UUID, raw)


def record_id(namespace: str, value: object) -> Optional[Identifier]:
    raw = _clean(value).lower()
    return Identifier(namespace, raw[:512]) if raw else None


def unique(ids: Iterable[Optional[Identifier]]) -> List[Identifier]:
    seen: Set[Identifier] = set()
    out: List[Identifier] = []
    for ident in ids:
        if ident is not None and ident not in seen:
            seen.add(ident)
            out.append(ident)
    return out


def primary_cloud_id(ids: Iterable[Identifier]) -> Optional[Identifier]:
    """The cloud ID that best names a new cloud asset (used as its ``value``)."""
    cloud = [i for i in ids if i.namespace in CLOUD_NAMESPACES]
    return min(cloud, key=lambda i: _RANK[i.namespace]) if cloud else None


# ── Resolver ────────────────────────────────────────────────────────────────


@dataclass
class Resolution:
    asset: Optional[Asset] = None
    # Other assets this record proves are the same machine; merge them in.
    duplicates: List[Asset] = field(default_factory=list)
    # A weak match was refused because a cloud/hardware ID disagreed.
    conflict: bool = False


class AssetIdentityResolver:
    def __init__(self, db: Session, organization_id: int, source: str) -> None:
        self.db = db
        self.org_id = organization_id
        self.source = source

    # Lookups ---------------------------------------------------------------

    def _rows(self, ids: List[Identifier]) -> List[AssetIdentifier]:
        if not ids:
            return []
        return self.db.query(AssetIdentifier).filter(
            AssetIdentifier.organization_id == self.org_id,
            or_(*[and_(AssetIdentifier.namespace == i.namespace, AssetIdentifier.value == i.value) for i in ids]),
        ).all()

    def held(self, asset: Asset) -> Dict[str, Set[str]]:
        held: Dict[str, Set[str]] = {}
        if asset.id is None:
            return held
        for row in self.db.query(AssetIdentifier).filter(AssetIdentifier.asset_id == asset.id):
            held.setdefault(row.namespace, set()).add(row.value)
        return held

    def conflicts(self, asset: Asset, ids: Iterable[Identifier]) -> bool:
        """True when ``asset`` holds a different value in an exclusive namespace."""
        held = self.held(asset)
        return any(
            i.namespace in EXCLUSIVE_NAMESPACES and held.get(i.namespace) and i.value not in held[i.namespace]
            for i in ids
        )

    def assets_conflict(self, a: Asset, b: Asset) -> bool:
        held_a, held_b = self.held(a), self.held(b)
        return any(
            ns in EXCLUSIVE_NAMESPACES and held_b.get(ns) and not (values & held_b[ns])
            for ns, values in held_a.items()
        )

    def find(self, ids: Iterable[Identifier]) -> Optional[Asset]:
        """Lookup only — never creates, never merges."""
        return self.resolve(ids).asset

    def resolve(
        self,
        ids: Iterable[Identifier],
        fallback: Optional[Callable[[], Optional[Asset]]] = None,
    ) -> Resolution:
        ids = unique(ids)
        best: Dict[int, int] = {}
        assets: Dict[int, Asset] = {}
        for row in self._rows(ids):
            rank = _RANK.get(row.namespace, len(PRIORITY))
            if row.asset_id not in best or rank < best[row.asset_id]:
                best[row.asset_id] = rank
                assets[row.asset_id] = row.asset
        if assets:
            ordered = sorted(
                assets.values(),
                key=lambda a: (_TYPE_RANK.get(a.asset_type, 3), best[a.id], a.created_at or datetime.min, a.id),
            )
            primary = ordered[0]
            duplicates = [a for a in ordered[1:] if not self.assets_conflict(primary, a)]
            return Resolution(primary, duplicates)
        if fallback is not None:
            candidate = fallback()
            if candidate is not None:
                if self.conflicts(candidate, ids):
                    return Resolution(conflict=True)
                return Resolution(candidate)
        return Resolution()

    # Writes ----------------------------------------------------------------

    def attach(self, asset: Asset, ids: Iterable[Identifier]) -> None:
        """Register ``ids`` on ``asset``. Exclusive IDs owned by another asset
        stay where they are; source record aliases follow the asset."""
        ids = unique(ids)
        if not ids:
            return
        if asset.id is None:
            self.db.flush()
        existing = {(r.namespace, r.value): r for r in self._rows(ids)}
        held = self.held(asset)
        now = datetime.utcnow()
        for ident in ids:
            row = existing.get((ident.namespace, ident.value))
            exclusive = ident.namespace in EXCLUSIVE_NAMESPACES
            if row is not None:
                if row.asset_id != asset.id:
                    if exclusive:
                        continue
                    row.asset = asset
                row.last_seen = now
                continue
            if exclusive and held.get(ident.namespace):
                continue  # the asset already names a different machine
            try:
                with self.db.begin_nested():
                    self.db.add(AssetIdentifier(
                        organization_id=self.org_id, asset=asset, namespace=ident.namespace,
                        value=ident.value, source=self.source, first_seen=now, last_seen=now,
                    ))
            except IntegrityError:
                logger.info("Identifier %s:%s claimed concurrently; skipped", ident.namespace, ident.value)
                continue
            held.setdefault(ident.namespace, set()).add(ident.value)

    def merge(self, primary: Asset, duplicates: Iterable[Asset]) -> int:
        """Fold assets one record proved are the same machine into ``primary``."""
        from app.services.asset_merge_service import AssetMergeService

        merger = AssetMergeService(self.db)
        merged = 0
        for dup in duplicates:
            if dup.id == primary.id or self.assets_conflict(primary, dup):
                continue
            merger.absorb(primary, dup)
            merged += 1
        return merged


# ── Backfill ────────────────────────────────────────────────────────────────


def identifiers_from_metadata(asset: Asset) -> List[Identifier]:
    """IDs already recorded in a source's metadata before identifiers existed."""
    meta = asset.metadata_ or {}
    ids: List[Optional[Identifier]] = []
    wiz = meta.get("wiz") if isinstance(meta.get("wiz"), dict) else {}
    if wiz:
        ids.append(record_id(WIZ_ID, wiz.get("id")))
        ids.extend(provider_ids(wiz.get("provider_unique_id"), wiz.get("cloud_platform")))
    tenable = meta.get("tenable") if isinstance(meta.get("tenable"), dict) else {}
    if tenable:
        ids.append(record_id(TENABLE_ASSET, tenable.get("asset_uuid")))
        for item in tenable.get("cloud_ids") or []:
            if isinstance(item, dict) and item.get("namespace") and item.get("value"):
                ids.append(Identifier(str(item["namespace"]), str(item["value"])))
    return unique(ids)


def backfill_identifiers(db: Session, organization_id: int, source: str, tag: str) -> int:
    """Register identifiers for assets a source touched before this table existed.

    Only assets carrying ``tag`` and no identifiers yet are loaded, so this is
    cheap after the first run.
    """
    has_ids = db.query(AssetIdentifier.asset_id).filter(AssetIdentifier.organization_id == organization_id)
    assets = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        cast(Asset.tags, String).like(f"%{tag}%"),
        Asset.id.notin_(has_ids),
    ).all()
    resolver = AssetIdentityResolver(db, organization_id, source)
    count = 0
    for asset in assets:
        ids = identifiers_from_metadata(asset)
        if ids:
            resolver.attach(asset, ids)
            count += 1
    return count
