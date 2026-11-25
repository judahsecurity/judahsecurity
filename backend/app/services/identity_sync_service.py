"""Read-only identity ingest from an organization's system of record.

Phase 1 source: ServiceNow ``sys_user`` plus ``sys_user_grmember`` for group
membership, using the organization's existing ServiceNow integration login.
The service account needs read ACLs on those two tables; nothing is written
back to ServiceNow.

Only fields used for risk scoring are requested (``sysparm_fields``), so phone
numbers, addresses and other HR data never leave the customer's instance.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models.identity import (
    IDENTITY_SOURCE_SERVICENOW,
    Identity,
    IdentitySourceSync,
)
from app.models.servicenow_integration import ServiceNowIntegration
from app.services.identity_risk import score_identity
from app.services.servicenow_service import _headers, _instance_base

logger = logging.getLogger(__name__)

SYS_USER_FIELDS = (
    "sys_id,user_name,email,name,title,department,manager,active,vip,"
    "employee_number,locked_out"
)
GRMEMBER_FIELDS = "user,group"
PAGE_SIZE = 1000
DEFAULT_MAX_USERS = 100_000
MAX_GROUP_MEMBERSHIP_ROWS = 500_000
_TIMEOUT = 60.0


class IdentitySyncError(Exception):
    pass


def _field(record: Dict[str, Any], name: str, display: bool = False) -> Optional[str]:
    """Read a field from a ``sysparm_display_value=all`` record."""
    raw = record.get(name)
    if isinstance(raw, dict):
        raw = raw.get("display_value" if display else "value")
    if raw is None:
        return None
    raw = str(raw).strip()
    return raw or None


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"true", "1", "yes"}


def normalize_sys_user(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Turn one ``sys_user`` row into Identity column values."""
    sys_id = _field(record, "sys_id")
    if not sys_id:
        return None
    email = (_field(record, "email") or "").lower() or None
    username = (_field(record, "user_name") or "").lower() or None
    if not email and not username:
        return None
    aliases = sorted({a for a in (email, username) if a})
    return {
        "source_id": sys_id,
        "email": email,
        "username": username,
        "aliases": aliases,
        "display_name": _field(record, "name", display=True),
        "employee_number": _field(record, "employee_number"),
        "title": _field(record, "title", display=True),
        "department": _field(record, "department", display=True),
        "manager_name": _field(record, "manager", display=True),
        "manager_source_id": _field(record, "manager"),
        "is_active": _truthy(_field(record, "active")) and not _truthy(_field(record, "locked_out")),
        "is_vip": _truthy(_field(record, "vip")),
    }


class ServiceNowIdentityClient:
    def __init__(self, integration: ServiceNowIntegration, client: Optional[httpx.AsyncClient] = None):
        base = _instance_base(integration.webhook_url)
        if not base:
            raise IdentitySyncError("Could not derive the ServiceNow instance URL from the integration.")
        if not integration.username:
            raise IdentitySyncError("The ServiceNow integration has no service-account login.")
        self.base = base
        self.headers = _headers(integration)
        self._client = client

    async def _paged(self, table: str, fields: str, limit: int) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        offset = 0
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=_TIMEOUT)
        try:
            while offset < limit:
                params = {
                    "sysparm_fields": fields,
                    "sysparm_display_value": "all",
                    "sysparm_exclude_reference_link": "true",
                    "sysparm_limit": str(min(PAGE_SIZE, limit - offset)),
                    "sysparm_offset": str(offset),
                    "sysparm_query": "ORDERBYsys_id",
                }
                resp = await client.get(
                    f"{self.base}/api/now/table/{table}", params=params, headers=self.headers
                )
                if resp.status_code in (401, 403):
                    raise IdentitySyncError(
                        f"ServiceNow denied read access to {table} (HTTP {resp.status_code}). "
                        f"Grant the integration account read ACLs on {table}."
                    )
                if resp.status_code != 200:
                    raise IdentitySyncError(f"ServiceNow {table} returned HTTP {resp.status_code}")
                page = (resp.json() or {}).get("result") or []
                rows.extend(page)
                if len(page) < int(params["sysparm_limit"]):
                    break
                offset += len(page)
        finally:
            if owns_client:
                await client.aclose()
        return rows

    async def fetch_users(self, max_users: int) -> List[Dict[str, Any]]:
        return await self._paged("sys_user", SYS_USER_FIELDS, max_users)

    async def fetch_group_memberships(self, max_rows: int) -> Dict[str, List[str]]:
        rows = await self._paged("sys_user_grmember", GRMEMBER_FIELDS, max_rows)
        groups: Dict[str, set[str]] = {}
        for row in rows:
            user = _field(row, "user")
            group = _field(row, "group", display=True)
            if user and group:
                groups.setdefault(user, set()).add(group)
        return {k: sorted(v) for k, v in groups.items()}


def apply_identity_scores(identity: Identity) -> None:
    score, factors, privileged = score_identity(
        title=identity.title,
        department=identity.department,
        groups=identity.groups or [],
        is_vip=bool(identity.is_vip),
        is_active=bool(identity.is_active),
        username=identity.username,
        worker_type=identity.worker_type,
    )
    identity.risk_score = score
    identity.risk_factors = [f.to_dict() for f in factors]
    identity.is_privileged = privileged


def upsert_identities(
    db: Session,
    organization_id: int,
    source: str,
    records: Iterable[Dict[str, Any]],
    groups_by_source_id: Dict[str, List[str]],
    *,
    complete: bool,
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """Insert or update identities; deactivate ones missing from a complete pull."""
    now = now or datetime.utcnow()
    existing = {
        i.source_id: i
        for i in db.query(Identity).filter(
            Identity.organization_id == organization_id, Identity.source == source
        )
    }
    stats = {"created": 0, "updated": 0, "deactivated": 0, "skipped": 0}
    seen: set[str] = set()

    for raw in records:
        values = normalize_sys_user(raw) if source == IDENTITY_SOURCE_SERVICENOW else raw
        if not values:
            stats["skipped"] += 1
            continue
        sid = values["source_id"]
        seen.add(sid)
        identity = existing.get(sid)
        if identity is None:
            identity = Identity(organization_id=organization_id, source=source, source_id=sid)
            db.add(identity)
            existing[sid] = identity
            stats["created"] += 1
        else:
            stats["updated"] += 1
        for key, val in values.items():
            setattr(identity, key, val)
        identity.groups = groups_by_source_id.get(sid, [])
        identity.last_seen_in_source_at = now
        apply_identity_scores(identity)

    if complete:
        for sid, identity in existing.items():
            if sid not in seen and identity.is_active:
                identity.is_active = False
                apply_identity_scores(identity)
                stats["deactivated"] += 1

    db.flush()
    return stats


def _sync_row(db: Session, organization_id: int, source: str) -> IdentitySourceSync:
    row = (
        db.query(IdentitySourceSync)
        .filter(
            IdentitySourceSync.organization_id == organization_id,
            IdentitySourceSync.source == source,
        )
        .first()
    )
    if row is None:
        row = IdentitySourceSync(organization_id=organization_id, source=source)
        db.add(row)
        db.flush()
    return row


def claim_sync(db: Session, organization_id: int, source: str) -> bool:
    """Mark a sync as running; False if one is already in progress."""
    row = _sync_row(db, organization_id, source)
    if row.running:
        return False
    row.running = True
    row.last_sync_started_at = datetime.utcnow()
    db.commit()
    return True


async def sync_servicenow_identities(
    db: Session,
    organization_id: int,
    *,
    max_users: int = DEFAULT_MAX_USERS,
    client: Optional[ServiceNowIdentityClient] = None,
) -> Dict[str, Any]:
    """Pull sys_user into Identity rows, then rescore the org's exposures."""
    from app.services.credential_exposure_service import rescore_organization

    row = _sync_row(db, organization_id, IDENTITY_SOURCE_SERVICENOW)
    try:
        if client is None:
            integration = (
                db.query(ServiceNowIntegration)
                .filter(ServiceNowIntegration.organization_id == organization_id)
                .first()
            )
            if integration is None or not integration.is_active:
                raise IdentitySyncError("No active ServiceNow integration for this organization.")
            client = ServiceNowIdentityClient(integration)

        users = await client.fetch_users(max_users)
        try:
            groups = await client.fetch_group_memberships(MAX_GROUP_MEMBERSHIP_ROWS)
        except IdentitySyncError as exc:
            # Group ACLs are often missing; title-based scoring still works.
            logger.warning("Identity sync org=%s: group fetch skipped: %s", organization_id, exc)
            groups = {}

        stats = upsert_identities(
            db,
            organization_id,
            IDENTITY_SOURCE_SERVICENOW,
            users,
            groups,
            complete=len(users) < max_users,
        )
        stats["users_fetched"] = len(users)
        stats["group_memberships_loaded"] = bool(groups)
        stats["exposures_rescored"] = rescore_organization(db, organization_id)

        row.last_sync_ok = True
        row.last_error = None
        row.last_sync_stats = stats
        return stats
    except Exception as exc:
        db.rollback()
        row = _sync_row(db, organization_id, IDENTITY_SOURCE_SERVICENOW)
        row.last_sync_ok = False
        row.last_error = str(exc)[:2000]
        logger.warning("Identity sync org=%s failed: %s", organization_id, exc)
        raise
    finally:
        row.running = False
        row.last_sync_at = datetime.utcnow()
        db.commit()
